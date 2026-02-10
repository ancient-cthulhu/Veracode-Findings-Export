import argparse
import datetime as dt
import json
import time
import csv

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


BASE_URL = "https://api.veracode.com/appsec/v1/analytics/report"
MAX_WINDOW_DAYS = 180      # API supports up to ~6 months per request
DEFAULT_POLL_INTERVAL = 5  # 5s
DEFAULT_MAX_POLLS = 40     #  ~3.3 min


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export Veracode FINDINGS data via Reporting REST API."
    )
    parser.add_argument(
        "--start-date",
        required=True,
        help="Start date (YYYY-MM-DD, inclusive).",
    )
    parser.add_argument(
        "--end-date",
        help="End date (YYYY-MM-DD, inclusive). Defaults to today.",
    )
    parser.add_argument(
        "--output",
        default="veracode_findings.csv",
        help="Output CSV filename (default: veracode_findings.csv).",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Sleep in seconds between windows (default: 1.0).",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="Seconds between report status checks (default: 5.0).",
    )
    parser.add_argument(
        "--max-polls",
        type=int,
        default=DEFAULT_MAX_POLLS,
        help="Max number of report status checks (default: 40).",
    )
    return parser.parse_args()


def to_date(value):
    return dt.date.fromisoformat(value)


def date_iteration_windows(start_date, end_date):
    delta = dt.timedelta(days=MAX_WINDOW_DAYS - 1)
    current = start_date

    while current <= end_date:
        window_end = min(current + delta, end_date)
        yield current, window_end
        current = window_end + dt.timedelta(days=1)


def build_findings_payload(window_start, window_end):
    """Build payload for FINDINGS report type."""
    payload = {
        "report_type": "FINDINGS",
        "last_updated_start_date": window_start.strftime("%Y-%m-%d 00:00:00"),
    }

    if window_end > window_start:
        payload["last_updated_end_date"] = window_end.strftime("%Y-%m-%d 23:59:59")

    return payload


def request_report(session, payload):
    resp = session.post(
        BASE_URL,
        json=payload,
        auth=RequestsAuthPluginVeracodeHMAC(),
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()

    embedded = data.get("_embedded", {})
    report_id = data.get("id") or embedded.get("id")

    if not report_id:
        raise RuntimeError(
            f"No 'id' in response from {BASE_URL}: {json.dumps(data)}"
        )

    return report_id


def get_report_once(session, report_id):
    url = f"{BASE_URL}/{report_id}"
    resp = session.get(
        url,
        auth=RequestsAuthPluginVeracodeHMAC(),
        timeout=300,
    )
    resp.raise_for_status()
    return resp.json()


def wait_for_report(session, report_id, poll_interval, max_polls):
    for attempt in range(1, max_polls + 1):
        data = get_report_once(session, report_id)
        embedded = data.get("_embedded", {})
        status = embedded.get("status")

        print(f"  Poll {attempt}/{max_polls}: {status}")

        if status == "COMPLETED":
            return data

        if status not in ("SUBMITTED", "PROCESSING", None):
            raise RuntimeError(
                f"Report {report_id} ended in unexpected status {status}: "
                f"{json.dumps(data)}"
            )

        time.sleep(poll_interval)

    raise TimeoutError(
        f"Report {report_id} did not reach COMPLETED after {max_polls} polls"
    )


def extract_findings_records(report_data):
    """Extract findings records from the completed report."""
    records = []
    
    if isinstance(report_data, dict):
        embedded = report_data.get("_embedded", {})
        
        # Try common field names for findings data
        for key in ["findings", "finding", "data", "records"]:
            if key in embedded and isinstance(embedded[key], list):
                records.extend(embedded[key])
        
        # If still no records, check top level
        if not records:
            for key in ["findings", "finding", "data", "records"]:
                if key in report_data and isinstance(report_data[key], list):
                    records.extend(report_data[key])
    
    return records


def calculate_days_to_resolve(first_found, fixed_date):
    """Calculate days between first found and fixed date."""
    if not first_found or not fixed_date:
        return None
    
    try:
        # Parse dates - handle various formats
        if isinstance(first_found, str):
            first_found_dt = dt.datetime.fromisoformat(first_found.replace('Z', '+00:00'))
        else:
            first_found_dt = first_found
            
        if isinstance(fixed_date, str):
            fixed_date_dt = dt.datetime.fromisoformat(fixed_date.replace('Z', '+00:00'))
        else:
            fixed_date_dt = fixed_date
        
        delta = fixed_date_dt - first_found_dt
        return delta.days
    except Exception:
        return None


def normalize_finding_record(finding):
    """
    Extract and normalize required fields from a finding record.
    
    Required fields:
    - Application Name
    - Application ID
    - Custom Severity Name
    - CVE ID
    - Description
    - Vulnerability Title
    - CWE ID
    - Flaw Name
    - First Found Date
    - Filename/Class
    - Finding Status
    - Fixed Date
    - Team Name
    - Days to Resolve
    - Scan Type
    """
    # Get nested values with fallbacks
    app_name = finding.get("app_name") or finding.get("application_name") or finding.get("application", {}).get("name")
    app_id = finding.get("app_id") or finding.get("application_id") or finding.get("application", {}).get("id")
    
    custom_severity = finding.get("custom_severity") or finding.get("custom_severity_name")
    cve_id = finding.get("cve_id") or finding.get("cve")
    description = finding.get("description") or finding.get("flaw_description")
    vuln_title = finding.get("vulnerability_title") or finding.get("title") or finding.get("issue_name")
    cwe_id = finding.get("cwe_id") or finding.get("cwe")
    flaw_name = finding.get("flaw_name") or finding.get("finding_category", {}).get("name")
    
    first_found = finding.get("first_found_date") or finding.get("found_date")
    filename = finding.get("file_name") or finding.get("filename") or finding.get("file_path") or finding.get("source_file")
    status = finding.get("finding_status") or finding.get("status") or finding.get("resolution_status")
    fixed_date = finding.get("fixed_date") or finding.get("resolution_date")
    team_name = finding.get("team_name") or finding.get("team") or finding.get("business_unit")
    scan_type = finding.get("scan_type") or finding.get("analysis_type")
    
    # Calculate days to resolve
    days_to_resolve = calculate_days_to_resolve(first_found, fixed_date)
    
    return {
        "Application Name": app_name,
        "Application ID": app_id,
        "Custom Severity Name": custom_severity,
        "CVE ID": cve_id,
        "Description": description,
        "Vulnerability Title": vuln_title,
        "CWE ID": cwe_id,
        "Flaw Name": flaw_name,
        "First Found Date": first_found,
        "Filename/Class": filename,
        "Finding Status": status,
        "Fixed Date": fixed_date,
        "Team Name": team_name,
        "Days to Resolve": days_to_resolve,
        "Scan Type": scan_type,
    }


def fetch_findings_window(session, window_start, window_end, sleep_between_windows,
                          poll_interval, max_polls):
    payload = build_findings_payload(window_start, window_end)
    start_str = payload["last_updated_start_date"]
    end_str = payload.get("last_updated_end_date", start_str)

    print(f"  Requesting report: {start_str} to {end_str}")

    report_id = request_report(session, payload)
    print(f"  Report ID: {report_id}")

    report_data = wait_for_report(
        session=session,
        report_id=report_id,
        poll_interval=poll_interval,
        max_polls=max_polls,
    )
    
    # Extract findings records
    findings = extract_findings_records(report_data)
    print(f"  Completed: {len(findings)} findings retrieved\n")

    time.sleep(sleep_between_windows)

    return findings


def main():
    args = parse_args()

    start_date = to_date(args.start_date)
    end_date = to_date(args.end_date) if args.end_date else dt.date.today()

    if start_date > end_date:
        raise ValueError("start-date must be on or before end-date")

    # Print header banner
    print("\n" + "=" * 70)
    print("  VERACODE FINDINGS EXPORT")
    print("=" * 70)
    print(f"  Date Range: {start_date} to {end_date}")
    print(f"  Output File: {args.output}")
    print("=" * 70 + "\n")

    session = requests.Session()
    all_findings = []

    for window_id, (w_start, w_end) in enumerate(date_iteration_windows(start_date, end_date), start=1):
        print("\n" + "-" * 70)
        print(f"  Window {window_id}: {w_start} to {w_end}")
        print("-" * 70)
        window_findings = fetch_findings_window(
            session=session,
            window_start=w_start,
            window_end=w_end,
            sleep_between_windows=args.sleep,
            poll_interval=args.poll_interval,
            max_polls=args.max_polls,
        )
        all_findings.extend(window_findings)

    # Save raw JSON for debugging
    print("\n" + "=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)
    
    json_file = f"veracode_findings_{start_date}_to_{end_date}_raw.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)
    print(f"  Raw JSON: {json_file} ({len(all_findings)} findings)")

    # Normalize and save to CSV
    if all_findings:
        normalized_findings = [normalize_finding_record(f) for f in all_findings]
        
        fieldnames = [
            "Application Name",
            "Application ID",
            "Custom Severity Name",
            "CVE ID",
            "Description",
            "Vulnerability Title",
            "CWE ID",
            "Flaw Name",
            "First Found Date",
            "Filename/Class",
            "Finding Status",
            "Fixed Date",
            "Team Name",
            "Days to Resolve",
            "Scan Type",
        ]
        
        with open(args.output, "w", encoding="utf-8", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(normalized_findings)
        
        print(f"  CSV File: {args.output} ({len(normalized_findings)} findings)")
    else:
        print("  No findings found in the specified date range.")

    print("=" * 70)
    print("  EXPORT COMPLETED")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
