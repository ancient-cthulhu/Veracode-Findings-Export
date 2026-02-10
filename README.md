# Veracode Findings Export

A Python script to export vulnerability findings data from Veracode using the Reporting REST API. This tool automatically handles date windowing, report generation, polling, and data normalization.

## Overview

This script pulls findings data from Veracode and exports it to both JSON (raw) and CSV (normalized) formats. It's designed to extract comprehensive vulnerability information including application details, CVE/CWE IDs, finding status, remediation timelines, and more.

## Prerequisites

### 1. Veracode API Credentials

You need Veracode API credentials configured on your system. The script uses HMAC authentication.

**Required Veracode Roles:**

**Important:** To enable the Reporting API for your account, you must first send a request to support@veracode.com.

Once enabled, you need one of these account configurations:
- **API Service Account** with the **Reporting API** role
- **User Account** with one of these roles:
  - **Executive**
  - **Security Lead**
  - **Security Insights** (Note: API only returns data for teams you're a member of)

**Credential Setup:**

Create a Veracode API credentials file at:
- **Windows**: `C:\Users\<username>\.veracode\credentials`
- **Mac/Linux**: `~/.veracode/credentials`

File format:
```ini
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

Alternatively, set environment variables:
```bash
export VERACODE_API_KEY_ID=your_key_id
export VERACODE_API_KEY_SECRET=your_key_secret
```

### 2. Python Requirements

- Python 3.7 or higher
- Required packages:
  ```
  requests
  veracode-api-signing
  ```

## Installation

1. Clone or download this repository

2. Install required Python packages:
   ```bash
   pip install requests veracode-api-signing
   ```

3. Verify your Veracode credentials are configured (see Prerequisites above)

## Usage

### Basic Usage

Export findings from a start date to today:
```bash
python findings_export.py --start-date 2025-01-01
```

### Specify Date Range

Export findings for a specific date range:
```bash
python findings_export.py --start-date 2025-01-01 --end-date 2025-12-31
```

### Custom Output Filename

Specify a custom CSV output filename:
```bash
python findings_export.py --start-date 2025-01-01 --output my_findings_report.csv
```

### Advanced Options

```bash
python findings_export.py \
  --start-date 2024-01-01 \
  --end-date 2025-12-31 \
  --output findings.csv \
  --sleep 2.0 \
  --poll-interval 10 \
  --max-polls 60
```

## Command-Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--start-date` | Yes | - | Start date (YYYY-MM-DD format, inclusive) |
| `--end-date` | No | Today | End date (YYYY-MM-DD format, inclusive) |
| `--output` | No | `veracode_findings.csv` | Output CSV filename |
| `--sleep` | No | `1.0` | Sleep time in seconds between date windows |
| `--poll-interval` | No | `5.0` | Seconds between report status checks |
| `--max-polls` | No | `40` | Maximum number of status check attempts |

## Output Files

The script generates two output files:

### 1. CSV File (Normalized)
**Default:** `veracode_findings.csv`

Contains normalized findings data with the following columns:
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
- Days to Resolve (automatically calculated)
- Scan Type

### 2. JSON File (Raw)
**Format:** `veracode_findings_<start>_to_<end>_raw.json`

Contains the raw findings data from the API for debugging.

## Field Mappings

The script maps various API response field names to the required output fields:

| Output Field | Possible API Fields |
|--------------|---------------------|
| Application Name | `app_name`, `application_name`, `application.name` |
| Application ID | `app_id`, `application_id`, `application.id` |
| Custom Severity Name | `custom_severity`, `custom_severity_name` |
| CVE ID | `cve_id`, `cve` |
| Description | `description`, `flaw_description` |
| Vulnerability Title | `vulnerability_title`, `title`, `issue_name` |
| CWE ID | `cwe_id`, `cwe` |
| Flaw Name | `flaw_name`, `finding_category.name` |
| First Found Date | `first_found_date`, `found_date` |
| Filename/Class | `file_name`, `filename`, `file_path`, `source_file` |
| Finding Status | `finding_status`, `status`, `resolution_status` |
| Fixed Date | `fixed_date`, `resolution_date` |
| Team Name | `team_name`, `team`, `business_unit` |
| Scan Type | `scan_type`, `analysis_type` |

## How It Works

1. **Date Windowing**: The script automatically splits large date ranges into 180-day windows (Veracode API limitation)

2. **Report Creation**: For each window, it creates a findings report via the Reporting API

3. **Polling**: Waits for report completion, checking status every 5 seconds (configurable)

4. **Data Extraction**: Extracts findings records from the completed report

5. **Normalization**: Maps API fields to standardized output fields

6. **Export**: Saves both raw JSON and normalized CSV files

## Example Output

### Console Output
```
======================================================================
  VERACODE FINDINGS EXPORT
======================================================================
  Date Range: 2025-01-01 to 2026-02-09
  Output File: veracode_findings.csv
======================================================================


----------------------------------------------------------------------
  Window 1: 2025-01-01 to 2025-06-29
----------------------------------------------------------------------
  Requesting report: 2025-01-01 00:00:00 to 2025-06-29 23:59:59
  Report ID: c5a6c9d4-9bb1-4443-88ea-0a054faf16cc
  Poll 1/40: SUBMITTED
  Poll 2/40: PROCESSING
  Poll 3/40: PROCESSING
  Poll 4/40: PROCESSING
  Poll 5/40: PROCESSING
  Poll 6/40: PROCESSING
  Poll 7/40: COMPLETED
  Completed: 248 findings retrieved


----------------------------------------------------------------------
  Window 2: 2025-06-30 to 2025-12-26
----------------------------------------------------------------------
  Requesting report: 2025-06-30 00:00:00 to 2025-12-26 23:59:59
  Report ID: 644c4e31-3946-4008-a92c-4a49375a6510
  Poll 1/40: SUBMITTED
  Poll 2/40: PROCESSING
  Poll 3/40: PROCESSING
  Poll 4/40: PROCESSING
  Poll 5/40: COMPLETED
  Completed: 330 findings retrieved


----------------------------------------------------------------------
  Window 3: 2025-12-27 to 2026-02-09
----------------------------------------------------------------------
  Requesting report: 2025-12-27 00:00:00 to 2026-02-09 23:59:59
  Report ID: 9a8e6b72-ff45-451b-87fe-97d84fdf507c
  Poll 1/40: SUBMITTED
  Poll 2/40: PROCESSING
  Poll 3/40: PROCESSING
  Poll 4/40: PROCESSING
  Poll 5/40: PROCESSING
  Poll 6/40: PROCESSING
  Poll 7/40: COMPLETED
  Completed: 615 findings retrieved


======================================================================
  SAVING RESULTS
======================================================================
  Raw JSON: veracode_findings_2025-01-01_to_2026-02-09_raw.json (1193 findings)
  CSV File: veracode_findings.csv (1193 findings)
======================================================================
  EXPORT COMPLETED
======================================================================

```

### CSV Output Sample
```csv
Application Name	Application ID	Custom Severity Name	CVE ID	Description	Vulnerability Title	CWE ID	Flaw Name	First Found Date	Filename/Class	Finding Status	Fixed Date	Team Name	Days to Resolve	Scan Type
Github-Verademo	2470774	3		Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)		80	Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)	2025-02-18 15:34:12.283	login.jsp	Open		Not Specified		Static Analysis
Github-Verademo	2470774	3		Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)		80	Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)	2025-02-18 15:34:12.283	login.jsp	Open		Not Specified		Static Analysis
Github-Verademo	2470774	3		Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)		80	Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)	2025-02-18 15:34:12.283	login.jsp	Open		Not Specified		Static Analysis
Github-Verademo	2470774	2		Information Exposure Through an Error Message		209	Generation of Error Message Containing Sensitive Information	2025-02-18 15:34:12.283	login.jsp	Open		Not Specified		Static Analysis
```

## Troubleshooting

### Authentication Errors

**Error:** `401 Unauthorized` or `403 Forbidden`

**Solutions:**
- Verify your API credentials file is correctly formatted
- Ensure your Veracode user/service-account have the required roles 

### No Findings Returned

**Issue:** Script completes but shows 0 findings

**Solutions:**
- Verify the date range contains scan results
- Check that your user has access to applications with findings
- Inspect the raw JSON file to see the actual API response structure

### Timeout Errors

**Error:** `TimeoutError: Report did not complete after X polls`

**Solutions:**
- Increase `--max-polls` value (e.g., `--max-polls 60`)
- Increase `--poll-interval` to reduce API load (e.g., `--poll-interval 10`)
- Try smaller date ranges
- Check Veracode platform status at https://status.veracode.com

### Possible Field Mapping Issues

**Issue:** Some fields are empty or null in the CSV

**Solutions:**
- Check the raw JSON file to see actual field names from the API
- Update the `normalize_finding_record()` function with correct field names
- Some fields may genuinely be empty (e.g., CVE ID if not assigned)

## API Rate Limits

The Veracode API has rate limits. 

This script includes:
- Configurable sleep between windows (`--sleep`)
- Configurable polling interval (`--poll-interval`)
- Automatic retry logic for status checks

**Best Practices:**
- Use reasonable polling intervals (5-10 seconds)
- Avoid running multiple instances simultaneously
- Schedule large exports during off-peak hours


## Veracode API Documentation

For more information about the Veracode Reporting API:
- [Veracode Reporting API Documentation](https://docs.veracode.com/r/Reporting_REST_API)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)

## License

This script is provided as-is for use with Veracode's API. Ensure compliance with your Veracode license agreement.

## Support

For issues with:
- **This script**: Open an Issue
- **Veracode API**: Contact Veracode Support
- **API credentials or roles**: Contact your Veracode Administrator
