# Vault Client Activity Report

## Description

This project includes a Python script, `main.py`, that generates and reads activity reports for Vault client usage. The script fetches data from a Vault server, processes it, and outputs the results in JSON and CSV formats.

## Features

- Generate activity reports for namespaces and mounts.
- Fetch data from a Vault server using specified date ranges.
- Save reports in JSON and CSV formats.
- Print activity reports to the console.

## Requirements

- Python 3.x
- `pip` for managing dependencies
- Required Python packages (listed in `requirements.txt`):
  - `argparse`
  - `requests`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nhsy-hcp/vault-tools.git
   cd activity_export
   ```
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ``` 
3. Ensure you have access to a Vault server and have the necessary permissions to fetch activity data.
4. Set the `VAULT_ADDR` environment variable to point to your Vault server:
   ```bash
   export VAULT_ADDR='https://your-vault-server:8200'
   ```
5. Set the `VAULT_TOKEN` environment variable to your Vault token:
   ```bash
    export VAULT_TOKEN='your-vault-token'
    ```
## Usage
1. To generate a report for a specific namespace:
```text
   python main.py --namespace <namespace> --start-date <start_date> --end-date <end_date>
```
Replace `<namespace>`, `<start_date>`, and `<end_date>` with the desired values.

example below:
```text
   python main.py --namespace my-namespace --start-date 2023-01-01 --end-date 2023-01-31
```

## CLI Usage
The python script supports the following command-line arguments:

```text
python main.py -s <start_date> -e <end_date> -f <json_file> -p
  -s, --start_date: Start date for the activity report (format: YYYY-MM-DD).
  -e, --end_date: End date for the activity report (format: YYYY-MM-DD).
  -f, --filename: JSON file name for the activity report.
  -p, --print: Print the activity report to the console.
```