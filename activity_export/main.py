import argparse
import csv
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import requests

# Constants
DEFAULT_BILLING_START_DATE = "2023-06-01"
REQUEST_TIMEOUT = 300
DATE_FORMAT = "%Y-%m-%d"
FILE_DATE_FORMAT = "%Y%m%d"


class VaultConfig:
    """Configuration for Vault connection and file paths."""
    
    def __init__(self):
        self.vault_addr = os.environ.get('VAULT_ADDR')
        self.vault_token = os.environ.get('VAULT_TOKEN')
        self.date_str = datetime.now().strftime(FILE_DATE_FORMAT)
        
    @property
    def activity_json_filename(self) -> str:
        return f'activity-{self.date_str}.json'
        
    @property
    def activity_namespaces_filename(self) -> str:
        return f'activity-namespaces-{self.date_str}.csv'
        
    @property
    def activity_mounts_filename(self) -> str:
        return f'activity-mounts-{self.date_str}.csv'
        
    def validate_environment(self) -> None:
        """Validate required environment variables are set."""
        if not self.vault_token:
            raise EnvironmentError("VAULT_TOKEN environment variable not set")
        if not self.vault_addr:
            raise EnvironmentError("VAULT_ADDR environment variable not set")


class VaultAPIError(Exception):
    """Custom exception for Vault API errors."""
    pass


class FileProcessingError(Exception):
    """Custom exception for file processing errors."""
    pass


def _get_first_day_of_month(month: datetime) -> datetime:
    """Get the first day of the given month.
    
    Args:
        month: A datetime object representing any day of the month.
        
    Returns:
        A datetime object representing the first day of the input month.
    """
    return month.replace(day=1)


def _get_last_day_of_month(month: datetime) -> datetime:
    """Get the last day of the given month.
    
    Args:
        month: A datetime object representing any day of the month.
        
    Returns:
        A datetime object representing the last day of the input month.
    """
    next_month = month.replace(day=28) + timedelta(days=4)
    return next_month - timedelta(days=next_month.day)


def _get_last_month() -> datetime:
    """Get the last day of the previous month from today's date.
    
    Returns:
        A datetime object representing the last day of the previous month.
    """
    return datetime.today().replace(day=1) - timedelta(days=1)


def validate_date_format(date_str: str) -> None:
    """Validate date string format.
    
    Args:
        date_str: Date string to validate.
        
    Raises:
        ValueError: If date format is invalid.
    """
    try:
        datetime.strptime(date_str, DATE_FORMAT)
    except ValueError as e:
        raise ValueError(f"Invalid date format '{date_str}'. Expected format: {DATE_FORMAT}") from e


def load_data_from_file(json_file_path: str) -> Dict[str, Any]:
    """Load activity data from JSON file.
    
    Args:
        json_file_path: Path to the JSON file.
        
    Returns:
        Dictionary containing the activity data.
        
    Raises:
        FileProcessingError: If file cannot be read or parsed.
    """
    try:
        print(f"Loading activity report from {json_file_path}")
        file_path = Path(json_file_path)
        if not file_path.exists():
            raise FileProcessingError(f"File not found: {json_file_path}")
            
        with open(file_path, "r") as json_file:
            data = json.load(json_file)
            # Handle both formats: direct data or wrapped in "data" key
            if "data" in data:
                return data["data"]
            elif "by_namespace" in data:
                return data
            else:
                raise FileProcessingError(f"Invalid file format: missing 'by_namespace' key in {json_file_path}")
    except (json.JSONDecodeError, OSError) as e:
        raise FileProcessingError(f"Error reading file {json_file_path}: {e}") from e


def fetch_data_from_vault(config: VaultConfig, start_date: str, end_date: str) -> Dict[str, Any]:
    """Fetch activity data from Vault API.
    
    Args:
        config: VaultConfig instance with connection details.
        start_date: Start date in YYYY-MM-DD format.
        end_date: End date in YYYY-MM-DD format.
        
    Returns:
        Dictionary containing the activity data.
        
    Raises:
        VaultAPIError: If API request fails.
    """
    url = f"{config.vault_addr}/v1/sys/internal/counters/activity?end_time={end_date}T00%3A00%3A00Z&start_time={start_date}T00%3A00%3A00Z"
    print(f"Fetching activity report data for {start_date} to {end_date}")
    print(f"URL: {url}")
    
    headers = {'X-Vault-Token': config.vault_token}
    
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
        
        if response.status_code == 200:
            data = response.json()["data"]
            
            # Print summary information
            total = data.get('total', {})
            print(f"Summary - Start datetime: {data.get('start_time', 'N/A')}, "
                  f"clients: {total.get('clients', 0)}, "
                  f"entity_clients: {total.get('entity_clients', 0)}, "
                  f"non_entity_clients: {total.get('non_entity_clients', 0)}\n")
            
            # Save raw data to JSON file
            try:
                with open(config.activity_json_filename, 'w') as jsonfile:
                    json.dump(data, jsonfile, indent=2)
            except OSError as e:
                print(f"Warning: Could not save JSON file: {e}")
                
            return data
        else:
            raise VaultAPIError(
                f"Vault API request failed with status {response.status_code}: {response.text}"
            )
    except requests.RequestException as e:
        raise VaultAPIError(f"Failed to connect to Vault: {e}") from e


def process_activity_data(data: Dict[str, Any]) -> Tuple[List[List[str]], List[List[str]]]:
    """Process activity data into namespace and mount lists.
    
    Args:
        data: Raw activity data from Vault.
        
    Returns:
        Tuple of (namespaces_data, mounts_data) as lists of lists.
    """
    namespaces = [['namespace_id', 'namespace_path', 'mounts', 'clients', 'entity_clients', 'non_entity_clients']]
    mounts = [['namespace_id', 'namespace_path', 'mount_path', 'clients', 'entity_clients', 'non_entity_clients']]
    
    by_namespace = data.get("by_namespace", [])
    
    for namespace in by_namespace:
        ns_id = namespace.get("namespace_id", "")
        ns_path = namespace.get("namespace_path", "")
        ns_mounts = namespace.get("mounts", [])
        ns_counts = namespace.get("counts", {})
        
        namespaces.append([
            ns_id,
            ns_path,
            len(ns_mounts),
            ns_counts.get("clients", 0),
            ns_counts.get("entity_clients", 0),
            ns_counts.get("non_entity_clients", 0)
        ])
        
        for mount in ns_mounts:
            mount_counts = mount.get("counts", {})
            mounts.append([
                ns_id,
                ns_path,
                mount.get("mount_path", ""),
                mount_counts.get("clients", 0),
                mount_counts.get("entity_clients", 0),
                mount_counts.get("non_entity_clients", 0)
            ])
    
    return namespaces, mounts


def write_csv_reports(config: VaultConfig, namespaces_data: List[List[str]], mounts_data: List[List[str]]) -> None:
    """Write namespace and mount data to CSV files.
    
    Args:
        config: VaultConfig instance with file paths.
        namespaces_data: List of namespace data rows.
        mounts_data: List of mount data rows.
        
    Raises:
        FileProcessingError: If CSV files cannot be written.
    """
    try:
        with open(config.activity_mounts_filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerows(mounts_data)
            
        with open(config.activity_namespaces_filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerows(namespaces_data)
            
        print(f"CSV reports written to {config.activity_namespaces_filename} and {config.activity_mounts_filename}")
    except OSError as e:
        raise FileProcessingError(f"Error writing CSV files: {e}") from e


def create_activity_report(config: VaultConfig, start_date: Optional[str] = None, 
                         end_date: Optional[str] = None, json_file_name: Optional[str] = None) -> None:
    """Create an activity report from Vault API or JSON file.
    
    Args:
        config: VaultConfig instance with connection details and file paths.
        start_date: Start date in YYYY-MM-DD format.
        end_date: End date in YYYY-MM-DD format.
        json_file_name: Path to JSON file to process instead of fetching from API.
        
    Raises:
        VaultAPIError: If API request fails.
        FileProcessingError: If file operations fail.
        ValueError: If date format is invalid.
    """
    if json_file_name:
        data = load_data_from_file(json_file_name)
    else:
        if not start_date or not end_date:
            raise ValueError("start_date and end_date must be provided when not using a JSON file")
        validate_date_format(start_date)
        validate_date_format(end_date)
        config.validate_environment()
        data = fetch_data_from_vault(config, start_date, end_date)
    
    namespaces_data, mounts_data = process_activity_data(data)
    write_csv_reports(config, namespaces_data, mounts_data)


def read_activity_report(config: VaultConfig) -> None:
    """Read and display activity reports from CSV files.
    
    Args:
        config: VaultConfig instance with file paths.
        
    Raises:
        FileProcessingError: If CSV files cannot be read.
    """
    try:
        print("Namespace client counts:")
        with open(config.activity_namespaces_filename, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                print(row)
        
        print("\nMount path client counts:")
        with open(config.activity_mounts_filename, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                print(row)
    except OSError as e:
        raise FileProcessingError(f"Error reading CSV files: {e}") from e


def main() -> None:
    """Main function to handle CLI arguments and execute the activity report generation."""
    parser = argparse.ArgumentParser(
        description='Create vault client activity report.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Generate report for specific date range
  {sys.argv[0]} -s 2024-01-01 -e 2024-01-31 -p
  
  # Process existing JSON file
  {sys.argv[0]} -f activity-20240101.json -p
  
  # Use default date range (billing start to last month)
  {sys.argv[0]} -p
"""
    )
    
    parser.add_argument(
        '-s', '--start_date', 
        type=str, 
        help='Start date (YYYY-MM-DD) for the activity report'
    )
    parser.add_argument(
        '-e', '--end_date', 
        type=str, 
        help='End date (YYYY-MM-DD) for the activity report'
    )
    parser.add_argument(
        '-f', '--filename', 
        type=str, 
        help='JSON file name for the activity report'
    )
    parser.add_argument(
        '-p', '--print', 
        default=False, 
        action=argparse.BooleanOptionalAction,
        help='Print the activity report to console'
    )
    
    args = parser.parse_args()
    config = VaultConfig()
    
    try:
        # Determine date range
        start_date = args.start_date or DEFAULT_BILLING_START_DATE
        end_date = args.end_date or _get_last_month().strftime(DATE_FORMAT)
        
        # Generate the report
        if args.filename:
            create_activity_report(config, json_file_name=args.filename)
        else:
            create_activity_report(config, start_date=start_date, end_date=end_date)
        
        # Print the report if requested
        if args.print:
            read_activity_report(config)
            
    except (VaultAPIError, FileProcessingError, EnvironmentError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
