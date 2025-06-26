import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd
import requests

# Constants
REQUEST_TIMEOUT = 300
DATE_FORMAT = "%Y-%m-%d"
FILE_DATE_FORMAT = "%Y%m%d"

# Configure logging
logger = logging.getLogger(__name__)


def setup_logging(debug: bool = False) -> None:
    """Configure logging based on debug flag.
    
    Args:
        debug: Enable debug logging if True.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Set specific loggers
    logger.setLevel(level)
    
    # Reduce noise from requests library unless in debug mode
    if not debug:
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logger.debug("Debug logging enabled")


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
        
    @property
    def entity_export_json_filename(self) -> str:
        return f'entity-export-{self.date_str}.json'
        
    @property
    def entity_export_entities_csv_filename(self) -> str:
        return f'entity-export-{self.date_str}.csv'
        
    def validate_environment(self) -> None:
        """Validate required environment variables are set."""
        logger.debug("Validating environment variables")
        if not self.vault_token:
            logger.error("VAULT_TOKEN environment variable not set")
            raise EnvironmentError("VAULT_TOKEN environment variable not set")
        if not self.vault_addr:
            logger.error("VAULT_ADDR environment variable not set")
            raise EnvironmentError("VAULT_ADDR environment variable not set")
        logger.debug(f"Environment validated - Vault address: {self.vault_addr}")


class VaultAPIError(Exception):
    """Custom exception for Vault API errors."""
    pass


class FileProcessingError(Exception):
    """Custom exception for file processing errors."""
    pass


def parse_vault_response(response: requests.Response) -> Any:
    """Parse Vault API response with robust error handling.
    
    This function handles various response formats that Vault might return:
    - Standard JSON objects
    - NDJSON (newline-delimited JSON)
    - Malformed responses with trailing data
    
    Args:
        response: requests.Response object from Vault API
        
    Returns:
        Parsed data from the response
        
    Raises:
        VaultAPIError: If response cannot be parsed
    """
    content = response.text
    logger.debug(f"Response content type: {response.headers.get('content-type', 'unknown')}")
    logger.debug(f"Response content length: {len(content)} characters")
    
    if not content.strip():
        logger.warning("Empty response content")
        return []
    
    # Try standard JSON parsing first
    try:
        data = response.json()
        logger.debug("Successfully parsed response as standard JSON")
        return data
    except json.JSONDecodeError as e:
        logger.debug(f"Standard JSON parsing failed: {e}")
        
        # Try parsing as NDJSON (newline-delimited JSON)
        try:
            lines = content.strip().split('\n')
            parsed_data = []
            
            for i, line in enumerate(lines):
                line = line.strip()
                if line:  # Skip empty lines
                    try:
                        parsed_data.append(json.loads(line))
                        logger.debug(f"Successfully parsed line {i+1} as JSON")
                    except json.JSONDecodeError:
                        logger.debug(f"Skipping line {i+1} - not valid JSON: {line[:100]}...")
                        continue
            
            if parsed_data:
                logger.debug(f"Successfully parsed {len(parsed_data)} JSON objects from NDJSON format")
                return parsed_data
        except Exception as ndjson_error:
            logger.debug(f"NDJSON parsing failed: {ndjson_error}")
        
        # Try extracting the first valid JSON object
        try:
            # Find the first complete JSON object
            decoder = json.JSONDecoder()
            data, idx = decoder.raw_decode(content)
            logger.warning(f"Extracted first JSON object, ignoring {len(content) - idx} trailing characters")
            logger.debug(f"Trailing content: {content[idx:100]}...")
            return data
        except json.JSONDecodeError as extract_error:
            logger.debug(f"JSON extraction failed: {extract_error}")
        
        # Log response content for debugging
        logger.error(f"Failed to parse response. Content preview: {content[:500]}...")
        
        # Try to save the problematic response for debugging
        try:
            debug_filename = f"vault_response_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(debug_filename, 'w') as debug_file:
                debug_file.write(f"Response Status: {response.status_code}\n")
                debug_file.write(f"Response Headers: {dict(response.headers)}\n\n")
                debug_file.write(f"Response Content:\n{content}")
            logger.info(f"Saved problematic response to {debug_filename} for debugging")
        except Exception as save_error:
            logger.debug(f"Could not save debug file: {save_error}")
        
        raise VaultAPIError(
            f"Failed to parse Vault response as JSON. Original error: {e}. "
            f"Response length: {len(content)} characters. "
            f"Content preview: {content[:200]}..."
        )


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
    logger.debug(f"Validating date format: {date_str}")
    try:
        datetime.strptime(date_str, DATE_FORMAT)
        logger.debug(f"Date format valid: {date_str}")
    except ValueError as e:
        logger.error(f"Invalid date format '{date_str}'. Expected format: {DATE_FORMAT}")
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
        logger.info(f"Loading activity report from {json_file_path}")
        print(f"Loading activity report from {json_file_path}")
        file_path = Path(json_file_path)
        if not file_path.exists():
            logger.error(f"File not found: {json_file_path}")
            raise FileProcessingError(f"File not found: {json_file_path}")
            
        logger.debug(f"Reading JSON file: {file_path}")
        with open(file_path, "r") as json_file:
            data = json.load(json_file)
            logger.debug(f"JSON loaded successfully. Keys: {list(data.keys()) if isinstance(data, dict) else 'Non-dict data'}")
            
            # Handle both formats: direct data or wrapped in "data" key
            if "data" in data:
                logger.debug("Found 'data' wrapper, extracting nested data")
                return data["data"]
            elif "by_namespace" in data:
                logger.debug("Found direct format with 'by_namespace' key")
                return data
            else:
                logger.error(f"Invalid file format: missing 'by_namespace' key in {json_file_path}")
                raise FileProcessingError(f"Invalid file format: missing 'by_namespace' key in {json_file_path}")
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Error reading file {json_file_path}: {e}")
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
    logger.info(f"Fetching activity report data for {start_date} to {end_date}")
    logger.debug(f"Request URL: {url}")
    print(f"Fetching activity report data for {start_date} to {end_date}")
    print(f"URL: {url}")
    
    headers = {'X-Vault-Token': config.vault_token}
    logger.debug(f"Request headers configured (token length: {len(config.vault_token) if config.vault_token else 0})")
    
    try:
        logger.debug(f"Making GET request with timeout={REQUEST_TIMEOUT}, verify=True")
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
        logger.debug(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            logger.debug("Successfully received response, parsing JSON")
            data = response.json()["data"]
            logger.debug(f"JSON response keys: {list(data.keys()) if isinstance(data, dict) else 'Non-dict data'}")
            
            # Print summary information
            total = data.get('total', {})
            logger.info(f"Activity data summary - Start: {data.get('start_time', 'N/A')}, "
                       f"Total clients: {total.get('clients', 0)}, "
                       f"Entity clients: {total.get('entity_clients', 0)}, "
                       f"Non-entity clients: {total.get('non_entity_clients', 0)}")
            print(f"Summary - Start datetime: {data.get('start_time', 'N/A')}, "
                  f"clients: {total.get('clients', 0)}, "
                  f"entity_clients: {total.get('entity_clients', 0)}, "
                  f"non_entity_clients: {total.get('non_entity_clients', 0)}\n")
            
            # Save raw data to JSON file
            try:
                logger.debug(f"Saving JSON data to {config.activity_json_filename}")
                with open(config.activity_json_filename, 'w') as jsonfile:
                    json.dump(data, jsonfile, indent=2)
                logger.info(f"JSON data saved to {config.activity_json_filename}")
            except OSError as e:
                logger.warning(f"Could not save JSON file: {e}")
                print(f"Warning: Could not save JSON file: {e}")
                
            return data
        else:
            logger.error(f"Vault API request failed with status {response.status_code}: {response.text}")
            raise VaultAPIError(
                f"Vault API request failed with status {response.status_code}: {response.text}"
            )
    except requests.RequestException as e:
        logger.error(f"Failed to connect to Vault: {e}")
        raise VaultAPIError(f"Failed to connect to Vault: {e}") from e


def fetch_entity_export_from_vault(config: VaultConfig, start_date: str, end_date: str) -> List[Dict[str, Any]]:
    """Fetch entity export data from Vault API.
    
    Args:
        config: VaultConfig instance with connection details.
        start_date: Start date in YYYY-MM-DD format.
        end_date: End date in YYYY-MM-DD format.
        
    Returns:
        List containing the entity export data.
        
    Raises:
        VaultAPIError: If API request fails.
    """
    # Convert dates to RFC3339 format for the API
    start_rfc3339 = f"{start_date}T00:00:00Z"
    end_rfc3339 = f"{end_date}T23:59:59Z"
    logger.debug(f"Converted dates to RFC3339 format: {start_rfc3339} to {end_rfc3339}")
    
    url = f"{config.vault_addr}/v1/sys/internal/counters/activity/export"
    params = {
        'start_time': start_rfc3339,
        'end_time': end_rfc3339,
        'format': 'json'
    }

    logger.info(f"Fetching entity export data for {start_date} to {end_date}")
    logger.debug(f"Request URL: {url}")
    logger.debug(f"Request parameters: {params}")
    print(f"Fetching entity export data for {start_date} to {end_date}")
    print(f"URL: {url}")
    print(f"Parameters: {params}")
    
    headers = {'X-Vault-Token': config.vault_token}
    logger.debug(f"Request headers configured for entity export")
    
    try:
        logger.debug(f"Making GET request for entity export with timeout={REQUEST_TIMEOUT}")
        logger.debug(f"Request URL: {url}")
        logger.debug(f"Request params: {params}")
        
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT, verify=True)
        
        logger.debug(f"Entity export response status: {response.status_code}")
        logger.debug(f"Response content-type: {response.headers.get('content-type', 'not specified')}")
        logger.debug(f"Response content-length: {response.headers.get('content-length', 'not specified')}")
        try:
            logger.debug(f"Actual response size: {len(response.content)} bytes")
        except (TypeError, AttributeError):
            logger.debug("Response content size: unable to determine")
        
        if response.status_code == 200:
            logger.debug("Successfully received entity export response, parsing JSON")
            logger.debug(f"Response headers: {dict(response.headers)}")
            logger.debug(f"Response status: {response.status_code}")
            
            # Use robust JSON parsing
            data = parse_vault_response(response)
            logger.debug(f"Entity export JSON type: {type(data)}, size: {len(data) if isinstance(data, (list, dict)) else 'unknown'}")
            
            # Handle both direct list and wrapped response formats
            if isinstance(data, list):
                entity_data = data
                logger.debug("Entity data is direct list format")
            elif isinstance(data, dict) and 'data' in data:
                entity_data = data['data']
                logger.debug("Entity data extracted from 'data' wrapper")
            else:
                # If data is neither list nor dict with 'data' key, try to convert to list
                if isinstance(data, dict):
                    # If it's a single dict object, wrap it in a list
                    entity_data = [data]
                    logger.debug("Wrapped single dict object in list")
                else:
                    entity_data = data
                    logger.debug("Using entity data as-is (unknown format)")
            
            # Ensure entity_data is a list for consistent handling
            if not isinstance(entity_data, list):
                logger.warning(f"Entity data is not a list (type: {type(entity_data)}), attempting conversion")
                entity_data = [entity_data] if entity_data else []
            
            logger.info(f"Retrieved {len(entity_data)} entity records")
            print(f"Retrieved {len(entity_data)} entity records\n")
            
            # Log sample of data structure for debugging
            if entity_data and len(entity_data) > 0:
                sample_record = entity_data[0]
                logger.debug(f"Sample entity record keys: {list(sample_record.keys()) if isinstance(sample_record, dict) else 'not a dict'}")
                logger.debug(f"Sample entity record: {str(sample_record)[:200]}...")
            
            # Save raw data to JSON file
            try:
                logger.debug(f"Saving entity export JSON to {config.entity_export_json_filename}")
                with open(config.entity_export_json_filename, 'w') as jsonfile:
                    json.dump(entity_data, jsonfile, indent=2)
                logger.info(f"Entity export JSON saved to {config.entity_export_json_filename}")
                print(f"Entity export JSON saved to {config.entity_export_json_filename}")
            except OSError as e:
                logger.warning(f"Could not save entity export JSON file: {e}")
                print(f"Warning: Could not save entity export JSON file: {e}")
                
            return entity_data
        else:
            logger.error(f"Vault entity export API request failed with status {response.status_code}")
            logger.error(f"Response headers: {dict(response.headers)}")
            logger.error(f"Response content preview: {response.text[:500]}...")
            raise VaultAPIError(
                f"Vault entity export API request failed with status {response.status_code}: {response.text[:200]}..."
            )
    except VaultAPIError:
        # Re-raise VaultAPIError (including JSON parsing errors) as-is
        raise
    except requests.RequestException as e:
        logger.error(f"Failed to connect to Vault for entity export: {e}")
        raise VaultAPIError(f"Failed to connect to Vault for entity export: {e}") from e


def process_activity_data(data: Dict[str, Any]) -> Tuple[List[List[str]], List[List[str]]]:
    """Process activity data into namespace and mount lists.
    
    Args:
        data: Raw activity data from Vault.
        
    Returns:
        Tuple of (namespaces_data, mounts_data) as lists of lists.
    """
    logger.debug("Processing activity data into namespace and mount lists")
    namespaces = [['namespace_id', 'namespace_path', 'mounts', 'clients', 'entity_clients', 'non_entity_clients']]
    mounts = [['namespace_id', 'namespace_path', 'mount_path', 'clients', 'entity_clients', 'non_entity_clients']]
    
    by_namespace = data.get("by_namespace", [])
    logger.debug(f"Found {len(by_namespace)} namespaces to process")
    
    for namespace in by_namespace:
        ns_id = namespace.get("namespace_id", "")
        ns_path = namespace.get("namespace_path", "")
        ns_mounts = namespace.get("mounts", [])
        ns_counts = namespace.get("counts", {})
        
        logger.debug(f"Processing namespace {ns_id} ({ns_path}) with {len(ns_mounts)} mounts")
        
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
            mount_path = mount.get("mount_path", "")
            logger.debug(f"Processing mount {mount_path} in namespace {ns_id}")
            mounts.append([
                ns_id,
                ns_path,
                mount_path,
                mount_counts.get("clients", 0),
                mount_counts.get("entity_clients", 0),
                mount_counts.get("non_entity_clients", 0)
            ])
    
    logger.info(f"Processed {len(namespaces)-1} namespaces and {len(mounts)-1} mounts")
    return namespaces, mounts


def process_entity_export_data(entity_data: List[Dict[str, Any]]) -> pd.DataFrame:
    """Process entity export data using pandas for analysis.
    
    Args:
        entity_data: List of entity records from Vault export.
        
    Returns:
        pandas DataFrame with processed entity data and summaries.
        
    Raises:
        FileProcessingError: If data processing fails.
    """
    try:
        logger.debug(f"Processing entity export data with {len(entity_data)} records")
        if not entity_data:
            logger.warning("No entity data to process")
            print("Warning: No entity data to process")
            return pd.DataFrame()
        
        # Convert to DataFrame
        logger.debug("Converting entity data to pandas DataFrame")
        df = pd.DataFrame(entity_data)
        logger.debug(f"DataFrame created with shape: {df.shape}, columns: {list(df.columns)}")
        
        # Ensure required columns exist with defaults
        required_columns = {
            'client_id': '',
            'namespace_id': '',
            'timestamp': '',
            'mount_accessor': '',
            'non_entity': False
        }
        
        logger.debug("Ensuring required columns exist with defaults")
        for col, default_val in required_columns.items():
            if col not in df.columns:
                logger.debug(f"Adding missing column '{col}' with default value: {default_val}")
                df[col] = default_val
        
        # Convert timestamp to datetime if it exists
        if 'timestamp' in df.columns and not df['timestamp'].empty:
            logger.debug("Converting timestamp column to datetime")
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            # Convert timezone-aware timestamps to UTC, then remove timezone info to avoid warning
            if hasattr(df['timestamp'].dtype, 'tz') and df['timestamp'].dtype.tz is not None:
                df['timestamp'] = df['timestamp'].dt.tz_convert('UTC').dt.tz_localize(None)
            df['month'] = df['timestamp'].dt.to_period('M')
            logger.debug(f"Timestamp conversion complete. Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
        
        # Fill NaN values
        logger.debug("Filling NaN values with defaults")
        df = df.fillna({
            'client_id': 'unknown',
            'namespace_id': 'root',
            'mount_accessor': 'unknown',
            'non_entity': False
        })
        
        # Add analysis columns
        logger.debug("Adding entity_type analysis column")
        df['entity_type'] = df['non_entity'].map({True: 'non_entity', False: 'entity'})
        
        # Log summary statistics
        unique_clients = df['client_id'].nunique()
        unique_namespaces = df['namespace_id'].nunique()
        entity_type_counts = df['entity_type'].value_counts().to_dict()
        
        logger.info(f"Entity export processing complete: {len(df)} records, {unique_clients} unique clients, {unique_namespaces} unique namespaces")
        logger.debug(f"Entity type breakdown: {entity_type_counts}")
        
        print(f"Processed {len(df)} entity records")
        print(f"Unique clients: {unique_clients}")
        print(f"Unique namespaces: {unique_namespaces}")
        print(f"Entity types: {entity_type_counts}")
        
        return df
        
    except Exception as e:
        logger.error(f"Error processing entity export data: {e}")
        raise FileProcessingError(f"Error processing entity export data: {e}") from e


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
        logger.debug(f"Writing {len(mounts_data)} mount records to {config.activity_mounts_filename}")
        with open(config.activity_mounts_filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerows(mounts_data)
        logger.debug(f"Mount CSV file written successfully")
            
        logger.debug(f"Writing {len(namespaces_data)} namespace records to {config.activity_namespaces_filename}")
        with open(config.activity_namespaces_filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerows(namespaces_data)
        logger.debug(f"Namespace CSV file written successfully")
            
        logger.info(f"CSV reports written to {config.activity_namespaces_filename} and {config.activity_mounts_filename}")
        print(f"CSV reports written to {config.activity_namespaces_filename} and {config.activity_mounts_filename}")
    except OSError as e:
        logger.error(f"Error writing CSV files: {e}")
        raise FileProcessingError(f"Error writing CSV files: {e}") from e



def write_entities_csv_report(config: VaultConfig, df: pd.DataFrame) -> None:
    """Write comprehensive entity data to CSV file with all metadata fields.
    
    Args:
        config: VaultConfig instance with file paths.
        df: pandas DataFrame with processed entity data.
        
    Raises:
        FileProcessingError: If CSV file cannot be written.
    """
    try:
        if df.empty:
            logger.warning("No entity data to write to entities CSV file")
            print("No entity data to write to entities CSV file")
            return
        
        # Define all possible entity columns with full metadata
        entity_columns = [
            'client_id', 'entity_name', 'entity_alias_name', 'local_entity_alias', 
            'client_type', 'namespace_id', 'namespace_path', 'mount_accessor', 
            'mount_type', 'mount_path', 'timestamp', 'policies', 
            'entity_group_ids', 'entity_metadata', 'entity_alias_metadata', 
            'entity_alias_custom_metadata'
        ]
        
        # Get available columns from the DataFrame
        available_columns = [col for col in entity_columns if col in df.columns]
        
        logger.debug(f"Writing entities CSV with {len(available_columns)} columns to {config.entity_export_entities_csv_filename}")
        logger.debug(f"Available columns: {available_columns}")
        
        # Create a copy of the DataFrame to avoid modifying the original
        df_copy = df.copy()
        
        # Helper function to safely serialize values to JSON
        def safe_json_serialize(x):
            """Safely serialize a value to JSON string, handling pandas arrays and None values."""
            if x is None:
                return '{}'
            
            # Handle numpy arrays and pandas Series - check if it's a scalar value first
            if hasattr(x, 'size') and x.size == 0:
                return '[]'  # Empty array
            elif hasattr(x, 'size') and x.size == 1:
                # Single-element array, extract the scalar value
                try:
                    scalar_x = x.item() if hasattr(x, 'item') else x[0]
                    return safe_json_serialize(scalar_x)  # Recursively handle the scalar
                except (IndexError, TypeError):
                    pass
            
            # For scalar values, check for pandas NA using scalar-safe method
            if not hasattr(x, '__len__') or isinstance(x, str):
                try:
                    if pd.isna(x):
                        return '{}'
                except (ValueError, TypeError):
                    pass
            
            # Handle lists and dicts
            if isinstance(x, (list, dict)):
                return json.dumps(x)
            
            # Handle any other type by converting to JSON
            return json.dumps(x)
        
        # Serialize complex fields (lists and dicts) to JSON strings
        json_fields = ['policies', 'entity_group_ids', 'entity_metadata', 
                      'entity_alias_metadata', 'entity_alias_custom_metadata']
        
        for field in json_fields:
            if field in df_copy.columns:
                logger.debug(f"Serializing JSON field: {field}")
                df_copy[field] = df_copy[field].apply(safe_json_serialize)
        
        # Write CSV file with comprehensive entity data
        with open(config.entity_export_entities_csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header row
            writer.writerow(available_columns)
            
            # Write data rows
            for _, row in df_copy.iterrows():
                writer.writerow([row.get(col, '') for col in available_columns])
        
        logger.info(f"Entities CSV written to {config.entity_export_entities_csv_filename}")
        print(f"Entities CSV written to {config.entity_export_entities_csv_filename}")
        
    except Exception as e:
        logger.error(f"Error writing entities CSV file: {e}")
        raise FileProcessingError(f"Error writing entities CSV file: {e}") from e


def load_entity_export_from_file(json_file_path: str) -> List[Dict[str, Any]]:
    """Load entity export data from JSON file.
    
    Args:
        json_file_path: Path to the entity export JSON file.
        
    Returns:
        List containing the entity export data.
        
    Raises:
        FileProcessingError: If file cannot be read or parsed.
    """
    try:
        print(f"Loading entity export from {json_file_path}")
        file_path = Path(json_file_path)
        if not file_path.exists():
            raise FileProcessingError(f"File not found: {json_file_path}")
            
        with open(file_path, "r") as json_file:
            data = json.load(json_file)
            
        # Handle both direct list and wrapped formats
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and 'data' in data:
            return data['data']
        else:
            # Try to return as-is if it's a dict that might contain entity data
            return data if isinstance(data, list) else [data]
            
    except (json.JSONDecodeError, OSError) as e:
        raise FileProcessingError(f"Error reading entity export file {json_file_path}: {e}") from e


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
    logger.info(f"Creating activity report - file: {json_file_name}, dates: {start_date} to {end_date}")
    
    if json_file_name:
        logger.debug(f"Using existing JSON file: {json_file_name}")
        data = load_data_from_file(json_file_name)
    else:
        if not start_date or not end_date:
            logger.error("start_date and end_date must be provided when not using a JSON file")
            raise ValueError("start_date and end_date must be provided when not using a JSON file")
        logger.debug(f"Fetching data from Vault API for date range: {start_date} to {end_date}")
        validate_date_format(start_date)
        validate_date_format(end_date)
        config.validate_environment()
        data = fetch_data_from_vault(config, start_date, end_date)
    
    logger.debug("Processing activity data")
    namespaces_data, mounts_data = process_activity_data(data)
    logger.debug("Writing CSV reports")
    write_csv_reports(config, namespaces_data, mounts_data)
    logger.info("Activity report creation completed successfully")


def create_entity_export_report(config: VaultConfig, start_date: Optional[str] = None, 
                               end_date: Optional[str] = None, json_file_name: Optional[str] = None) -> None:
    """Create an entity export report from Vault API or JSON file.
    
    Args:
        config: VaultConfig instance with connection details and file paths.
        start_date: Start date in YYYY-MM-DD format.
        end_date: End date in YYYY-MM-DD format.
        json_file_name: Path to entity export JSON file to process instead of fetching from API.
        
    Raises:
        VaultAPIError: If API request fails.
        FileProcessingError: If file operations fail.
        ValueError: If date format is invalid.
    """
    logger.info(f"Creating entity export report - file: {json_file_name}, dates: {start_date} to {end_date}")
    
    if json_file_name:
        logger.debug(f"Using existing entity export JSON file: {json_file_name}")
        entity_data = load_entity_export_from_file(json_file_name)
    else:
        if not start_date or not end_date:
            logger.error("start_date and end_date must be provided when not using a JSON file")
            raise ValueError("start_date and end_date must be provided when not using a JSON file")
        logger.debug(f"Fetching entity data from Vault API for date range: {start_date} to {end_date}")
        validate_date_format(start_date)
        validate_date_format(end_date)
        config.validate_environment()
        entity_data = fetch_entity_export_from_vault(config, start_date, end_date)
    
    logger.debug("Processing entity export data")
    df = process_entity_export_data(entity_data)
    logger.debug("Writing entities CSV report")
    write_entities_csv_report(config, df)
    logger.info("Entity export report creation completed successfully")


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
  
  # Generate entity export report
  {sys.argv[0]} --entity-export -s 2024-01-01 -e 2024-01-31
  
  # Process existing entity export JSON file
  {sys.argv[0]} --entity-export --entity-filename entity-export-20240101.json
  
  # Enable debug logging
  {sys.argv[0]} --debug -s 2024-01-01 -e 2024-01-31 -p
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
    parser.add_argument(
        '--entity-export', 
        default=False, 
        action=argparse.BooleanOptionalAction,
        help='Generate entity export report instead of regular activity report'
    )
    parser.add_argument(
        '--entity-filename', 
        type=str, 
        help='JSON file name for the entity export report'
    )
    parser.add_argument(
        '--debug', 
        default=False, 
        action=argparse.BooleanOptionalAction,
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging first
    setup_logging(debug=args.debug)
    
    config = VaultConfig()
    logger.debug(f"VaultConfig initialized with date_str: {config.date_str}")
    
    try:
        # Determine date range
        start_date = args.start_date
        end_date = args.end_date or _get_last_month().strftime(DATE_FORMAT)
        
        # Require start_date if not using existing files
        if not start_date and not args.filename and not args.entity_filename:
            logger.error("start_date is required when not using existing JSON files")
            print("Error: start_date (-s/--start_date) is required when not using existing JSON files", file=sys.stderr)
            sys.exit(1)
        logger.debug(f"Using date range: {start_date} to {end_date}")
        
        # Generate the appropriate report type
        if args.entity_export:
            logger.info("Starting entity export report generation")
            # Generate entity export report
            if args.entity_filename:
                create_entity_export_report(config, json_file_name=args.entity_filename)
            else:
                create_entity_export_report(config, start_date=start_date, end_date=end_date)
            print(f"Entity export report completed. Files: {config.entity_export_json_filename}, {config.entity_export_entities_csv_filename}")
        else:
            # Generate regular activity report
            logger.info("Starting regular activity report generation")
            if args.filename:
                create_activity_report(config, json_file_name=args.filename)
            else:
                create_activity_report(config, start_date=start_date, end_date=end_date)
            
            # Print the report if requested
            if args.print:
                logger.debug("Printing activity report to console")
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
