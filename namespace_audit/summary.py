#!/usr/bin/env python3
"""
Namespace audit summary module for processing Vault cluster data.

This module provides functionality to parse and analyze Vault namespace data,
authentication methods, and secret engines, outputting the results to CSV files.
"""
import argparse
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Dict, Any, Optional

import pandas as pd


def extract_level_1_namespace(namespace_path: str) -> str:
    """
    Extract the level 1 namespace from a namespace path.
    
    Args:
        namespace_path: The full namespace path
        
    Returns:
        The level 1 namespace with trailing slash
    """
    return namespace_path.split('/')[0] + '/'


def setup_logger(log_level: str = "INFO") -> logging.Logger:
    """
    Configure and return a logger with the specified log level.

    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        A configured logger instance
    """
    level = getattr(logging, log_level.upper())
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger(__name__)


def load_json_data(filename: str) -> Dict[str, Any]:
    """
    Load JSON data from a file.

    Args:
        filename: The path to the JSON file

    Returns:
        Dictionary containing the JSON data

    Raises:
        ValueError: If filename is invalid
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If the file contains invalid JSON
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string")
    
    file_path = Path(filename)
    if not file_path.suffix.lower() == '.json':
        logging.warning(f"File {filename} does not have .json extension")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as jsonfile:
            data = json.load(jsonfile)
            if not isinstance(data, dict):
                raise ValueError(f"JSON data in {filename} must be a dictionary")
            return data
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in {filename}: {e}")
        raise
    except PermissionError as e:
        logging.error(f"Permission denied accessing {filename}: {e}")
        raise


def parse_namespaces(data: Dict[str, Any], csv_filename: str) -> pd.DataFrame:
    """
    Parse namespaces from the provided data and write the results to a CSV file.

    Args:
        data: A dictionary containing the namespace data
        csv_filename: The name of the CSV file to write the results to

    Returns:
        DataFrame containing the processed namespace data
    
    Raises:
        ValueError: If data is invalid
    """
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary")
    if not csv_filename or not isinstance(csv_filename, str):
        raise ValueError("CSV filename must be a non-empty string")
    
    logging.debug("Parsing namespaces")
    
    if not data:
        logging.warning("No namespace data to process")
        df = pd.DataFrame(columns=['path', 'level_1_namespace', 'id', 'custom_metadata'])
    else:
        df = pd.DataFrame.from_dict(data, orient='index', columns=['path', 'id', 'custom_metadata'])
        df.insert(1, 'level_1_namespace', df['path'].apply(extract_level_1_namespace))
    
    try:
        df.to_csv(csv_filename, index=False)
    except (IOError, OSError) as e:
        logging.error(f"Failed to write CSV file {csv_filename}: {e}")
        raise
    
    logging.debug(f"Namespaces processed: {len(df)}")
    if len(df) > 0:
        logging.debug(f"Sample data:\n{df.head(3)}")
    return df


def parse_vault_items(data: Dict[str, Any], csv_filename: str, item_name: str) -> pd.DataFrame:
    """
    Generic parser for Vault items (auth methods or secret engines).
    
    Args:
        data: A dictionary containing the item data
        csv_filename: The name of the CSV file to write the results to
        item_name: Name of the item type for logging (e.g., "auth methods", "secret engines")
        
    Returns:
        DataFrame containing the processed item data
        
    Raises:
        ValueError: If input parameters are invalid
    """
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary")
    if not csv_filename or not isinstance(csv_filename, str):
        raise ValueError("CSV filename must be a non-empty string")
    if not item_name or not isinstance(item_name, str):
        raise ValueError("Item name must be a non-empty string")
        
    logging.debug(f"Parsing {item_name}")
    result = {}

    for namespace_path in data.keys():
        if not isinstance(namespace_path, str):
            logging.warning(f"Skipping non-string namespace path: {namespace_path}")
            continue
            
        items = {
            'namespace_path': namespace_path,
            'level_1_namespace': extract_level_1_namespace(namespace_path)
        }

        namespace_data = data[namespace_path]
        if not isinstance(namespace_data, dict):
            logging.warning(f"Skipping non-dict data for namespace {namespace_path}")
            continue

        # Find all items and count them by type
        for item in [v for v in namespace_data.values() if isinstance(v, dict)]:
            # Handle nested items
            for mount in [v for v in item.values() if isinstance(v, dict) and 'type' in v]:
                item_type = mount.get('type')
                if item_type:
                    items[item_type] = items.get(item_type, 0) + 1

        # Handle direct items
        for item in [v for v in namespace_data.values() if isinstance(v, dict) and 'type' in v]:
            item_type = item.get('type')
            if item_type:
                items[item_type] = items.get(item_type, 0) + 1

        result[namespace_path] = items

    return _process_and_save_dataframe(result, csv_filename)


def count_items_by_type(data: Dict[str, Any], item_type_key: str) -> Dict[str, int]:
    """
    Count items by their type from nested dictionaries.

    Args:
        data: The data dictionary to process
        item_type_key: The key that identifies the type of the item

    Returns:
        Dictionary with item types as keys and their counts as values
    """
    type_counter = Counter()

    for value in data.values():
        if not isinstance(value, dict):
            continue
            
        # Check if this is a direct item with the type key
        if item_type_key in value:
            type_counter[value[item_type_key]] += 1
        
        # Check nested items
        for subvalue in value.values():
            if isinstance(subvalue, dict) and item_type_key in subvalue:
                type_counter[subvalue[item_type_key]] += 1

    return dict(type_counter)


def parse_auth_methods(data: Dict[str, Any], csv_filename: str) -> pd.DataFrame:
    """
    Parse authentication methods and write the results to a CSV file.

    Args:
        data: A dictionary containing the authentication method data
        csv_filename: The name of the CSV file to write the results to

    Returns:
        DataFrame containing the processed authentication methods data
    """
    return parse_vault_items(data, csv_filename, "auth methods")


def parse_secret_engines(data: Dict[str, Any], csv_filename: str) -> pd.DataFrame:
    """
    Parse secret engines and write the results to a CSV file.

    Args:
        data: A dictionary containing the secret engine data
        csv_filename: The name of the CSV file to write the results to

    Returns:
        DataFrame containing the processed secret engines data
    """
    return parse_vault_items(data, csv_filename, "secret engines")


def _process_and_save_dataframe(data: Dict[str, Dict[str, Any]],
                                csv_filename: str) -> pd.DataFrame:
    """
    Convert dictionary data to DataFrame, process numerical columns, and save to CSV.

    Args:
        data: Dictionary data to convert
        csv_filename: CSV file path to save the DataFrame

    Returns:
        The processed DataFrame
    """
    df = pd.DataFrame.from_dict(data, orient='index')

    # Convert count columns to integers
    for column in df.columns[2:]:
        df[column] = df[column].fillna(0)
        df[column] = df[column].astype(int)

    df.to_csv(csv_filename, index=False)
    logging.debug(f"Records processed: {len(df)}")
    logging.debug(f"Sample data:\n{df.head(3)}")
    return df


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Object containing parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Process Vault cluster data to generate summary CSV files"
    )
    parser.add_argument(
        "--cluster-id",
        default="vault-cluster",
        help="Vault cluster ID"
    )
    parser.add_argument(
        "--date",
        default="20240726",
        help="Date stamp for the input files (YYYYMMDD)"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output files"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level"
    )
    return parser.parse_args()


def main() -> None:
    """
    Main function to process Vault cluster data.
    """
    args = parse_args()
    logger = setup_logger(args.log_level)

    # Setup file paths
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    cluster_id = args.cluster_id
    date_stamp = args.date

    auth_methods_filename = f"{cluster_id}-auth-methods-{date_stamp}.json"
    namespaces_filename = f"{cluster_id}-namespaces-{date_stamp}.json"
    secret_engines_filename = f"{cluster_id}-secrets-engines-{date_stamp}.json"

    output_namespaces = output_dir / f"summary-namespaces-{date_stamp}.csv"
    output_auth_methods = output_dir / f"summary-auth-methods-{date_stamp}.csv"
    output_secret_engines = output_dir / f"summary-secret-engines-{date_stamp}.csv"

    try:
        logger.info(f"Processing data for cluster {cluster_id} from {date_stamp}")

        auth_methods = load_json_data(auth_methods_filename)
        namespaces = load_json_data(namespaces_filename)
        secret_engines = load_json_data(secret_engines_filename)

        parse_namespaces(namespaces, str(output_namespaces))
        parse_auth_methods(auth_methods, str(output_auth_methods))
        parse_secret_engines(secret_engines, str(output_secret_engines))

        logger.info("Data processing completed successfully")
    except Exception as e:
        logger.error(f"Error processing data: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()