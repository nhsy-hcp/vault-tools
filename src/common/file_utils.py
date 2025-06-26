
import csv
import json
import logging
import os
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class FileProcessingError(Exception):
    """Custom exception for file processing errors."""
    pass

def write_csv(file_path: str, data: List[Dict[str, Any]], headers: List[str] = None):
    """Write data to a CSV file from a list of dictionaries."""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        logger.debug(f"Writing {len(data)} rows to {file_path}")
        with open(file_path, 'w', newline='') as csvfile:
            if not data and not headers:
                return # Nothing to write

            fieldnames = headers if headers else list(data[0].keys())
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(data)
        logger.info(f"CSV report written to {file_path}")
    except IOError as e:
        logger.error(f"Error writing CSV file {file_path}: {e}")
        raise FileProcessingError(f"Error writing CSV file {file_path}") from e

def write_json(file_path: str, data: Dict[str, Any]):
    """Write data to a JSON file."""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        logger.debug(f"Writing JSON data to {file_path}")
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"JSON data saved to {file_path}")
    except IOError as e:
        logger.error(f"Failed to write {file_path}: {e}")
        raise FileProcessingError(f"Failed to write {file_path}: {e}") from e

def read_json(file_path: str) -> Dict[str, Any]:
    """Read data from a JSON file."""
    try:
        logger.debug(f"Reading JSON data from {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to read or parse {file_path}: {e}")
        raise FileProcessingError(f"Failed to read or parse {file_path}") from e
