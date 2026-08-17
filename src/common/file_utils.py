import csv
import json
import logging
import os
from collections.abc import Iterable
from typing import Any

from .exceptions import FileProcessingError  # noqa: F401

logger = logging.getLogger(__name__)


def write_csv_stream(file_path: str, rows: Iterable[dict[str, Any]], headers: list[str]):
    """Write rows to a CSV file incrementally.

    Accepts any iterable — including a generator — so a large export can be
    streamed to disk without materialising every row in memory first (F4).
    Because the rows are not inspected up front, ``headers`` is required.

    Args:
        file_path: Destination path.
        rows: Iterable of row dictionaries.
        headers: Column names, written as the header row.

    Raises:
        FileProcessingError: If the file cannot be written.
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        written = 0
        with open(file_path, "w", newline="") as csvfile:
            # restval="" so a row missing a key produces an empty cell rather
            # than raising partway through a partially written file (F1).
            writer = csv.DictWriter(csvfile, fieldnames=headers, restval="")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                written += 1
        logger.info(f"CSV report written to {file_path} ({written} rows)")
    except OSError as e:
        logger.error(f"Error writing CSV file {file_path}: {e}")
        raise FileProcessingError(f"Error writing CSV file {file_path}") from e


def write_csv(file_path: str, data: list[dict[str, Any]], headers: list[str] = None):
    """Write data to a CSV file from a list of dictionaries.

    Thin wrapper over write_csv_stream that derives the header row from the
    first record when one is not supplied.
    """
    if not data and not headers:
        logger.debug(f"No data or headers for {file_path}; nothing written")
        return  # Nothing to write

    fieldnames = headers if headers else list(data[0].keys())
    logger.debug(f"Writing {len(data)} rows to {file_path}")
    write_csv_stream(file_path, data, fieldnames)


def write_json(file_path: str, data: dict[str, Any]):
    """Write data to a JSON file.

    Raises:
        FileProcessingError: If the file cannot be written, or if the data
            contains a value json cannot serialise. The latter used to escape as
            a bare TypeError, bypassing this module's error-wrapping contract
            (F2). Serialisation is deliberately strict here — silently coercing
            unknown types to str() would put unpredictable content in a report.
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        logger.debug(f"Writing JSON data to {file_path}")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"JSON data saved to {file_path}")
    except OSError as e:
        logger.error(f"Failed to write {file_path}: {e}")
        raise FileProcessingError(f"Failed to write {file_path}: {e}") from e
    except TypeError as e:
        logger.error(f"Failed to serialise data for {file_path}: {e}")
        raise FileProcessingError(f"Failed to write {file_path}: data contains a value that cannot be serialised to JSON ({e})") from e


def write_markdown(file_path: str, content: str):
    """Write a rendered markdown document to disk.

    Sibling to write_json/write_csv, and shares their error contract: the caller
    sees only FileProcessingError, never a bare OSError. Content is written
    verbatim — rendering belongs to the caller, this only owns the file.

    Raises:
        FileProcessingError: If the file cannot be written.
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        logger.debug(f"Writing markdown report to {file_path}")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Markdown report written to {file_path}")
    except OSError as e:
        logger.error(f"Failed to write {file_path}: {e}")
        raise FileProcessingError(f"Failed to write {file_path}: {e}") from e


def read_json(file_path: str) -> dict[str, Any]:
    """Read data from a JSON file."""
    try:
        logger.debug(f"Reading JSON data from {file_path}")
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to read or parse {file_path}: {e}")
        raise FileProcessingError(f"Failed to read or parse {file_path}") from e


def read_csv(file_path: str) -> list[dict[str, Any]]:
    """Read data from a CSV file into a list of dictionaries.

    Counterpart to read_json, so the module's read/write API is symmetric (F3).
    All values come back as strings — CSV carries no type information.

    Args:
        file_path: Path to the CSV file.

    Returns:
        One dictionary per data row, keyed by the header row.

    Raises:
        FileProcessingError: If the file cannot be read or parsed.
    """
    try:
        logger.debug(f"Reading CSV data from {file_path}")
        with open(file_path, newline="", encoding="utf-8") as csvfile:
            return list(csv.DictReader(csvfile))
    except (OSError, csv.Error) as e:
        logger.error(f"Failed to read or parse {file_path}: {e}")
        raise FileProcessingError(f"Failed to read or parse {file_path}") from e
