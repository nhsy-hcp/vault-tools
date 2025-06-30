
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd
from src.common.vault_client import VaultClient
from src.common.file_utils import write_csv, write_json, FileProcessingError

logger = logging.getLogger(__name__)

def get_entity_export_data(client: VaultClient, start_date: str, end_date: str) -> List[Dict[str, Any]]:
    start_rfc3339 = f"{start_date}T00:00:00Z"
    end_rfc3339 = f"{end_date}T23:59:59Z"
    params = {
        'start_time': start_rfc3339,
        'end_time': end_rfc3339,
        'format': 'json'
    }
    
    logger.info(f"Fetching entity export data from {start_date} to {end_date}")
    return client.get("sys/internal/counters/activity/export", params=params)

def process_entity_export_data(data: List[Dict[str, Any]], cluster_name: str, output_dir: str = "outputs") -> Optional[pd.DataFrame]:
    if not data:
        logger.warning("No entity data to process")
        return None

    df = pd.DataFrame(data)
    if 'client_type' not in df.columns:
        logger.error("Column 'client_type' not found in data")
        return None

    df['entity_type'] = df['client_type']
    
    # Convert root namespace path to "root/" when namespace_id is "root"
    if 'namespace_id' in df.columns and 'namespace_path' in df.columns:
        mask = (df['namespace_id'] == 'root') & (df['namespace_path'] == '')
        df.loc[mask, 'namespace_path'] = 'root/'
    
    date_str = datetime.now().strftime("%Y%m%d")
    
    try:
        write_json(f"{output_dir}/{cluster_name}-entity-export-{date_str}.json", data)
        # Convert numeric columns to int to avoid float output in CSV
        numeric_columns = df.select_dtypes(include=['float64']).columns
        df[numeric_columns] = df[numeric_columns].astype('int64')
        write_csv(f"{output_dir}/{cluster_name}-entity-export-{date_str}.csv", df.to_dict('records'), df.columns.tolist())
    except FileProcessingError as e:
        logger.error(f"Failed to write entity export reports: {e}")
        return None
        
    return df

def run_entity_export(client: VaultClient, start_date: str, end_date: str, cluster_name: str, data: Optional[List[Dict[str, Any]]] = None, output_dir: str = "outputs"):
    if data is None:
        data = get_entity_export_data(client, start_date, end_date)
    
    process_entity_export_data(data, cluster_name, output_dir)
