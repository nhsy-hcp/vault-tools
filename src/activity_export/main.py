
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from src.common.vault_client import VaultClient, VaultAPIError
from src.common.file_utils import write_csv, write_json, FileProcessingError

logger = logging.getLogger(__name__)

def get_activity_data(client: VaultClient, start_date: str, end_date: str) -> Dict[str, Any]:
    path = "sys/internal/counters/activity"
    params = {
        'start_time': f"{start_date}T00:00:00Z",
        'end_time': f"{end_date}T00:00:00Z"
    }
    
    logger.info(f"Fetching activity data from {start_date} to {end_date}")
    try:
        response = client.get(path, params=params)
        return response.get('data', {})
    except VaultAPIError as e:
        logger.error(f"Vault API request failed: {e}")
        raise

def process_activity_data(data: Dict[str, Any], cluster_name: str, output_dir: str = "outputs"):
    date_str = datetime.now().strftime("%Y%m%d")

    # Process namespaces and mounts
    namespaces_data = []
    mounts_data = []
    for namespace in data.get("by_namespace", []):
        ns_id = namespace.get("namespace_id", "")
        ns_path = namespace.get("namespace_path", "")
        # Convert root namespace path to "root/" when namespace_id is "root"
        if ns_id == "root" and ns_path == "":
            ns_path = "root/"
        ns_counts = namespace.get("counts", {})
        namespaces_data.append({
            'namespace_id': ns_id,
            'namespace_path': ns_path,
            'mounts': len(namespace.get("mounts", [])),
            'clients': ns_counts.get("clients", 0),
            'entity_clients': ns_counts.get("entity_clients", 0),
            'non_entity_clients': ns_counts.get("non_entity_clients", 0)
        })
        for mount in namespace.get("mounts", []):
            mount_counts = mount.get("counts", {})
            mounts_data.append({
                'namespace_id': ns_id,
                'namespace_path': ns_path,
                'mount_path': mount.get("mount_path", ""),
                'clients': mount_counts.get("clients", 0),
                'entity_clients': mount_counts.get("entity_clients", 0),
                'non_entity_clients': mount_counts.get("non_entity_clients", 0)
            })

    # Write reports
    try:
        logger.debug(f"Writing activity JSON with data for {len(data.get('by_namespace', []))} namespaces")
        write_json(f"{output_dir}/{cluster_name}-activity-{date_str}.json", data)
        
        logger.debug(f"Writing activity namespaces CSV with {len(namespaces_data)} namespace entries")
        write_csv(f"{output_dir}/{cluster_name}-activity-namespaces-{date_str}.csv", namespaces_data)
        
        logger.debug(f"Writing activity mounts CSV with {len(mounts_data)} mount entries")
        write_csv(f"{output_dir}/{cluster_name}-activity-mounts-{date_str}.csv", mounts_data)
    except FileProcessingError as e:
        logger.error(f"Error writing activity reports: {e}")

    return namespaces_data, mounts_data

def run_activity_export(client: VaultClient, start_date: str, end_date: str, cluster_name: str, data: Optional[Dict[str, Any]] = None, output_dir: str = "outputs"):
    if data is None:
        data = get_activity_data(client, start_date, end_date)
    
    return process_activity_data(data, cluster_name, output_dir)
