import argparse
from datetime import datetime
import hvac  # Import Hashicorp Vault library
import logging
import json
import os
import queue
import threading
import time
import summary

# Define Vault connection parameters from environment variables
VAULT_ADDR = os.environ.get('VAULT_ADDR')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN')

# Define HVAC client parameters
HVAC_TIMEOUT = 3

# Define number of worker threads
WORKER_THREADS = 4

RATE_LIMIT_BATCH_SIZE = 100
RATE_LIMIT_SLEEP_SECONDS = 3
RATE_LIMIT_DISABLE = False

logger = logging.getLogger(__name__)


def traverse_namespace(namespace_path: str, path_queue: str):
    """
    Traverses a given Vault namespace and adds child paths to the queue.
    Args:
    namespace_path: Path of the namespace to traverse.
    path_queue: Queue object to store child paths.
    """

    global global_counter
    global global_error_counter
    global global_namespaces
    global global_auth_methods
    global global_secret_engines

    try:
        if namespace_path == "":
            key_path = "/"
        else:
            key_path = namespace_path

        current_thread = threading.current_thread()
        logging.info(f"{current_thread.name} processing namespace ({global_counter}): {key_path}")

        # Connect to vault and retrieve namespaces
        vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN, namespace=namespace_path, timeout=HVAC_TIMEOUT)

        # Fetch auth methods and secrets engines
        global_auth_methods[key_path] = vault_client.sys.list_auth_methods()
        global_secret_engines[key_path] = vault_client.sys.list_mounted_secrets_engines()
        # Fetch child namespaces, 404 error returned if no child namespaces, so needs to be the last item to process
        namespaces = vault_client.sys.list_namespaces()

        # Add child namespace paths to the queue
        if namespaces and "data" in namespaces and "key_info" in namespaces["data"]:
            for child_namespace in namespaces["data"]["key_info"]:
                child_namespace_path = f"{namespace_path}{child_namespace}"
                path_queue.put(child_namespace_path)
                global_namespaces[child_namespace_path] = namespaces["data"]["key_info"][child_namespace]
    # Ignore path error if no child namespaces
    except hvac.exceptions.InvalidPath:
        pass
    # except hvac.exceptions.VaultError as e:
    except Exception as e:
        logging.exception(f"Error traversing path {namespace_path}: {e}")
        with global_thread_lock:
            global_error_counter += 1


def write_to_file(cluster_name: str):
    auth_json_filename = f'{cluster_name}-auth-methods-{datetime.now().strftime("%Y%m%d")}.json'
    namespace_json_filename = f'{cluster_name}-namespaces-{datetime.now().strftime("%Y%m%d")}.json'
    secret_json_filename = f'{cluster_name}-secrets-engines-{datetime.now().strftime("%Y%m%d")}.json'
    logging.info(f"Writing output to files: {namespace_json_filename}, {auth_json_filename}, {secret_json_filename}")

    with open(namespace_json_filename, 'w') as jsonfile:
        json.dump(global_namespaces, jsonfile, indent=2)

    with open(auth_json_filename, 'w') as jsonfile:
        json.dump(global_auth_methods, jsonfile, indent=2)

    with open(secret_json_filename, 'w') as jsonfile:
        json.dump(global_secret_engines, jsonfile, indent=2)


def summary_report(cluster_name: str):
    auth_csv_filename = f"{cluster_name}-summary-auth-methods-{datetime.now().strftime('%Y%m%d')}.csv"
    namespace_csv_filename = f"{cluster_name}-summary-namespaces-{datetime.now().strftime('%Y%m%d')}.csv"
    secret_csv_filename = f"{cluster_name}-summary-secrets-engines-{datetime.now().strftime('%Y%m%d')}.csv"

    logging.info(f"Writing summary to files: {namespace_csv_filename}, {auth_csv_filename}, {secret_csv_filename}")
    summary.parse_namespaces(global_namespaces, namespace_csv_filename)
    summary.parse_auth_methods(global_auth_methods, auth_csv_filename)
    summary.parse_secret_engines(global_secret_engines, secret_csv_filename)


def worker(path_queue: str):
    """
    Worker thread that retrieves paths from the queue and traverses them.
    """
    global global_counter

    while True:
        namespace_path = path_queue.get()
        if namespace_path is None:
            break

        # Rate limit requests
        with global_thread_lock:
            global_counter += 1
            logging.debug(f"global_counter: {global_counter}, namespace_path: {namespace_path}")

            if not RATE_LIMIT_DISABLE and global_counter % RATE_LIMIT_BATCH_SIZE == 0:
                logging.info(
                    f"Rate limiting - sleep: {RATE_LIMIT_SLEEP_SECONDS} seconds, batch size: {RATE_LIMIT_BATCH_SIZE}")
                time.sleep(RATE_LIMIT_SLEEP_SECONDS)

        try:
            traverse_namespace(namespace_path, path_queue)
        finally:
            path_queue.task_done()


def main():
    """
    Main function that initializes Vault client, creates threads, and starts traversal.
    """

    # Check vault connection and exit if not authenticated
    vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    cluster_info = vault_client.sys.read_health_status(method='GET',
                                                       sealed_code=200, performance_standby_code=200, uninit_code=200)

    # Check HTTP response code 200
    if not isinstance(cluster_info, dict):
        logging.error("Unknown Vault cluster health status. Exiting.")
        logging.error(f"status code: {cluster_info.status_code}")
        logging.error(f"response: {cluster_info.text}")
        exit(1)

    # Check vault cluster initialized, unsealed and authenticated
    if vault_client.sys.is_sealed():
        logging.error("Vault cluster is sealed. Exiting.")
        exit(1)
    elif not vault_client.is_authenticated():
        logging.error("Vault client is not authenticated. Exiting.")
        exit(1)
    elif not vault_client.sys.is_initialized():
        logging.error("Vault cluster is not initialized. Exiting.")
        exit(1)

    logging.info(f"Vault cluster info: {cluster_info}")
    cluster_name = cluster_info['cluster_name']

    # Create a queue to store paths
    path_queue = queue.Queue()
    # Add namespace path to the queue
    path_queue.put(NAMESPACE_PATH)

    # Create worker threads
    workers = []
    for _ in range(WORKER_THREADS):
        worker_thread = threading.Thread(target=worker, args=(path_queue,))
        worker_thread.start()
        workers.append(worker_thread)

    # Wait for all tasks to complete
    path_queue.join()

    # Shutdown worker threads gracefully
    for _ in range(WORKER_THREADS):
        path_queue.put(None)

    for worker_thread in workers:
        worker_thread.join()

    # logging.debug(json.dumps(global_namespaces, indent=2))
    # logging.debug(json.dumps(global_auth_methods, indent=2))
    # logging.debug(json.dumps(global_secret_engines, indent=2))

    write_to_file(cluster_name)
    summary_report(cluster_name)

    logging.info(f"Namespace traversal complete: {global_counter} paths processed, {global_error_counter} errors")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Audit vault cluster namespaces')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Print the debug output')
    parser.add_argument('--fast', action='store_true',
                        help='Disable rate limiting')
    parser.add_argument('-n', '--namespace', type=str, help='namespace path to audit (default: "")')
    parser.add_argument('-w', '--workers', type=int, default=4, help='workers threads (default: 4)')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.fast:
        RATE_LIMIT_DISABLE = True

    if args.namespace:
        NAMESPACE_PATH = args.namespace
        # Add trailing slash to namespace
        if not NAMESPACE_PATH.endswith("/"):
            NAMESPACE_PATH += "/"
    else:
        NAMESPACE_PATH = ""

    if args.workers:
        WORKER_THREADS = args.workers

    # dictionaries to store outputs
    global_namespaces = {}
    global_auth_methods = {}
    global_secret_engines = {}

    # counter to rate limit requests
    global_counter = 0

    # counter to log errors
    global_error_counter = 0

    # thread lock for updating counters
    global_thread_lock = threading.Lock()

    main()
