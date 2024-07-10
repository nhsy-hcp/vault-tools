import argparse
from datetime import datetime
import json
import threading
import os
import queue
import hvac  # Import Hashicorp Vault library

DEBUG = False

# Define Vault connection parameters from environment variables
VAULT_ADDR = os.environ.get('VAULT_ADDR')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN')

# Define HVAC client parameters
HVAC_TIMEOUT = 3

# Define number of worker threads
WORKER_THREADS = 4


def traverse_namespace(namespace_path, path_queue):
    """
    Traverses a given Vault namespace and adds child paths to the queue.
    Args:
    namespace_path: Path of the namespace to traverse.
    path_queue: Queue object to store child paths.
    """
    try:
        print("Processing namespace: ", namespace_path)
        vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN, namespace=namespace_path, timeout=HVAC_TIMEOUT)
        namespaces = vault_client.sys.list_namespaces()

        if namespace_path == "":
            key_path = "/"
        else:
            key_path = namespace_path

        # Add namespaces, auth methods and secrets engines data to global dictionary
        global_namespaces[key_path] = namespaces
        global_auth_methods[key_path] = vault_client.sys.list_auth_methods()
        global_secret_engines[key_path] = vault_client.sys.list_mounted_secrets_engines()

        if DEBUG:
            print(json.dumps(namespaces, indent=2))

        # Add child namespace paths to the queue
        if namespaces and "data" in namespaces and "key_info" in namespaces["data"]:
            for child_namespace in namespaces["data"]["key_info"]:
                child_namespace_path = f"{namespace_path}{child_namespace}"
                path_queue.put(child_namespace_path)
    except hvac.exceptions.InvalidPath as e:  # Ignore if no child namespaces
        pass
    except hvac.exceptions.VaultError as e:
        print(f"Error traversing path {namespace_path}: {e}")


def write_to_file():
    namespace_json_filename = 'namespaces-{}.json'.format(datetime.now().strftime("%Y%m%d"))
    auth_json_filename = 'auth-methods-{}.json'.format(datetime.now().strftime("%Y%m%d"))
    secrets_json_filename = 'secrets-engines-{}.json'.format(datetime.now().strftime("%Y%m%d"))

    with open(namespace_json_filename, 'w') as jsonfile:
        json.dump(global_namespaces, jsonfile, indent=2)

    with open(auth_json_filename, 'w') as jsonfile:
        json.dump(global_auth_methods, jsonfile, indent=2)

    with open(secrets_json_filename, 'w') as jsonfile:
        json.dump(global_secret_engines, jsonfile, indent=2)


def worker(path_queue):
    """
    Worker thread that retrieves paths from the queue and traverses them.
    """
    while True:
        namespace_path = path_queue.get()
        if namespace_path is None:
            break
        traverse_namespace(namespace_path, path_queue)
        path_queue.task_done()


def main():
    """
    Main function that initializes Vault client, creates threads, and starts traversal.
    """

    # Check vault connection and exit if not authenticated
    vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    if not vault_client.is_authenticated():
        print("Vault client is not authenticated. Exiting.")
        exit(1)

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

    # Shutdown worker threads
    for _ in range(WORKER_THREADS):
        path_queue.put(None)

    for worker_thread in workers:
        worker_thread.join()

    if DEBUG:
        print(json.dumps(global_namespaces, indent=2))
        print(json.dumps(global_auth_methods, indent=2))
        print(json.dumps(global_secret_engines, indent=2))

    write_to_file()

    print("\nNamespace traversal complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Audit vault cluster namespaces')
    parser.add_argument('-d', '--debug', default=False, action=argparse.BooleanOptionalAction,
                        help='Print the debug output')
    parser.add_argument('-n', '--namespace', type=str, help='namespace path to audit (default: root)')

    args = parser.parse_args()

    if args.debug:
        DEBUG = True

    if args.namespace:
        NAMESPACE_PATH = args.namespace
        # Add trailing slash to namespace
        if not NAMESPACE_PATH.endswith("/"):
            NAMESPACE_PATH += "/"
    else:
        NAMESPACE_PATH = ""

    # namespace dictionary to store output
    global_namespaces = {}

    # auth dictionary to store output
    global_auth_methods = {}

    # auth dictionary to store output
    global_secret_engines = {}

    main()
