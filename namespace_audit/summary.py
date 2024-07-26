import json
import logging
import pandas as pd


def parse_namespaces(data: dict, csv_filename: str):
    """
    Parses namespaces from the provided data and writes the results to a CSV file.

    Args:
        data (dict): A dictionary containing the namespace data.
        csv_filename (str): The name of the CSV file to write the results to.

    The function processes the input data to create a DataFrame with the namespace path, id,
    and custom metadata. The results are then written to a CSV file.
    """

    logging.info("Parsing namespaces")
    df = pd.DataFrame.from_dict(data, orient='index', columns=['path', 'id', 'custom_metadata'])
    df.to_csv(csv_filename, index=False)
    logging.debug(df.head(3))


def parse_auth_methods(data: dict, csv_filename: str):
    """
    Parses authentication methods from the provided data and writes the results to a CSV file.

    Args:
        data (dict): A dictionary containing the authentication method data.
        csv_filename (str): The name of the CSV file to write the results to.

    The function processes the input data to count the occurrences of each authentication method type
    within each namespace. The results are then written to a CSV file with the namespace path,
    level 1 namespace, and counts of each authentication method type.
    """

    logging.info("Parsing auth methods")
    result = {}
    for key in (data.keys()):
        items = {
            'namespace_path': key,
            'level_1_namespace': key.split('/')[0] + '/'
        }
        # for item in data[key]:
        #     if data[key][item] and 'type' in data[key][item]:
        #         auth_method_type = data[key][item]['type']
        #         if auth_method_type in auth_methods:
        #             items[auth_method_type] += 1
        #         else:
        #             items[auth_method_type] = 1
        #     result[key] = items

        # Find all auth methods and increment the count
        for item in [v for v in data[key].values() if isinstance(v, dict) and 'type' in v]:
            auth_method_type = item['type']
            items[auth_method_type] = items.get(auth_method_type, 0) + 1
        result[key] = items

    df = pd.DataFrame.from_dict(result, orient='index')
    for column in df.columns[2:]:
        df[column] = df[column].fillna(0)
        df[column] = df[column].astype(int)
    df.to_csv(csv_filename, index=False)
    logging.debug(df.head(3))


def parse_secret_engines(data: dict, csv_filename: str):
    """
    Parses secret engines from the provided data and writes the results to a CSV file.

    Args:
        data (dict): A dictionary containing the secret engine data.
        csv_filename (str): The name of the CSV file to write the results to.

    The function processes the input data to count the occurrences of each secret engine type
    within each namespace. The results are then written to a CSV file with the namespace path,
    level 1 namespace, and counts of each secret engine type.
    """

    logging.info("Parsing secret engines")
    result = {}
    for key in (data.keys()):
        items = {
            'namespace_path': key,
            'level_1_namespace': key.split('/')[0] + '/'
        }
        # for item in data[key]:
        #     if isinstance(data[key][item], dict):
        #         for mount_path in data[key][item]:
        #             secret_engine = data[key][item][mount_path]
        #             if isinstance(secret_engine, dict) and "type" in secret_engine:
        #                 secret_engine_type = secret_engine["type"]
        #                 if secret_engine_type in items:
        #                     items[secret_engine_type] += 1
        #                 else:
        #                     items[secret_engine_type] = 1

        # Find all secret engines and increment the count
        for item in [v for v in data[key].values() if isinstance(v, dict)]:
            for secret_engine in item.values():
                if isinstance(secret_engine, dict) and "type" in secret_engine:
                    secret_engine_type = secret_engine["type"]
                    items[secret_engine_type] = items.get(secret_engine_type, 0) + 1
        result[key] = items

    df = pd.DataFrame.from_dict(result, orient='index')

    for column in df.columns[2:]:
        df[column] = df[column].fillna(0)
        df[column] = df[column].astype(int)
    df.to_csv(csv_filename, index=False)
    logging.debug(df.head(3))


def main():
    # Unit test with sample data
    auth_methods_filename = "vault-cluster-edcac415-auth-methods-20240726.json"
    namespaces_filename = "vault-cluster-edcac415-namespaces-20240726.json"
    secret_engines_filename = "vault-cluster-edcac415-secrets-engines-20240726.json"

    with open(auth_methods_filename, 'r') as jsonfile:
        auth_methods = json.load(jsonfile)

    with open(namespaces_filename, 'r') as jsonfile:
        namespaces = json.load(jsonfile)

    with open(secret_engines_filename, 'r') as jsonfile:
        secret_engines = json.load(jsonfile)

    parse_namespaces(namespaces, "summary-namespaces.csv")
    parse_auth_methods(auth_methods, "summary-auth-methods.csv")
    parse_secret_engines(secret_engines, "summary-secret-engines.csv")


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    main()
