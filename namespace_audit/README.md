# vault namespace audit

## Description
The python script uses multi-threaded queues to traverse all namespaces in a vault cluster and audit the auth methods and secrets engines in each namespace. The script will output the results to JSON files.

## Pre-requisites
- jq
- python 3.x

vault policy write vault-namespace-audit ./vault-namespace-audit-policy.hcl
vault token create -policy=vault-namespace-audit -period=1h -orphan -field=token

```hcl 


Vault ACL Policy required for the script to run:
```hcl

```

Install python hvac library with the following command:
```shell
pip install -r requirements.txt
```

## Usage
Export environment variables for `VAULT_ADDR` and `VAULT_TOKEN`. Then run the script with the following command:

```shell
usage: main.py [-h] [-d | --debug | --no-debug] [-n NAMESPACE]

Audit vault cluster namespaces

options:
  -h, --help            show this help message and exit
  -d, --debug, --no-debug
                        Print the debug output
  -n NAMESPACE, --namespace NAMESPACE
                        namespace path to audit (default: root)
```

## Output
JSON output files will be created with the following filename format:
- namespaces-YYYYMMDD.json
- auth-methods-YYYYMMDD.json
- secrets-engines-YYYYMMDD.json

Query the results with `jq`, examples below.

```shell
cat namespaces-20240710.json| jq '."/".data.key_info'
```