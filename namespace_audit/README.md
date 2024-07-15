# vault namespace audit

## Description
The [main.py](main.py) python script uses multithreaded queues to traverse all namespaces in a vault cluster and audit the resources below in each namespace for analysis.
- namespaces
- auth methods
- secrets engines

Performance is greatly improved with concurrency, an example large vault cluster with 6K namespaces and 85ms round trip ping latency, took the following time to audit with rate limiting disabled:
- 1 worker thread: 30m:52s
- 4 worker threads: 7m:48s
- 16 worker threads: 3m:55s

## Pre-requisites
- jq (optional)
- python 3.8 or later

Install python hvac library dependency with the following command:
```shell
pip install -r requirements.txt
```

### Optional
Create a policy and token for the script to use with the following commands:
```shell
vault policy write vault-namespace-audit ./vault-namespace-audit-policy.hcl
vault token create -policy=vault-namespace-audit -period=1h -orphan -field=token
```
Please note the ACL policy [vault-namespace-audit-policy.hcl](vault-namespace-audit-policy.hcl) supports upto 5 levels of nested namespaces and will need editing if more levels are required.

## Usage
Export environment variables for `VAULT_ADDR` and `VAULT_TOKEN`. Then run the script with the following command:

```shell
usage: main.py [-h] [-d] [--fast] [-n NAMESPACE]

Audit vault cluster namespaces

options:
  -h, --help            show this help message and exit
  -d, --debug           Print the debug output
  --fast                Disable rate limiting
  -n NAMESPACE, --namespace NAMESPACE
                        namespace path to audit (default: root)
```

## Outputs
JSON output files will be created with the following filename formats:
- namespaces-CLUSTER_ID-YYYYMMDD.json
- auth-methods-CLUSTER_ID-YYYYMMDD.json
- secrets-engines-CLUSTER_ID-YYYYMMDD.json

The JSON output files can be queried with `jq`, examples below.

List namespaces
```shell
jq '.[].data.keys' namespaces-vault-cluster-20240710.json
```

Count namespaces
```shell
jq '.[].data.keys | length' namespaces-vault-cluster-20240710.json
```

## Customizations
Rate limit is enabled by default to prevent the vault cluster from being overwhelmed with requests. This can be disabled with the `--fast` flag.

The following variables can be amended to adjust the script behaviour:
- WORKER_THREADS variable in [main.py](main.py) to increase or decrease the number of threads used by the script.
- RATE_LIMIT_BATCH_SIZE variable in [main.py](main.py) to increase or decrease the number of namespaces processed in each batch.
- RATE_LIMIT_SLEEP_SECONDS variable in [main.py](main.py) to increase or decrease the sleep time between batches.

## Known Issues
- If the TTL of the vault FQDN is too low, e.g. 30 seconds, the script may fail occasionally with the following error:
```
requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='vault.example.com', port=8200): Read timed out. (read timeout=3)
```
  This can be resolved by increasing the TTL of the vault FQDN.
  
## To Do
- [ ] Improve thread exception handling
- [ ] Add support for ACL policies
- [ ] Add support for auth roles
- [ ] Add support for EGP / RGP sentinel policies
