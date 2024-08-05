# vault namespace audit

## Description
The [main.py](main.py) python script uses multithreaded queues to traverse all namespaces in a vault cluster and audit the resources below in each namespace for analysis.
- namespaces
- auth methods
- secrets engines

Performance is greatly improved with concurrency, an example large vault cluster with 7K namespaces and 85ms round trip ping latency, took the following time to audit with rate limiting disabled:
- 1 worker thread: 1h:13m
- 4 worker threads: 15m
- 8 worker threads: 6m
- 16 worker threads: 3m

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
vault token create -policy=vault-namespace-audit -period=2h -orphan -field=token
```
Please note the ACL policy [vault-namespace-audit-policy.hcl](vault-namespace-audit-policy.hcl) supports upto 5 levels of nested namespaces and will need editing if more levels are required.

## Usage
Export environment variables for `VAULT_ADDR` and `VAULT_TOKEN`.

Check Vault cluster status and connectivity using the following commands:
```shell
vault status
vault token lookup
````

Then run the script with the following command:
```shell
usage: main.py [-h] [-d] [--fast] [-n NAMESPACE]

Audit vault cluster namespaces

options:
  -h, --help            show this help message and exit
  -d, --debug           Print the debug output
  --fast                Disable rate limiting
  -n NAMESPACE, --namespace NAMESPACE
                        namespace path to audit (default: "")
  -w WORKERS, --workers WORKERS
                        workers threads (default: 4)
```

If TLS is enabled with a self-signed certificate, the following environment variable can be set to disable certificate verification:
```shell
export VAULT_SKIP_VERIFY=true
```
## Outputs
Summary CSV out files will be created with the following filename formats:
- vault-cluster-CLUSTER_ID-summary-namespaces-YYYYMMDD.csv
- vault-cluster-CLUSTER_ID-summary--auth-methods-YYYYMMDD.csv
- vault-cluster-CLUSTER_ID-summary--secrets-engines-YYYYMMDD.csv

JSON output files will be created with the following filename formats:
- vault-cluster-CLUSTER_ID-namespaces-YYYYMMDD.json
- vault-cluster-CLUSTER_ID-auth-methods-YYYYMMDD.json
- vault-cluster-CLUSTER_ID-secrets-engines-YYYYMMDD.json

The JSON output files can be queried with `jq`, examples below.

List namespaces
```shell
jq '.' vault-cluster-12345-namespaces-20240726.json
```

Count namespaces
```shell
jq '. | length' vault-cluster-12345-namespaces-20240726.json
```

## Customizations
Rate limit is enabled by default to prevent the vault cluster from being overwhelmed with requests. This can be disabled with the `--fast` flag.

The following variables can be amended to adjust the script behaviour:
- WORKER_THREADS variable in [main.py](main.py) to increase or decrease the number of threads used by the script.
- RATE_LIMIT_BATCH_SIZE variable in [main.py](main.py) to increase or decrease the number of namespaces processed in each batch.
- RATE_LIMIT_SLEEP_SECONDS variable in [main.py](main.py) to increase or decrease the sleep time between batches.

## Known Issues
- If the DNS host record TTL of the vault FQDN is too low, e.g. 30 seconds, the script may fail occasionally with the following error:
```
requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='vault.example.com', port=8200): Read timed out. (read timeout=3)
```
  This can be resolved by increasing the TTL of the vault FQDN.
  
## To Do
- [ ] Add support for ACL policies
- [ ] Add support for auth roles
- [ ] Add support for EGP / RGP sentinel policies
