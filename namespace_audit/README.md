w# Vault Namespace Audit Tool

## Overview
A defensive security tool for comprehensive auditing of HashiCorp Vault clusters. This multi-threaded application analyzes namespaces, authentication methods, and secret engines across an entire Vault deployment to provide detailed security insights.

### What It Audits
- **Namespaces** - Complete namespace hierarchy and structure
- **Authentication Methods** - All auth backends and their configurations
- **Secret Engines** - All secret stores and their types

### Performance Benchmarks
Multi-threading provides significant performance improvements. Example results from a large Vault cluster (7K namespaces, 85ms latency):

| Worker Threads | Audit Time |
|----------------|------------|
| 1 thread       | 1h 13m     |
| 4 threads      | 15m        |
| 8 threads      | 6m         |
| 16 threads     | 3m         |

## Prerequisites

### Required
- Python 3.8 or later
- HashiCorp Vault access

### Optional
- `jq` for JSON output analysis

### Installation
```bash
pip install -r requirements.txt
```

## Configuration

### Environment Variables
```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="your-vault-token"
export VAULT_SKIP_VERIFY=true  # Optional: Skip TLS verification for self-signed certs
```

### Vault Policy Setup (Optional)
Create a dedicated policy and token for auditing:

```bash
vault policy write vault-namespace-audit ./vault-namespace-audit-policy.hcl
vault token create -policy=vault-namespace-audit -period=2h -orphan -field=token
```

**Note:** The included policy supports up to 5 levels of nested namespaces. Edit the policy file if deeper nesting is required.

## Usage

### Verify Connectivity
```bash
vault status
vault token lookup
```

### Basic Usage
```bash
# Audit entire cluster
python main.py

# Audit specific namespace with debug logging
python main.py -n "team-a/" -d

# Fast audit with 8 workers (no rate limiting)
python main.py -w 8 --fast

# Generate summary reports from existing data
python summary.py --cluster-id vault-cluster-620f0fe0 --date 20250623
```

### Command Line Options
```
usage: main.py [-h] [-d] [--fast] [-n NAMESPACE] [-w WORKERS]

options:
  -h, --help            Show help message
  -d, --debug           Enable debug output
  --fast                Disable rate limiting
  -n NAMESPACE          Namespace path to audit (default: root)
  -w WORKERS            Number of worker threads (default: 4)
```

## Output Files

### CSV Summary Reports
- `vault-cluster-{CLUSTER_ID}-summary-namespaces-{YYYYMMDD}.csv`
- `vault-cluster-{CLUSTER_ID}-summary-auth-methods-{YYYYMMDD}.csv`
- `vault-cluster-{CLUSTER_ID}-summary-secrets-engines-{YYYYMMDD}.csv`

### JSON Raw Data
- `vault-cluster-{CLUSTER_ID}-namespaces-{YYYYMMDD}.json`
- `vault-cluster-{CLUSTER_ID}-auth-methods-{YYYYMMDD}.json`
- `vault-cluster-{CLUSTER_ID}-secrets-engines-{YYYYMMDD}.json`

### Analyzing Output with jq
```bash
# List all namespaces
jq '.' vault-cluster-12345-namespaces-20240726.json

# Count total namespaces
jq '. | length' vault-cluster-12345-namespaces-20240726.json

# Find specific auth method types
jq '.[] | select(.type == "ldap")' vault-cluster-12345-auth-methods-20240726.json
```

## Configuration & Tuning

### Rate Limiting
Rate limiting is enabled by default to prevent overwhelming the Vault cluster. Use `--fast` to disable for faster audits when the cluster can handle higher load.

### Advanced Configuration
These settings can be modified in the source code if needed:
- `WORKER_THREADS` - Concurrent worker threads
- `RATE_LIMIT_BATCH_SIZE` - Namespaces processed per batch
- `RATE_LIMIT_SLEEP_SECONDS` - Delay between batches

## Security Considerations

- **Defensive Tool**: Designed exclusively for security auditing and analysis
- **Credential Safety**: Never logs or exposes sensitive tokens or secrets
- **Minimal Permissions**: Uses read-only Vault operations
- **TLS Support**: Supports proper TLS verification (can be disabled for self-signed certificates)

## Troubleshooting

### DNS/Network Issues
If experiencing intermittent timeouts:
```
requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='vault.example.com', port=8200): Read timed out.
```

**Solution:** Increase the DNS TTL for the Vault FQDN (recommended: >300 seconds)

### Common Issues
- **Authentication failures**: Verify `VAULT_TOKEN` is valid and has necessary permissions
- **TLS errors**: Set `VAULT_SKIP_VERIFY=true` for self-signed certificates
- **Performance issues**: Adjust worker count based on cluster capacity and network latency

