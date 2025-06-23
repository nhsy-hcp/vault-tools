# Vault Namespace Audit Tool

## Project Overview
This is a defensive security tool for auditing HashiCorp Vault clusters. It analyzes namespaces, authentication methods, and secret engines across an entire Vault deployment.

## Project Structure
- `main.py` - Multi-threaded Vault auditing tool (main entry point)
- `summary.py` - Data processing and CSV generation module
- `tests/` - Test files (backing up original tests)

## Key Files

### main.py
- **Purpose**: Main auditing application with multi-threading support
- **Key Classes**:
  - `VaultAuditor` - Main audit orchestrator
  - `AuditConfig` - Configuration dataclass
  - `AuditStats` - Thread-safe statistics tracking (fixed thread safety issues)
  - `AuditData` - Container for audit results
- **Environment Variables Required**:
  - `VAULT_ADDR` - Vault server address
  - `VAULT_TOKEN` - Authentication token
  - `VAULT_SKIP_VERIFY` - Skip TLS verification (optional)

### summary.py
- **Purpose**: Data processing and CSV report generation
- **Key Functions**:
  - `parse_vault_items()` - Generic parser for auth methods and secret engines
  - `parse_namespaces()` - Namespace-specific parsing
  - `extract_level_1_namespace()` - Utility for namespace path operations
  - `load_json_data()` - Enhanced JSON loading with validation

## Recent Improvements (2025-06-23)
1. **Critical Fix**: Fixed thread safety issues in `AuditStats` counters using proper locks
2. **Performance**: Optimized `count_items_by_type` using `collections.Counter`
3. **Code Quality**: Consolidated duplicate parsing logic into generic functions
4. **Optimization**: Added conditional checks for debug logging in hot paths
5. **Validation**: Enhanced input validation and error handling throughout

## Usage Examples
```bash
# Basic audit of entire cluster
python main.py

# Audit specific namespace with debug logging
python main.py -n "team-a/" -d

# Fast audit with multiple workers
python main.py -w 8 --fast

# Generate summary reports from existing data
python summary.py --cluster-id vault-cluster-620f0fe0 --date 20250623
```

## Output Files
- `{cluster-id}-namespaces-{date}.json` - Raw namespace data
- `{cluster-id}-auth-methods-{date}.json` - Raw auth method data  
- `{cluster-id}-secrets-engines-{date}.json` - Raw secret engine data
- `{cluster-id}-summary-*-{date}.csv` - Processed CSV reports

## Dependencies
- `hvac` - HashiCorp Vault client
- `pandas` - Data processing
- `urllib3` - HTTP client (for SSL warning suppression)

## Testing
- Run tests using standard Python testing frameworks
- Test files are backed up in `tests/` directory

## Security Notes
- This is a **defensive security tool** for auditing and analysis only
- Never logs or exposes sensitive Vault tokens or secrets
- Follows security best practices for credential handling
- Supports TLS verification (can be disabled for self-signed certs)

## Performance Considerations
- Multi-threaded design for large Vault clusters
- Rate limiting to avoid overwhelming Vault API
- Memory efficient processing with streaming support considerations
- Optimized logging to reduce performance impact

## Configuration
- Uses environment variables for sensitive data
- Command-line arguments for operational parameters
- Configurable timeouts, thread counts, and rate limiting