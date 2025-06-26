# Vault Tools - Gemini Integration

This project, `vault-tools`, is designed to provide command-line utilities for interacting with HashiCorp Vault. It has been refactored and unified to offer a streamlined experience for auditing namespaces, exporting activity logs, and exporting entities from Vault.

## Purpose of `GEMINI.md`

This `GEMINI.md` file serves as a dedicated document for the Gemini model, providing context and specific instructions relevant to its interaction with this project. It outlines:

- **Project Overview:** A concise summary of what `vault-tools` does.
- **Key Areas for Gemini:** Highlights specific modules or functionalities where Gemini's assistance might be most valuable (e.g., `src/common/vault_client.py` for Vault API interactions, `src/namespace_audit/main.py` for audit logic).
- **Development Guidelines:** Any project-specific conventions, coding styles, or testing procedures that Gemini should adhere to when making modifications or generating new code.
- **Troubleshooting/Debugging:** Common issues and their resolutions, or pointers to logging mechanisms that Gemini can use for debugging.

## Project Structure (Relevant to Gemini)

```
/vault-tools/
├── main.py                   # CLI entry point
│
├── src/
│   ├── common/
│   │   ├── vault_client.py   # Centralized Vault API client
│   │   └── file_utils.py     # Helper functions for file operations
│   │
│   ├── namespace_audit/
│   │   └── main.py           # Namespace audit logic
│   │
│   ├── activity_export/
│   │   └── main.py           # Activity export logic
│   │
│   └── entity_export/
│       └── main.py           # Entity export logic
│
├── tests/                    # Unit and integration tests
│
├── inputs/                   # Input files for various scripts
└── outputs/                   # Generated reports and data
```

## Gemini-Specific Instructions

- When modifying Vault API interactions, always refer to `src/common/vault_client.py`.
- For new features, ensure they integrate seamlessly with the `main.py` CLI structure.
- Prioritize the use of existing `file_utils.py` for any file writing operations.
- When adding new tests, follow the existing structure in the `tests/` directory.
- If encountering issues with Vault connectivity, check environment variables and `vault_client.py`.
