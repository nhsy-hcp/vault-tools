# Refactoring and Merging `namespace_audit` and `activity_export`

This document outlines a strategy for refactoring the `namespace_audit` and `activity_export` tools into a single, unified, and maintainable Python application.

## 1. Analysis of Current Structure

Currently, the repository contains two separate and disconnected tools: `namespace_audit` and `activity_export`.

**Problems:**

*   **Code Duplication:** Both tools likely have duplicated code for interacting with the HashiCorp Vault API, handling configuration, and writing output files.
*   **Dependency Management:** Each tool has its own `requirements.txt`, which can lead to conflicting dependencies and makes managing the environment complex.
*   **Inconsistent Structure:** The tools have grown organically, resulting in a cluttered directory structure with many backup files, old scripts (`main-old.py`, `summary.py.bak2`), and generated data files mixed with source code.
*   **Poor User Experience:** A user needs to navigate into specific folders and understand different command invocations for each tool.
*   **Scalability:** Adding new features is difficult without further cluttering the repository and duplicating more code.

## 2. Proposed Refactoring Strategy

The goal is to create a single, command-line-driven tool that consolidates the existing features (`namespace_audit`, `activity_export`, `entity_export`) and establishes a clean, scalable architecture.

**Key Principles:**

*   **Single Entry Point:** Create a main `main.py` that uses a command-line argument parser (like `argparse` or `click`) to allow the user to select the desired operation (e.g., `vault-tool namespace-audit`, `vault-tool activity-export`).
*   **Separation of Concerns:** Isolate distinct functionalities into their own modules and files.
*   **Shared Code:** Consolidate common functionalities, such as Vault API communication and data processing (CSV/JSON conversion), into a shared `common` or `utils` module.
*   **Standard Python Project Structure:** Adopt a standard project layout with a `src` directory for source code, a `tests` directory for tests, and a dedicated `output` directory for generated files.
*   **Unified Dependency Management:** Merge all dependencies into a single, top-level `requirements.txt` file.

## 3. Proposed Folder Structure

Here is the proposed folder structure for the new, unified tool.

```
/vault-tools/
├── .gitignore
├── README.md               # Updated README for the unified tool
├── requirements.txt          # Single file for all Python dependencies
├── pyproject.toml            # Consolidated project configuration
├── main.py                   # CLI entry point (e.g., using argparse or click)
│
├── src/
│   ├── __init__.py
│   │
│   ├── common/
│   │   ├── __init__.py
│   │   ├── vault_client.py   # Centralized client for all Vault API interactions
│   │   └── file_utils.py     # Helper functions for writing CSV, JSON, etc.
│   │
│   ├── namespace_audit/
│   │   ├── __init__.py
│   │   └── main.py           # Core logic for the namespace audit feature
│   │
│   ├── activity_export/
│   │   ├── __init__.py
│   │   └── main.py           # Core logic for the activity export feature
│   │
│   └── entity_export/
│       ├── __init__.py
│       └── main.py           # Core logic for the entity export feature
│
├── tests/
│   ├── __init__.py
│   ├── common/
│   │   ├── test_vault_client.py
│   │   └── test_file_utils.py
│   │
│   ├── namespace_audit/
│   │   └── test_main.py
│   │
│   ├── activity_export/
│   │   └── test_main.py
│   │
│   └── entity_export/
│       └── test_main.py
│
└── output/                   # All generated reports (CSV, JSON) will be saved here
    └── .gitkeep              # Ensures the directory is tracked by git
```

## 4. Implementation Steps

1.  **Create New Structure:** Create the new directories (`src`, `tests`, `output`, etc.). **[COMPLETE]**
2.  **Consolidate Dependencies:** Merge `namespace_audit/requirements.txt` and `activity_export/requirements.txt` into the root `requirements.txt`. **[COMPLETE]**
3.  **Migrate Shared Code:** Identify and move common code (like Vault API calls) into `src/common/`. **[COMPLETE]**
4.  **Migrate Features:**
    *   Move the logic from `namespace_audit/main.py` and `summary.py` into `src/namespace_audit/main.py`.
    *   Move the logic from `activity_export/main.py` into `src/activity_export/main.py` and `src/entity_export/main.py`.
    *   Refactor each feature to use the shared `common` modules. **[COMPLETE]**
5.  **Build CLI:** Implement the main CLI in `main.py` to call the respective feature modules based on user input. **[COMPLETE]**
6.  **Migrate Tests:** Move existing tests to the new `tests/` directory, mirroring the `src` structure, and update them to reflect the new code organization. **[COMPLETE]**
7.  **Cleanup:** Once the refactoring is complete and tested, the old `namespace_audit` and `activity_export` directories can be safely renamed with '-old' suffix. **[COMPLETE]**
8.  **GHA:** Update Gihub Actions **[COMPLETE]**
9.  **Update Documentation:** Update the main `README.md` to document the new tool's installation, configuration, and usage. **[COMPLETE]**
10.  **Update Documentation:** Generate the main `GEMINI.md`. **[COMPLETE]**

