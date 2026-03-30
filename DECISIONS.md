# Design Decisions

This document records the key architectural and design decisions made in the Databricks Workspace Detection App, the reasoning behind each, and the tradeoffs involved.

---

## 1. Generated Notebooks as Investigation Artifacts

**Decision**: Threat model and user behavior analysis notebooks generate new investigation notebooks in `/generated/` rather than executing detections directly and displaying results inline.

**Context**: When an analyst runs `threat_model_account_takeover.py`, it does not run the 17 detections itself. Instead, it produces a timestamped notebook containing the code for all 17 detections, uploads it to the workspace, and the analyst then opens and runs that notebook.

**Rationale**:
- **Audit trail**: Each investigation produces a durable artifact (`generated/threat_model_account_takeover_20260315_143022`) that can be attached to incident reports, shared with compliance, or reviewed later. If detections ran inline, the results would be lost when the session ends.
- **Reproducibility**: The generated notebook captures the exact time windows, detection versions, and parameters used. Re-running it recreates the same investigation.
- **Analyst workflow**: Investigators can edit the generated notebook mid-investigation (e.g., adjusting a threshold, adding a filter) without modifying the detection library. Each investigation is a standalone working copy.
- **Parallel investigations**: Multiple generated notebooks can run simultaneously with different parameters without interfering with each other or the generator.

**Tradeoff**: This adds an extra step (generate, then open and run) compared to direct execution. The `/generated/` directory can accumulate stale notebooks. The `.gitignore` excludes this directory to prevent committing investigation artifacts.

---

## 2. Detection Code Extraction via Regex Parsing

**Decision**: `parse_detection_file()` downloads each detection notebook from the Databricks workspace, extracts the function body using regex (`@detect.*?# COMMAND -------`), and embeds it as a string in the generated notebook.

**Context**: Generated investigation notebooks need to contain the complete detection function code inline. The system cannot use `%run` to include detections because each detection notebook also has widget setup, display calls, and other non-function code that would execute and interfere.

**Rationale**:
- **Selective extraction**: Only the decorated detection function is extracted, not the widget setup or display cells that surround it in standalone notebooks. This prevents widget conflicts when 17 detections are composed into a single notebook.
- **Self-contained output**: The generated notebook has no runtime dependency on the detection files. It works even if the detection library is later modified.
- **No import system needed**: Databricks notebooks don't support standard Python imports between notebooks. The alternatives are `%run` (which executes everything) or string extraction (which is selective).

**Tradeoff**: Regex-based code extraction is fragile. It depends on detection notebooks following the convention of placing the function between `@detect` and `# COMMAND ----------`. Detections that deviate from this pattern will fail to parse. The YAML metadata extraction (````yaml...```) has the same fragility.

---

## 3. `%run` for Shared Libraries, Not for Detections

**Decision**: Library code (`common.py`, `notebook_generator_base.py`, `threat_model_mappings.py`) is loaded via Databricks `%run` magic commands. Individual detection notebooks are loaded via regex extraction (see Decision 2).

**Context**: Databricks `%run` executes another notebook and injects all its definitions into the calling notebook's namespace. There is no standard Python `import` between Databricks notebooks.

**Rationale**:
- **Libraries are safe to %run**: `common.py`, `notebook_generator_base.py`, and `threat_model_mappings.py` define functions and constants without side effects (except GeoIP enricher initialization in `common.py`, which is guarded by try/except). Running them fully is correct behavior.
- **Detections are not safe to %run**: Each detection notebook contains widget definitions (`dbutils.widgets.text(...)`) and display calls that would execute immediately, creating widget conflicts and displaying stale results if 34 detections were all `%run` into a single notebook.
- **Namespace availability**: After `%run ../../lib/notebook_generator_base`, all shared functions (`discover_detections`, `format_time_range`, `generate_detection_code`, `_sanitize_for_markdown`, etc.) plus their imports (`os`, `io`, `datetime`, `WorkspaceClient`, etc.) are available in the calling notebook's namespace.

**Tradeoff**: IDE tooling cannot resolve `%run` imports, so type checking and autocomplete don't work for shared library functions. The implicit namespace injection can be confusing (e.g., `user_behavior_analysis.py` uses `w`, `io`, `os`, `datetime` without importing them because they come from `%run`).

---

## 4. Two-Tier Time Window System

**Decision**: The system maintains two independent time windows: `binary_time_range_hours` (default 24) for event-based detections and `time_range_days` (default 30) for behavioral detections.

**Context**: Event-based detections look for specific actions (SSO config change, privilege assignment) that are meaningful within a short window. Behavioral detections look for statistical patterns (login frequency anomalies, admin activity spikes) that require a longer baseline.

**Rationale**:
- **24-hour event window**: A configuration change or privilege escalation is an atomic event. Looking back 24 hours covers the recent alert cycle without drowning analysts in historical noise. This aligns with typical SOC shift-based review cadences.
- **30-day behavioral window**: Statistical anomaly detection needs enough data points to establish a baseline. 30 days captures weekly patterns and avoids flagging normal monthly variations. The `spike_in_table_admin_activity` detection, for example, computes per-user average query volumes and flags deviations, which requires sufficient history.
- **Independent configuration**: Analysts can widen the behavioral window (e.g., 90 days for seasonal pattern analysis) without also scanning 90 days of event-based detections, which would be excessive.

**Tradeoff**: The parameter naming still uses `binary_time_range_hours` in the widget interface for backward compatibility, even though the directory was renamed from `binary/` to `event-based/`. Internal variable names were updated to `event_based_*` for clarity.

---

## 5. Event-Based vs. Behavioral Detection Classification

**Decision**: Detections are classified into two categories stored in separate directories: `base/detections/event-based/` (16 detections) and `base/detections/behavioral/` (18 detections).

**Context**: All detections query the same `system.access.audit` table (except `potential_data_movement_sql_queries` which queries `system.query.history`), but they differ fundamentally in analysis approach.

**Rationale**:
- **Event-based** detections filter for specific action patterns (e.g., `service_name == "ssoConfigBackend" AND action_name IN ["create", "update"]`). They have high fidelity because the actions themselves are inherently suspicious or security-relevant. False positives are low. They answer: "Did this specific thing happen?"
- **Behavioral** detections perform aggregation, windowing, and statistical analysis (e.g., computing per-user query volume averages, detecting multi-IP session reuse within time thresholds). They answer: "Is this pattern abnormal?" False positives are higher because normal behavior varies.
- **Operational distinction**: Event-based detections are suitable for automated alerting. Behavioral detections are better suited for periodic threat hunting reviews.

**Tradeoff**: The classification is based on the detection's analysis approach, not its severity. Some event-based detections are low severity (SSO config change by a legitimate admin) while some behavioral detections are high severity (data exfiltration via COPY INTO with explicit credentials). The directory structure groups by analysis type, not by urgency.

---

## 6. YAML Metadata Embedded in Notebook Markdown

**Decision**: Each detection notebook contains its metadata (name, description, severity, MITRE ATT&CK taxonomy, fidelity, false positive guidance) in a YAML block inside a Databricks `%md` markdown cell.

**Context**: The system needs detection metadata for generated notebooks (displaying detection descriptions) and for the manifest (app registry). This metadata could live in separate YAML files, in a database, or embedded in the notebooks.

**Rationale**:
- **Co-location**: The metadata lives next to the code it describes. When a developer modifies a detection's SQL logic, they see and update the description in the same file. External metadata files drift.
- **Self-documenting notebooks**: When an analyst opens a detection notebook in Databricks, the markdown cell renders as formatted documentation above the code. No external docs needed.
- **Machine-readable**: `parse_detection_file()` extracts the YAML programmatically using regex (````yaml...````) for use in generated notebooks and manifest updates.
- **Standard format**: The `dscc` (Databricks Security Content Collection) schema provides a consistent structure across all detections with fields for author, UUID, MITRE taxonomy, severity, fidelity, and test expectations.

**Tradeoff**: YAML inside markdown inside a Databricks notebook source file creates nested escaping challenges. The `# MAGIC ` prefix that Databricks adds to markdown source lines means the YAML parser must strip these prefixes. Historical entries in the manifest contained `# MAGIC ` artifacts in descriptions before cleanup.

---

## 7. Threat Model Mapping as Static Configuration

**Decision**: The mapping of detections to threat models is defined as a static Python dictionary (`THREAT_MODEL_MAPPINGS`) in `lib/threat_model_mappings.py`, with companion dictionaries for risk descriptions (`THREAT_MODEL_RISK_DESCRIPTIONS`) and display metadata (`THREAT_MODEL_METADATA`).

**Context**: Seven threat models (Account Takeover, Data Exfiltration, Insider Threat, Supply Chain, Databricks Compromise, Ransomware, Resource Abuse) each map to a subset of the 34 detections. Detections can appear in multiple threat models.

**Rationale**:
- **Explicit governance**: The mappings are version-controlled alongside the detection code. Every change to threat model coverage is visible in git history and reviewable in PRs.
- **Authoritative sourcing**: Risk descriptions are quoted from "Databricks Security Best Practices for AWS (Version 2.2 - December 2025)", providing official context for each threat model.
- **Extensibility**: Adding a new threat model requires adding three dictionary entries (risk description, metadata, mapping list) and creating a thin notebook wrapper. No framework changes needed.
- **Many-to-many relationship**: A single detection like `access_token_created` appears in Account Takeover, Data Exfiltration, Insider Threat, and Resource Abuse. The dictionary structure naturally supports this without duplication of detection logic.

**Tradeoff**: The mappings must be manually maintained. Adding a new detection requires remembering to add it to all relevant threat model lists. There is no automated validation that all detections appear in at least one threat model.

---

## 8. Enrichment Class Hierarchy for MaxMind GeoIP

**Decision**: IP enrichment uses a four-level class hierarchy: `EnrichmentBase` -> `ColumnEnrichment` -> `PandasFunctionEnrichmentBase` -> `MaxMindEnrichmentBase` -> (`GeoIPEnrichment`, `ASNEnrichment`).

**Context**: The system optionally enriches IP addresses in detection results with geographic location (city, country, coordinates) and autonomous system information (ASN number, organization, network).

**Rationale**:
- **EnrichmentBase**: Abstract contract for any enrichment that transforms a DataFrame. Supports both column-based enrichment and join-based enrichment.
- **ColumnEnrichment**: Specializes to enrichments that add a single new column. The `enrich()` method calls `get_column()` and appends it via `df.select("*", column)`.
- **PandasFunctionEnrichmentBase**: Specializes to column enrichments implemented as Pandas UDFs. This is the performance-critical layer: Pandas UDFs execute vectorized Python code in Spark's Arrow-based format, avoiding the overhead of per-row Python function calls.
- **MaxMindEnrichmentBase**: Handles MaxMind-specific concerns: database file management (DBFS vs. local caching with `_copy_db_file` and `_get_database`), private IP filtering (skipping 10.*, 192.168.*, 127.*, 172.16-31.*, 169.254.*), and the shared UDF creation pattern with per-partition caching.
- **GeoIPEnrichment / ASNEnrichment**: Leaf classes that only define the record schema, extraction logic, and null type. All infrastructure is inherited.

**Tradeoff**: The hierarchy is deep for only two concrete implementations. The `ColumnEnrichment.enrich()` method has a documented limitation: it cannot expand struct columns, so enrichment always adds a new struct column rather than flattening fields into the DataFrame.

---

## 9. Optional GeoIP with Graceful Degradation

**Decision**: GeoIP enrichment is disabled by default. It activates only when a MaxMind database path is provided via Databricks widget or Spark configuration.

**Context**: MaxMind GeoLite2 databases require registration and download. Not all deployments have them available.

**Rationale**:
- **Zero-config startup**: Detections work without any GeoIP configuration. Analysts can begin investigating immediately without provisioning MaxMind databases.
- **Two configuration paths**: Spark config (`spark.conf.set("spark.databricks.geoip.city.path", ...)`) for cluster-wide enablement, or Databricks widgets for per-notebook override.
- **Graceful failure**: If a configured database path is invalid or the file is corrupted, the system prints a warning and continues without enrichment rather than failing the entire detection run.

**Tradeoff**: Individual detections do not apply GeoIP enrichment automatically. The enrichment infrastructure is initialized at `common.py` load time, but detections must explicitly use the `geo_enricher` / `asn_enricher` objects. Currently, no detection notebooks reference these enrichers; the infrastructure is available for future use or analyst-driven enrichment in generated notebooks.

---

## 10. `@detect` Decorator with Dual Output Modes

**Decision**: Detection functions are wrapped with a `@detect` decorator that supports two output modes: `Output.asDataFrame` (default, returns raw results) and `Output.asAlert` (transforms results into a standardized alert schema and merges into a Delta table).

**Context**: Detections serve two use cases: interactive investigation (analysts exploring results in notebooks) and automated alerting (scheduled jobs writing to an alerts table).

**Rationale**:
- **Separation of concerns**: Detection functions focus purely on identifying suspicious activity and returning a DataFrame. The output transformation (alert formatting, deduplication, Delta merge) is handled by the decorator, not the detection.
- **Standardized alert schema**: `alerts_schema` defines a consistent structure (`alert_id`, `alertTime`, `eventTime`, `user_email`, `event_type`, `source_ip`, `event_data` as JSON) that downstream consumers (SIEM integration, dashboards, notification systems) can rely on.
- **Deduplication via Delta merge**: `_write_alerts()` uses `DeltaTable.merge()` keyed on `alert_id` (UUID) to prevent duplicate alerts when detections are re-run on overlapping time windows.
- **Transparent wrapping**: Using `functools.wraps` preserves the original function's name and docstring. The decorator supports both `@detect` (no args) and `@detect(output=Output.asAlert)` syntax via `functools.partial`.

**Tradeoff**: The alert transformation in `_alerts_df()` assumes specific column names in the detection output (`EVENT_DATE`, `SRC_USER`, `ACTION`, `SRC_IP`). Detections that use different column names would need to conform or the alert will contain null values. There is no compile-time validation of this contract.

---

## 11. WorkspaceClient SDK for File Operations

**Decision**: The system uses the Databricks SDK `WorkspaceClient` for file operations (listing directories, downloading notebook content, uploading generated notebooks) rather than `dbutils` or local filesystem access.

**Context**: Detection discovery requires listing files in workspace directories. Generated notebooks must be uploaded to the workspace. The system must work on both classic compute (where `/Workspace` FUSE mount is available) and serverless (where it is not).

**Rationale**:
- **Serverless compatibility**: On Databricks serverless compute, the local filesystem does not include workspace paths. `os.listdir()` and `open()` fail. `WorkspaceClient.workspace.list()` and `.download()` work in both environments via the REST API.
- **Programmatic upload**: `w.workspace.upload()` creates notebook objects directly in the workspace, setting the correct format (`ImportFormat.SOURCE`) and language (`Language.PYTHON`). This avoids the limitations of `dbutils.notebook.run()` for file creation.
- **Error handling**: The SDK raises typed exceptions that `parse_detection_file()` catches to gracefully skip unreadable files.

**Tradeoff**: `WorkspaceClient()` requires authentication context. On Databricks compute this is automatic via ambient credentials. Locally or in CI, explicit configuration is needed. The SDK also adds a dependency (`databricks-sdk`) that `dbutils` doesn't require.

---

## 12. Manifest, Meta, and Detection Tracker Serve Different Audiences

**Decision**: The project maintains three metadata files that overlap in content but serve distinct purposes: `manifest.yaml`, `metadata/meta.yaml`, and `docs/detection_tracker.md`.

**Context**: The app is distributed through Databricks workspace repos and potentially through the Databricks marketplace. Different consumers need different views of the same information.

**Rationale**:
- **`manifest.yaml`**: Machine-readable app manifest. Lists every notebook (34 detections + 7 generators + user behavior analysis) with full `dscc` metadata (UUID, author, content type, detection name/description/objective). Used by Databricks tooling for app registration and discovery. Contains unique UUIDs per detection for tracking.
- **`metadata/meta.yaml`**: Marketplace submission metadata. Contains app-level information (name, version, author email, platform requirements, installation instructions, release dates). Does not list individual detections. Used for Databricks Exchange/marketplace publishing.
- **`docs/detection_tracker.md`**: Human-readable documentation. Organizes detections by category (event-based vs. behavioral, then by subcategory like "Authentication & Session Patterns"). Includes severity ratings, threat model cross-references, and a "Planned" section for future detections. Used by security engineers evaluating detection coverage.

**Tradeoff**: Keeping three files in sync requires discipline. The manifest historically fell behind (covering only 22 of 34 detections) and contained stale artifacts (`# MAGIC` in descriptions, duplicate UUIDs, wrong detection names). Automated validation would prevent this drift but is not currently implemented.

---

## 13. Path Validation Against Traversal Attacks

**Decision**: `discover_detections()` validates that resolved detection file paths stay within the `base/detections/` directory using `os.path.normpath()` before loading them.

**Context**: Detection paths come from `THREAT_MODEL_MAPPINGS`, which is a static dictionary in version-controlled code. However, if a malicious or malformed mapping entry contained `../../etc/passwd` or similar traversal patterns, the system would attempt to download and parse arbitrary workspace files.

**Rationale**:
- **Defense in depth**: Even though the mappings are currently trustworthy, validating paths prevents future mistakes (typos, copy-paste errors) from causing the system to read outside the detections directory.
- **Normalization**: `os.path.normpath()` resolves `..`, `.`, and redundant separators before the prefix check, preventing bypass via `base/detections/../../lib/../base/detections/../sensitive_file`.

**Tradeoff**: The validation only checks that the resolved path starts with the detections base directory. It does not verify that the file is actually a detection notebook (it could be any `.py` file within the detections directory). The file content validation (checking for `@detect` decorator and YAML metadata) provides a secondary check.

---

## 14. User Email Filtering via Variable Reference

**Decision**: When generating user-specific investigation notebooks, the system filters detection queries using `lit(USER_EMAIL)` (a PySpark column literal referencing a notebook variable) rather than string-interpolating the email into the generated code.

**Context**: `user_behavior_analysis.py` generates notebooks that filter all detections by a specific user's email. Previously, the email was interpolated directly into generated PySpark code via `.format(user_email)`, creating injection risk.

**Rationale**:
- **Injection prevention**: An email like `user" OR "1"=="1` would break out of the string literal in interpolated code. Using `lit(USER_EMAIL)` references a Python variable set via `repr()`, and the four generated `spark.sql()` calls use parameterized queries (`:user_email` with `args={"user_email": USER_EMAIL}`).
- **Defense in depth**: Email format validation via regex (`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`) rejects malformed inputs before code generation begins.
- **Readable generated code**: `spark.table("system.access.audit").filter(col("user_identity.email") == lit(USER_EMAIL))` is clearer than a hardcoded email string, and the variable definition at the top of the generated notebook (`USER_EMAIL = 'user@example.com'`) makes the parameter visible.

**Tradeoff**: The generated notebook must define `USER_EMAIL` as a variable and import `lit` from `pyspark.sql.functions`. This adds a few lines of setup code to every generated notebook.

---

## 15. Sanitization of Detection Metadata in Generated Notebooks

**Decision**: Detection names, descriptions, objectives, and other YAML-sourced metadata are sanitized via `_sanitize_for_markdown()` and `_sanitize_for_python_comment()` before being embedded in generated notebook content.

**Context**: Generated notebooks embed detection metadata in both markdown cells (for documentation) and Python comments (for code context). This metadata comes from YAML blocks in detection notebooks, which could contain characters that break the generated notebook.

**Rationale**:
- `_sanitize_for_markdown()` strips `# MAGIC ` artifacts (left over from Databricks notebook source format), triple quotes (`"""` / `'''`) that could terminate Python string literals, and fenced code blocks that could inject executable content.
- `_sanitize_for_python_comment()` removes newlines and truncates to 200 characters for safe embedding in single-line code comments.
- **Proactive defense**: Even though detection metadata is currently authored by trusted developers, the sanitization prevents accidental breakage (e.g., a description containing a backtick-fenced code example) and protects against future scenarios where metadata might come from less trusted sources.

**Tradeoff**: Sanitization is lossy. Code blocks in descriptions are replaced with `[code block removed]`. Descriptions longer than 200 characters are truncated in code comments. The full metadata is preserved in the markdown cells where length is not an issue.

---

## 16. Single-Function Threat Model Notebooks

**Decision**: Each of the 7 threat model generator notebooks is a thin wrapper that calls `run_threat_model_investigation("key")` from the shared library, rather than containing its own generation logic.

**Context**: Originally, each threat model notebook contained ~72 lines of identical boilerplate (widget setup, detection discovery, notebook generation, workspace upload) with only the threat model key, title, and description differing.

**Rationale**:
- **DRY**: The shared `run_threat_model_investigation()` function in `notebook_generator_base.py` handles all orchestration. Threat model metadata (titles, descriptions) lives in `THREAT_MODEL_METADATA` in `threat_model_mappings.py`.
- **Individual notebooks preserved**: Each threat model retains its own notebook file because Databricks workflows and UI navigation expect addressable notebooks. A single parameterized notebook would require the analyst to know the threat model key to type into a widget, rather than simply clicking the relevant notebook.
- **Documentation preserved**: Each notebook retains its markdown header with the threat model's risk description and detection coverage summary, providing context when browsing the repo or workspace.

**Tradeoff**: Seven files still exist where one parameterized file could suffice. The markdown documentation in each file is static and could drift from `THREAT_MODEL_RISK_DESCRIPTIONS`. The notebooks still have ~42 lines each (markdown documentation + widget setup + `%run` + function call), but the executable logic is a single line.
