# Changelog

All notable changes to the Databricks Workspace Detection App are documented in this file.

## [Unreleased] - 2026-03-29

### Security

- Fixed SQL/code injection vulnerabilities in `user_behavior_analysis.py` where user email was interpolated directly into generated PySpark filters via `.format()` and f-strings. Now uses `F.lit(USER_EMAIL)` variable references and Spark parameterized queries (`:param` syntax with `args={}`) for all generated SQL.
- Added email format validation (regex) and time range bounds checking to prevent injection via widget parameters.
- Added path traversal validation in `discover_detections()` using `os.path.normpath()` to ensure detection paths stay within the `base/detections/` directory.
- Added `_sanitize_for_markdown()` and `_sanitize_for_python_comment()` to strip characters that could break generated notebook code (triple quotes, code blocks, `# MAGIC` artifacts).

### Fixed

- Fixed `_get_database()` in `MaxMindEnrichmentBase` where `db_name` was not set to the local cached path after initial copy, causing the first run to always use the remote file despite copying locally.
- Fixed operator precedence bug in `run_all_detections()` where missing parentheses around `obj.object_type and obj.object_type.name == "NOTEBOOK"` could cause incorrect notebook filtering.
- Fixed bare `except:` clauses in `get_geoip_db_path()` to use `except Exception:` so `SystemExit` and `KeyboardInterrupt` are not silently swallowed.
- Fixed `databricks_employee_logon.py` manifest entry which incorrectly had detection name "Verbose Audit Disabled" instead of "Databricks Employee Logon".
- Fixed all 22 original manifest detections sharing the same UUID (`4e8de7fb...`); each now has a unique UUID.
- Cleaned `# MAGIC ` artifacts from all manifest description and objective fields.
- Added `run_all_detections()` null check: raises `ValueError` if `earliest` or `latest` timestamps are not provided.
- Added input validation to `format_time_range()` to reject non-positive `days`/`hours` values.

### Changed

- **Renamed `binary` to `event-based`** across the entire codebase: directory scan loops in `notebook_generator_base.py`, `common.py`, and `user_behavior_analysis.py` now reference `"event-based"` instead of `"binary"`. Generated notebook labels updated from "Binary Detections" to "Event-Based Detections". Internal variables renamed from `is_binary`/`binary_detections`/`BINARY_EARLIEST` to `is_event_based`/`event_based_detections`/`EVENT_BASED_EARLIEST`.
- **Consolidated 7 threat model generator notebooks** by adding `THREAT_MODEL_METADATA` dict to `threat_model_mappings.py` and `run_threat_model_investigation()` to `notebook_generator_base.py`. Each threat model notebook reduced from ~72 lines of duplicated boilerplate to ~42 lines calling the shared function.
- **Eliminated code duplication in `user_behavior_analysis.py`** by replacing local copies of `parse_detection_file`, `discover_detections`, `format_time_range`, `generate_detection_code`, and helper functions with `%run ../../lib/notebook_generator_base`. Reduced file from ~570 lines to ~360 lines.
- **Refactored `MaxMindEnrichmentBase`** to extract shared pandas UDF creation logic from `GeoIPEnrichment` and `ASNEnrichment` into `create_pandas_udf_function()` in the base class. Subclasses now only implement `_empty_record()`, `_extract_record()`, and `_udf_return_schema()`.
- Added `validate_widget_int()` utility in `notebook_generator_base.py` for consistent widget parameter validation with range checking.

### Manifest

- Updated `manifest.yaml` to include all 34 detections (previously only 22 of 34 were listed).
- Fixed all detection paths from `base/detections/binary/` to `base/detections/event-based/`.
- Filled `release_date` and `submitted_at` placeholder values.
- Assigned unique UUIDs to all detection entries.

## [1.3.0] - 2026-03-06

### Added

- **Privileged role assignment detections** (PR #8):
  - `account_admin_privileged_role_assignment.py` - Detects account admin privilege grants via direct assignment or group membership.
  - `metastore_admin_privilege_granted.py` - Detects metastore ownership changes and admin group additions.
  - `workspace_admin_privileged_role_assignment.py` - Detects workspace admin grants via entitlement or admins group.

### Fixed

- Fixed detection gaps in privileged role assignment detections (PR #9):
  - Fixed `TARGET_PRINCIPAL_NAME` resolution for `addPrincipalsToGroup` actions.
  - Added child group detection for nested group membership.
  - Corrected workspace admin detection to cover both direct entitlement and admins group paths.
  - Fixed metastore admin detection to handle ownership changes via `updateMetastore`.

### Changed

- Renamed `detections/binary/` folder to `detections/event-based/` for clarity.
- Updated documentation labels from "binary" to "event-based".
- Updated `detection_tracker.md` and `threat_model_mappings.py` to include privileged role assignment detections.

## [1.2.0] - 2026-02-02

### Added

- **Threat model investigation framework** (PR #6):
  - 7 threat model generator notebooks: Account Takeover, Data Exfiltration, Insider Threat, Supply Chain, Databricks Compromise, Ransomware, Resource Abuse.
  - `lib/notebook_generator_base.py` - Shared notebook generation library with detection discovery, code generation, and time range handling.
  - `lib/threat_model_mappings.py` - Detection-to-threat-model association matrix with official risk descriptions from Databricks Security Best Practices for AWS (v2.2).
  - `docs/detection_tracker.md` - Complete detection inventory documentation.

### Changed

- **Reorganized detections into subdirectories**: flat `base/detections/` split into `base/detections/binary/` (event-based) and `base/detections/behavioral/` subdirectories.
- Added 12 new detections created during the structural reorganization:
  - 5 behavioral: `potential_data_movement_explicit_creds`, `potential_data_movement_sql_queries`, `potential_data_movement_workspace_downloads`, `secret_scanning_activity`, `user_admin_account_change` (moved to event-based).
  - 4 event-based: `configuration_changes_account_level`, `configuration_changes_high_priority`, `configuration_changes_workspace_level`, `user_admin_account_change`.
- Updated `manifest.yaml` with threat model generator entries and new detection metadata.
- Enhanced `user_behavior_analysis.py` with improved detection discovery.
- Expanded `lib/common.py` with `run_all_detections()`, `get_time_range_from_widgets()`, and `get_detections_dir()` utilities.

## [1.1.0] - 2025-12-17

### Fixed

- **Serverless compatibility** (PR #5): Replaced local filesystem operations with Databricks Workspace SDK for notebook discovery and file access. Detection scanning now works on both classic compute and serverless.
- Fixed relative path resolution in `run_all_detections.py`.
- Fixed `dbutils.notebook.run()` calls to include proper timeout values.

### Changed

- Updated README with documentation links and renamed tool references.

## [1.0.1] - 2025-08-15

### Added

- **TruffleHog scan detection** (PR #3): New `trufflehog_scan_detected.py` detection for identifying credential scanning tool usage in the environment.

### Changed

- Elevated `user_account_created` severity to high given risk of persistence via unauthorized account provisioning.
- Standardized detection notebook formatting and metadata across existing detections.

## [1.0.0] - 2025-08-12

### Added

- Initial release with 22 security detections against `system.access.audit`:
  - **Authentication**: SSO config changes, non-SSO logins, denied IP logon attempts, Databricks employee logon.
  - **Session Security**: Multi-device session hijacking, frequent login detection, session count anomalies.
  - **Token Management**: Access token creation/deletion, token scanning activity.
  - **Identity & Access**: User account creation/deletion, role modifications, group creation/deletion, principal group membership changes, password changes.
  - **MFA**: MFA key addition/deletion.
  - **Audit**: Verbose audit logging disabled.
- `lib/common.py` with GeoIP/ASN enrichment (MaxMind), IP validation, and `@detect` decorator.
- `base/notebooks/user_behavior_analysis.py` for user-specific investigation notebook generation.
- `base/notebooks/run_all_detections.py` for batch execution.
- `manifest.yaml` and `metadata/meta.yaml` app configuration.
