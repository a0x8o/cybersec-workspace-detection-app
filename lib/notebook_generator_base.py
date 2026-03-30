# Databricks notebook source
# MAGIC %md
# MAGIC # Notebook Generator Base Library
# MAGIC
# MAGIC Shared functions for generating investigation notebooks (threat models and user behavior analysis).
# MAGIC
# MAGIC ## Key Functions
# MAGIC - `parse_detection_file(file_path)` - Parse YAML metadata and function code
# MAGIC - `discover_detections(base_path=None, detection_list=None)` - Scan and load detections
# MAGIC - `format_time_range(days=None, hours=None)` - Time range formatting
# MAGIC - `generate_detection_code(detection_name, config, earliest, latest, is_event_based=False, user_email=None)` - Generate detection execution code
# MAGIC - `generate_threat_model_notebook(threat_model, threat_model_title, threat_model_description, all_detections, time_range_days, binary_time_range_hours)` - Create complete threat model notebook

# COMMAND ----------

import os
import re
import yaml
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any, List, Optional
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.workspace import ImportFormat, Language
import io


def _sanitize_for_markdown(text: str) -> str:
    """Sanitize text for safe embedding in generated notebook markdown cells.

    Strips characters that could break out of # MAGIC markdown context or
    inject executable code.
    """
    if not text:
        return ""
    # Remove # MAGIC artifacts from notebook extraction
    text = text.replace("# MAGIC ", "").replace("#MAGIC ", "")
    # Strip triple quotes that could break Python string literals
    text = text.replace('"""', '').replace("'''", "")
    # Remove backtick-fenced code blocks that could inject executable content
    text = re.sub(r'```\w*\n.*?```', '[code block removed]', text, flags=re.DOTALL)
    return text.strip()


def _sanitize_for_python_comment(text: str) -> str:
    """Sanitize text for safe embedding in generated Python code comments."""
    if not text:
        return ""
    # Remove newlines and limit length for single-line comment context
    return text.replace('\n', ' ').replace('\r', '').strip()[:200]

# Initialize workspace client
w = WorkspaceClient()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Path Helpers

# COMMAND ----------

def get_notebook_path():
    """Get current notebook path (works on both classic compute and serverless)"""
    return dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()

def get_repo_root():
    """Get the repository root path from the current notebook location.

    Works for notebooks at different depths:
    - /repo/base/notebooks/file.py
    - /repo/base/notebooks/threat_models/file.py
    """
    notebook_path = get_notebook_path()

    # Walk up until we find the repo root (parent of 'base' directory)
    current = notebook_path
    while current and current != '/':
        parent = os.path.dirname(current)
        if os.path.basename(current) == 'base':
            # Found 'base' directory, parent is repo root
            return parent
        current = parent

    # Fallback: assume standard 3-level structure
    # notebook_path is like: /Users/user@email.com/repo/base/notebooks/notebook_name
    notebooks_dir = os.path.dirname(notebook_path)  # .../base/notebooks or .../base/notebooks/threat_models
    base_dir = os.path.dirname(notebooks_dir)       # .../base/notebooks or .../base
    if os.path.basename(base_dir) == 'notebooks':
        # We're in a subdirectory of notebooks (e.g., threat_models)
        base_dir = os.path.dirname(base_dir)        # .../base
    return os.path.dirname(base_dir)                # .../repo (root)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Detection Discovery Functions

# COMMAND ----------

def parse_detection_file(file_path: str, user_email: Optional[str] = None) -> Dict[str, Any]:
    """Parse a detection file to extract metadata and function information.

    Args:
        file_path: Path to detection file
        user_email: Optional user email for user-specific filtering

    Returns:
        Dictionary containing detection metadata and function code
    """
    file_path = re.sub(r'\.py$', '', file_path)
    print(f"Parsing detection file: {file_path}")

    try:
        with w.workspace.download(file_path) as f:
            content = f.read().decode()
    except Exception as e:
        print(f"Warning: Failed to download {file_path}: {e}")
        return None

    # Extract the YAML metadata from the markdown cell
    yaml_match = re.search(r'```yaml\s*(.*?)```', content, re.DOTALL)
    if not yaml_match:
        print(f"Warning: No YAML metadata found in {file_path}")
        return None

    yaml_content = yaml_match.group(1).replace("# MAGIC ", "")
    try:
        metadata = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse YAML in {file_path}: {e}")
        return None

    # Extract function definition and parameters
    func_match = re.search(r'@detect.*?\ndef\s+(\w+)\s*\((.*?)\):', content, re.DOTALL)
    if not func_match:
        print(f"Warning: No detection function found in {file_path}")
        return None

    function_name = func_match.group(1)
    params_str = func_match.group(2)

    full_function_match = re.search(r'(@detect.*?)# COMMAND -------', content, re.DOTALL)
    if not full_function_match:
        print(f"Warning: No full function found in {file_path}")
        return None
    full_function = full_function_match.group(1)

    # Apply user filter if specified (for user behavior analysis)
    # Uses variable reference (USER_EMAIL) instead of interpolating raw email to prevent injection
    user_replaced = False
    if user_email:
        if 'spark.table("system.access.audit")' in full_function:
            full_function = full_function.replace(
                'spark.table("system.access.audit")',
                'spark.table("system.access.audit").filter(col("user_identity.email") == lit(USER_EMAIL))'
            )
            user_replaced = True
        if 'spark.table("system.query.history")' in full_function:
            full_function = full_function.replace(
                'spark.table("system.query.history")',
                'spark.table("system.query.history").filter(col("executed_as") == lit(USER_EMAIL))'
            )
            user_replaced = True
        if not user_replaced:
            print(f"Warning: No user filter inserted into {file_path}")
            # Don't return None - threat model notebooks don't need user filters

    # Parse parameters
    params = []
    defaults = {}
    if params_str.strip():
        # Split by comma but handle nested parentheses
        param_parts = re.findall(r'(\w+)(?:\s*:\s*\w+)?(?:\s*=\s*([^,]+))?(?:,|$)', params_str)
        for param_name, default_value in param_parts:
            params.append(param_name)
            if default_value:
                # Clean up default value
                default_value = default_value.strip()
                if default_value.startswith('"') and default_value.endswith('"'):
                    defaults[param_name] = default_value[1:-1]
                elif default_value == 'None':
                    defaults[param_name] = None
                elif default_value.isdigit():
                    defaults[param_name] = int(default_value)
                else:
                    defaults[param_name] = default_value

    # Extract detection info from metadata
    detection_info = metadata.get('dscc', {}).get('detection', {})

    # Determine if this is an event-based or behavioral detection based on file path
    is_event_based = '/event-based/' in file_path

    return {
        "file_path": file_path,
        "file_name": os.path.basename(file_path).replace('.py', ''),
        "function_name": function_name,
        "full_function": full_function,
        "name": detection_info.get('name', function_name.replace('_', ' ').title()),
        "description": detection_info.get('description', '').strip(),
        "objective": detection_info.get('objective', '').strip(),
        "false_positives": detection_info.get('false_positives', '').strip(),
        "severity": detection_info.get('severity', '').strip(),
        "fidelity": detection_info.get('fidelity', '').strip(),
        "category": detection_info.get('category', '').strip(),
        "is_event_based": is_event_based,
        "params": params,
        "defaults": defaults,
        "metadata": metadata
    }

def discover_detections(base_path: str = None, detection_list: List[str] = None, user_email: Optional[str] = None) -> Dict[str, Dict]:
    """Dynamically discover detection files and parse their metadata.

    Args:
        base_path: Base path to scan for detections (if detection_list is None)
        detection_list: List of specific detection paths to load (e.g., ["event-based/sso_config_changed", "behavioral/access_token_created"])
        user_email: Optional user email for user-specific filtering

    Returns:
        Dictionary of detection configurations keyed by file name
    """
    detections = {}
    repo_root = get_repo_root()
    detections_base = os.path.join(repo_root, "base", "detections")

    if detection_list:
        # Load specific detections from the list
        print(f"Loading {len(detection_list)} specific detections...")
        print(f"Repo root: {repo_root}")
        for detection_path in detection_list:
            # detection_path is like "event-based/sso_config_changed" or "behavioral/access_token_created"
            # Build path: repo_root + /base/detections/ + detection_path + .py
            full_path = os.path.join(repo_root, "base", "detections", detection_path)

            # Path traversal validation: ensure resolved path stays within detections directory
            normalized = os.path.normpath(full_path)
            if not normalized.startswith(os.path.normpath(detections_base)):
                print(f"  ✗ Skipping invalid path (outside detections directory): {detection_path}")
                continue
            if not full_path.endswith('.py'):
                full_path += '.py'

            print(f"  Trying path: {full_path}")
            detection_info = parse_detection_file(full_path, user_email=user_email)
            if detection_info:
                detection_name = detection_info["file_name"]
                detections[detection_name] = detection_info
                print(f"  ✓ Loaded: {detection_name}")
            else:
                print(f"  ✗ Failed to load: {detection_path}")

    else:
        # Scan directories for all detections
        if base_path is None:
            detections_base = os.path.join(repo_root, "base", "detections")
        else:
            detections_base = base_path

        print(f"Repo root: {repo_root}")
        print(f"Scanning for detections in {detections_base}...")

        # Scan both event-based and behavioral subdirectories
        for subdir in ["event-based", "behavioral"]:
            detections_dir = os.path.join(detections_base, subdir)

            try:
                detection_objects = list(w.workspace.list(detections_dir))
                detection_files = [
                    obj.path for obj in detection_objects
                    if obj.path and (obj.path.endswith(".py") or
                                   (obj.object_type and obj.object_type.name == "NOTEBOOK"))
                ]

                print(f"Found {len(detection_files)} detection files in {subdir}/")

                for file_path in detection_files:
                    detection_info = parse_detection_file(file_path, user_email=user_email)
                    if detection_info:
                        detection_name = detection_info["file_name"]
                        detections[detection_name] = detection_info
                        print(f"  ✓ Loaded: {detection_name}")

            except Exception as e:
                print(f"Warning: Failed to scan {detections_dir}: {e}")

    print(f"\nSuccessfully loaded {len(detections)} detections")
    return detections

# COMMAND ----------

# MAGIC %md
# MAGIC ## Time Range Helpers

# COMMAND ----------

def format_time_range(days: int = None, hours: int = None) -> Tuple[str, str]:
    """Format time range for detection functions.

    Args:
        days: Number of days to look back (for behavioral detections)
        hours: Number of hours to look back (for event-based detections)

    Returns:
        Tuple of (earliest, latest) as formatted strings

    Raises:
        ValueError: If days or hours is not a positive number
    """
    if days is not None and days < 1:
        raise ValueError(f"days must be a positive integer, got: {days}")
    if hours is not None and hours < 1:
        raise ValueError(f"hours must be a positive integer, got: {hours}")

    latest = datetime.now()

    if days:
        earliest = latest - timedelta(days=days)
    elif hours:
        earliest = latest - timedelta(hours=hours)
    else:
        # Default to 30 days
        earliest = latest - timedelta(days=30)

    return (
        earliest.strftime("%Y-%m-%d %H:%M:%S"),
        latest.strftime("%Y-%m-%d %H:%M:%S")
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Code Generation Functions

# COMMAND ----------

def generate_detection_code(detection_name: str, config: Dict, earliest: str, latest: str,
                           is_event_based: bool = False, user_email: Optional[str] = None) -> str:
    """Generate PySpark code for a specific detection.

    Args:
        detection_name: Name of the detection
        config: Detection configuration dictionary
        earliest: Start of time range
        latest: End of time range
        is_event_based: Whether this is an event-based detection (vs behavioral)
        user_email: Optional user email for user-specific filtering

    Returns:
        Generated Python code as string
    """

    # Build the function call with parameters
    params = []
    for param in config.get("params", []):
        if param == "earliest":
            params.append(f'earliest="{earliest}"')
        elif param == "latest":
            params.append(f'latest="{latest}"')
        elif param in config.get("defaults", {}):
            default_value = config["defaults"][param]
            if default_value is not None:
                if isinstance(default_value, str):
                    params.append(f'{param}="{default_value}"')
                else:
                    params.append(f'{param}={default_value}')

    function_call = f"{config['function_name']}({', '.join(params)})"

    # Sanitize detection name for safe embedding in generated code comment
    safe_name = _sanitize_for_python_comment(config.get('name', detection_name))

    # Generate the code
    code = f"""# Run detection: {safe_name}

{config['full_function']}

try:
    result_df = {function_call}

    # Check if we have results
    if result_df is not None and result_df.count() > 0:
        print(f"✓ Found {{result_df.count()}} events")
        display(result_df)
        detection_triggered = True
    else:
        print(f"○ No events in the specified time range")
        detection_triggered = False

except Exception as e:
    print(f"✗ Error running detection: {{e}}")
    detection_triggered = False
"""

    return code

# COMMAND ----------

# MAGIC %md
# MAGIC ## Threat Model Notebook Generator

# COMMAND ----------

def generate_threat_model_notebook(threat_model: str, threat_model_title: str,
                                  threat_model_description: str, all_detections: Dict,
                                  time_range_days: int = 30, binary_time_range_hours: int = 24) -> str:
    """Generate a complete threat model investigation notebook.

    Args:
        threat_model: Threat model key (e.g., "account_takeover")
        threat_model_title: Display title for the threat model
        threat_model_description: Description of what this threat model covers
        all_detections: Dictionary of all loaded detections
        time_range_days: Time window for behavioral detections
        binary_time_range_hours: Time window for event-based detections (hours)

    Returns:
        Complete notebook content as string
    """

    # Get official risk description (THREAT_MODEL_RISK_DESCRIPTIONS loaded via %run)
    risk_description = _sanitize_for_markdown(THREAT_MODEL_RISK_DESCRIPTIONS.get(threat_model, "No risk description available."))
    threat_model_description = _sanitize_for_markdown(threat_model_description)

    # Calculate time ranges
    behavioral_earliest, behavioral_latest = format_time_range(days=time_range_days)
    event_based_earliest, event_based_latest = format_time_range(hours=binary_time_range_hours)

    # Separate detections by type
    event_based_detections = [(name, config) for name, config in all_detections.items() if config.get('is_event_based', False)]
    behavioral_detections = [(name, config) for name, config in all_detections.items() if not config.get('is_event_based', False)]

    # Sort detections alphabetically by name
    event_based_detections = sorted(event_based_detections, key=lambda x: x[1].get("name", x[0]))
    behavioral_detections = sorted(behavioral_detections, key=lambda x: x[1].get("name", x[0]))

    # Define magic command prefix as a variable to avoid confusion
    magic = "# MAGIC"
    command = "# COMMAND ----------"

    # Generate notebook header
    notebook_content = f"""# Databricks notebook source
{magic} %md
{magic} # Threat Model: {threat_model_title}
{magic}
{magic} ## Risk Description
{magic}
{magic} {risk_description}
{magic}
{magic} *Source: Databricks Security Best Practices for AWS (Version 2.2 - December 2025)*
{magic}
{magic} ## Detection Coverage
{magic}
{magic} {threat_model_description}
{magic}
{magic} **Analysis Parameters:**
{magic} - **Event-Based Detections Time Window:** {binary_time_range_hours} hours ({event_based_earliest} to {event_based_latest})
{magic} - **Behavioral Detections Time Window:** {time_range_days} days ({behavioral_earliest} to {behavioral_latest})
{magic} - **Total Detections:** {len(all_detections)} ({len(event_based_detections)} event-based, {len(behavioral_detections)} behavioral)
{magic} - **Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{command}

{magic} %md
{magic} ## Setup and Configuration

{command}

{magic} %run ../lib/common

{command}

from pyspark.sql.functions import col, count, when
from datetime import datetime, timedelta

# Analysis parameters
EVENT_BASED_EARLIEST = "{event_based_earliest}"
EVENT_BASED_LATEST = "{event_based_latest}"
BEHAVIORAL_EARLIEST = "{behavioral_earliest}"
BEHAVIORAL_LATEST = "{behavioral_latest}"
TIME_RANGE_DAYS = {time_range_days}
EVENT_BASED_TIME_RANGE_HOURS = {binary_time_range_hours}

print(f"Threat Model: {threat_model_title}")
print(f"Event-based detection window: {{EVENT_BASED_EARLIEST}} to {{EVENT_BASED_LATEST}} ({binary_time_range_hours} hours)")
print(f"Behavioral detection window: {{BEHAVIORAL_EARLIEST}} to {{BEHAVIORAL_LATEST}} ({time_range_days} days)")
print("=" * 80)

{command}

# Initialize summary statistics
summary_stats = {{
    "threat_model": "{threat_model_title}",
    "event_based_time_range": f"{{EVENT_BASED_EARLIEST}} to {{EVENT_BASED_LATEST}}",
    "behavioral_time_range": f"{{BEHAVIORAL_EARLIEST}} to {{BEHAVIORAL_LATEST}}",
    "total_detections": {len(all_detections)},
    "event_based_detections": {len(event_based_detections)},
    "behavioral_detections": {len(behavioral_detections)},
    "findings": 0,
    "detections_triggered": []
}}

detection_triggered = False

"""

    # Add event-based detections section
    if event_based_detections:
        notebook_content += f"""
{command}

{magic} %md
{magic} ## Event-Based Detections (Immediate Alerts)
{magic}
{magic} High-confidence security events requiring immediate attention.
{magic} **Time Window:** {binary_time_range_hours} hours

"""

        for detection_name, config in event_based_detections:
            display_name = _sanitize_for_markdown(config.get('name', detection_name.replace('_', ' ').title()))

            notebook_content += f"""
{command}

{magic} %md
{magic} ### {display_name}
{magic}
"""
            # Add sanitized metadata fields
            for field_key, field_label in [('description', 'Description'), ('objective', 'Objective'),
                                           ('severity', 'Severity'), ('fidelity', 'Fidelity'),
                                           ('false_positives', 'False Positives')]:
                field_val = _sanitize_for_markdown(config.get(field_key, ''))
                if field_val:
                    notebook_content += f"""{magic} **{field_label}:** {field_val}
{magic}
"""

            notebook_content += f"""{magic} **Detection File:** `{detection_name}.py`

{command}

{generate_detection_code(detection_name, config, event_based_earliest, event_based_latest, is_event_based=True)}

# Update summary statistics if detection triggered
if detection_triggered:
    summary_stats["findings"] += 1
    summary_stats["detections_triggered"].append("{display_name} (Event-Based)")

"""

    # Add behavioral detections section
    if behavioral_detections:
        notebook_content += f"""
{command}

{magic} %md
{magic} ## Behavioral Detections (Threat Hunting)
{magic}
{magic} Pattern analysis over time windows for threat hunting and investigation.
{magic} **Time Window:** {time_range_days} days

"""

        for detection_name, config in behavioral_detections:
            display_name = _sanitize_for_markdown(config.get('name', detection_name.replace('_', ' ').title()))

            notebook_content += f"""
{command}

{magic} %md
{magic} ### {display_name}
{magic}
"""
            # Add sanitized metadata fields
            for field_key, field_label in [('description', 'Description'), ('objective', 'Objective'),
                                           ('severity', 'Severity'), ('fidelity', 'Fidelity'),
                                           ('false_positives', 'False Positives')]:
                field_val = _sanitize_for_markdown(config.get(field_key, ''))
                if field_val:
                    notebook_content += f"""{magic} **{field_label}:** {field_val}
{magic}
"""

            notebook_content += f"""{magic} **Detection File:** `{detection_name}.py`

{command}

{generate_detection_code(detection_name, config, behavioral_earliest, behavioral_latest, is_event_based=False)}

# Update summary statistics if detection triggered
if detection_triggered:
    summary_stats["findings"] += 1
    summary_stats["detections_triggered"].append("{display_name} (Behavioral)")

"""

    # Add summary section
    notebook_content += f"""
{command}

{magic} %md
{magic} ## Investigation Summary

{command}

# Display final summary statistics
print("=" * 80)
print("THREAT MODEL INVESTIGATION SUMMARY")
print("=" * 80)
print(f"Threat Model: {{summary_stats['threat_model']}}")
print(f"Event-Based Detection Window: {{summary_stats['event_based_time_range']}}")
print(f"Behavioral Detection Window: {{summary_stats['behavioral_time_range']}}")
print(f"Total Detections Analyzed: {{summary_stats['total_detections']}} ({{summary_stats['event_based_detections']}} event-based, {{summary_stats['behavioral_detections']}} behavioral)")
print(f"Total Findings: {{summary_stats['findings']}}")
print("-" * 80)

if summary_stats["findings"] == 0:
    print("✓ RESULT: No suspicious activity detected for this threat model")
else:
    print(f"⚠️ RESULT: {{summary_stats['findings']}} detection(s) triggered - review required")
    print()
    print("Detections that triggered:")
    for detection in summary_stats["detections_triggered"]:
        print(f"  • {{detection}}")

{command}

{magic} %md
{magic} ---
{magic} *Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} using Threat Model Investigation Framework*
"""

    return notebook_content

# COMMAND ----------

# MAGIC %md
# MAGIC ## Threat Model Runner

# COMMAND ----------

def validate_widget_int(name: str, value_str: str, min_val: int = 1, max_val: int = 365) -> int:
    """Validate and parse an integer widget value.

    Args:
        name: Widget name for error messages
        value_str: Raw string value from widget
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Validated integer value

    Raises:
        ValueError: If value is not a valid integer or out of range
    """
    try:
        value = int(value_str)
    except (ValueError, TypeError):
        raise ValueError(f"Widget '{name}' must be a valid integer, got: {value_str!r}")
    if value < min_val or value > max_val:
        raise ValueError(f"Widget '{name}' must be between {min_val} and {max_val}, got: {value}")
    return value

def run_threat_model_investigation(threat_model: str):
    """Run a complete threat model investigation: discover detections, generate notebook, upload.

    Reads widget values for time_range_days and binary_time_range_hours.
    Uses THREAT_MODEL_MAPPINGS, THREAT_MODEL_METADATA, and THREAT_MODEL_RISK_DESCRIPTIONS
    (loaded via %run ../../../lib/threat_model_mappings).

    Args:
        threat_model: Key into THREAT_MODEL_MAPPINGS (e.g., "account_takeover")

    Raises:
        ValueError: If threat_model key not found in mappings
    """
    if threat_model not in THREAT_MODEL_MAPPINGS:
        raise ValueError(f"Unknown threat model: {threat_model!r}. Valid keys: {list(THREAT_MODEL_MAPPINGS.keys())}")

    metadata = THREAT_MODEL_METADATA.get(threat_model, {})
    title = metadata.get("title", threat_model.replace("_", " ").title())
    description = metadata.get("description", f"Investigation for {title}")

    # Discover detections for this threat model
    detection_list = THREAT_MODEL_MAPPINGS[threat_model]
    all_detections = discover_detections(detection_list=detection_list)
    print(f"Found {len(all_detections)} detections for: {threat_model}")

    # Validate and parse widget values
    time_range_days = validate_widget_int("time_range_days", dbutils.widgets.get("time_range_days"), min_val=1, max_val=365)
    binary_hours = validate_widget_int("binary_time_range_hours", dbutils.widgets.get("binary_time_range_hours"), min_val=1, max_val=720)

    # Generate notebook
    notebook_content = generate_threat_model_notebook(
        threat_model=threat_model,
        threat_model_title=title,
        threat_model_description=description,
        all_detections=all_detections,
        time_range_days=time_range_days,
        binary_time_range_hours=binary_hours
    )

    # Save to generated folder
    output_path = f"{get_repo_root()}/generated/threat_model_{threat_model}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    w.workspace.upload(output_path, io.BytesIO(notebook_content.encode('utf-8')),
                       format=ImportFormat.SOURCE, language=Language.PYTHON)

    print(f"✅ Generated: {output_path}")

# COMMAND ----------
