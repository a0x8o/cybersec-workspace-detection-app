# Databricks notebook source
# MAGIC %md
# MAGIC # Beta - User Behavior Analysis Generator
# MAGIC
# MAGIC This notebook generates a new investigative notebook focused on the behavior of
# MAGIC a specific user across multiple security detections. The new notebook will be
# MAGIC stored in the "generated" folder and the full path to the notebook will be printed below in Cell 13 and can be run to analyze the user's behavior.
# MAGIC
# MAGIC **Parameters:**
# MAGIC - `user_email`: Email address of the user to analyze
# MAGIC - `time_range_days`: Number of days to look back (default: 30)

# COMMAND ----------

# Widget parameters for interactive execution
dbutils.widgets.text("user_email", "", "User Email Address")
dbutils.widgets.text("time_range_days", "30", "Time Range (days)")

# Get parameters
user_email = dbutils.widgets.get("user_email")
time_range_days = int(dbutils.widgets.get("time_range_days"))

if not user_email:
    raise ValueError("Please provide a user email address")

# Validate email format to prevent injection in generated notebook code
import re as _re
if not _re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', user_email):
    raise ValueError(f"Invalid email format: {user_email!r}")
if time_range_days < 1 or time_range_days > 365:
    raise ValueError(f"time_range_days must be between 1 and 365, got: {time_range_days}")

print(f"Generating user behavior analysis notebook for: {user_email}")
print(f"Time range: {time_range_days} days")
print()

# COMMAND ----------

# MAGIC %pip install pyyaml

# COMMAND ----------

# MAGIC %run ../../lib/notebook_generator_base

# COMMAND ----------

from pyspark.sql.functions import col

# COMMAND ----------

# MAGIC %md
# MAGIC ## Generate User-Specific Analysis Notebook

# COMMAND ----------

def generate_user_notebook(user_email: str, time_range_days: int = 30, all_detections: dict = None) -> str:
    """Generate a complete notebook for analyzing a specific user's behavior.

    Uses shared functions from notebook_generator_base (loaded via %run):
    - discover_detections(), format_time_range(), generate_detection_code()
    - _sanitize_for_markdown(), _sanitize_for_python_comment()
    """

    # Discover all detections with user email filtering
    all_detections = all_detections or discover_detections(user_email=user_email)

    earliest, latest = format_time_range(days=time_range_days)

    # Sort detections alphabetically by name for consistent ordering
    sorted_detections = sorted(
        all_detections.items(),
        key=lambda x: x[1].get("name", x[0])
    )

    # Define magic command prefix as a variable to avoid confusion
    magic = "# MAGIC"
    command = "# COMMAND ----------"
    notebook_content = f"""# Databricks notebook source
{magic} %md
{magic} # User Behavior Analysis Report
{magic}
{magic} **User:** {user_email}
{magic} **Analysis Period:** {earliest} to {latest} ({time_range_days} days)
{magic} **Total Detections Included:** {len(all_detections)}
{magic} **Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{command}

{magic} %md
{magic} ## Setup and Configuration

{command}

{magic} %run ../lib/common

{command}

from pyspark.sql.functions import col, lit, count, when, max as spark_max, min as spark_min
from datetime import datetime, timedelta
import pandas as pd

# Analysis parameters
USER_EMAIL = {repr(user_email)}
EARLIEST = "{earliest}"
LATEST = "{latest}"
TIME_RANGE_DAYS = {time_range_days}

print(f"Analyzing user behavior for: {{USER_EMAIL}}")
print(f"Time range: {{EARLIEST}} to {{LATEST}}")
print("=" * 60)

{command}

{magic} %md
{magic} ## Recent Statistics

{command}

{magic} %md
{magic} ### IP Addresses
{magic}
{magic} The report below will show the IP Addresses that have been used by the time period. If there is a small number of IPs before any suspect period, followed by a new IP during a suspect period, it is prudent to review that IP address.

{command}

display(spark.sql('''
select
    min(event_time) as earliest,
    max(event_time) as latest,
    count(*) as total_events,
    count(distinct service_name || action_name) as num_unique_actions,
    source_ip_address
from system.access.audit
where user_identity.email = :user_email and event_time between :earliest and :latest
group by all
order by earliest desc
''', args={{"user_email": USER_EMAIL, "earliest": EARLIEST, "latest": LATEST}}))

{command}

{magic} %md
{magic} ### Token Usage
{magic}
{magic} The report below will show the Personal Access Tokens or OAuth tokens that have been used in the time period. This can provide context about normal vs abnormal activity.

{command}

display(spark.sql('''
select
  min(event_time) as earliest,
  max(event_time) as latest,
  count(*) as total_events,
  count(distinct source_ip_address) as num_source_ips,
  count(distinct user_agent) as num_useragents,
  request_params.tokenId
from system.access.audit where
  action_name == "tokenLogin" and
  request_params.authenticationMethod!='API_INT_PAT_TOKEN' and  -- filters out internal actions from a notebook / job
  user_identity.email = :user_email and event_time between :earliest and :latest
group by all
order by earliest desc
''', args={{"user_email": USER_EMAIL, "earliest": EARLIEST, "latest": LATEST}}))

{command}

{magic} %md
{magic} ### API Actions

{command}

display(spark.sql('''
select
  min(event_time) as earliest,
  max(event_time) as latest,
  count(*) as total_events,
  service_name,
  action_name,
  count(distinct source_ip_address) as num_source_ips,
  count(distinct user_agent) as num_useragents
from system.access.audit
where user_identity.email = :user_email and event_time between :earliest and :latest
group by all
order by earliest desc
''', args={{"user_email": USER_EMAIL, "earliest": EARLIEST, "latest": LATEST}}))

{command}

{magic} %md
{magic} ### Billing Usage
{magic}
{magic} We suggest viewing a stacked area chart of SKU usage over time to identify any spikes.

{command}

display(spark.sql('''
select
  usage_date,
  sku_name,
  sum(usage_quantity) as DBU_used
from system.billing.usage
where
  usage_unit="DBU" and
  identity_metadata.created_by = :user_email and usage_start_time between :earliest and :latest
group by all
''', args={{"user_email": USER_EMAIL, "earliest": EARLIEST, "latest": LATEST}}))

{command}

{magic} %md
{magic} ## Detection Analysis
{magic}
{magic} Analyzing user activity across {len(all_detections)} security detections.

{command}

# Initialize summary statistics
summary_stats = {{
    "user": USER_EMAIL,
    "analysis_period": f"{{EARLIEST}} to {{LATEST}}",
    "total_detections": {len(all_detections)},
    "findings": 0,
    "detections_triggered": []
}}

detection_triggered = False

"""

    # Add all detections
    fields = [
        {"field": "description", "label": "Description"},
        {"field": "objective", "label": "Objective"},
        {"field": "fidelity", "label": "Fidelity"},
        {"field": "category", "label": "Category"},
        {"field": "taxonomy", "label": "Taxonomy"},
        {"field": "platform", "label": "Platform"},
        {"field": "version", "label": "Version"},
        {"field": "false_positives", "label": "False Positives"},
        {"field": "severity", "label": "Severity"},
    ]
    for detection_name, config in sorted_detections:
        # Sanitize display name and metadata for safe embedding
        display_name = _sanitize_for_markdown(config.get('name', detection_name.replace('_', ' ').title()))

        notebook_content += f"""
{command}

{magic} %md
{magic} ### {display_name}
{magic}
"""
        for field in fields:
            field_val = _sanitize_for_markdown(config.get(field["field"], ''))
            if field_val:
                notebook_content += f"""{magic} **{field["label"]}:** {field_val}

"""
        notebook_content += f"""{magic} **Detection File:** `{detection_name}.py`

{command}

{generate_detection_code(detection_name, config, earliest, latest)}

# Update summary statistics if detection triggered
if detection_triggered:
    summary_stats["findings"] += 1
    summary_stats["detections_triggered"].append("{display_name}")

"""

    # Add summary section
    notebook_content += f"""
{command}

{magic} %md
{magic} ## Analysis Summary

{command}

# Display final summary statistics
print("=" * 60)
print("USER BEHAVIOR ANALYSIS SUMMARY")
print("=" * 60)
print(f"User: {{summary_stats['user']}}")
print(f"Analysis Period: {{summary_stats['analysis_period']}}")
print(f"Total Detections Analyzed: {{summary_stats['total_detections']}}")
print(f"Total Findings: {{summary_stats['findings']}}")
print("-" * 60)

if summary_stats["findings"] == 0:
    print("✓ RESULT: No suspicious activity detected for this user")
else:
    print(f"⚠️ RESULT: {{summary_stats['findings']}} detection(s) triggered - review required")
    print()
    print("Detections that triggered:")
    for detection in summary_stats["detections_triggered"]:
        print(f"  • {{detection}}")

{command}

{magic} %md
{magic} ---
{magic} *Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} using User Behavior Analysis Framework*
"""

    return notebook_content

# COMMAND ----------

# MAGIC %md
# MAGIC ## Main Execution

# COMMAND ----------

# Discover available detections (with user email for filtering)
print("Discovering available detections...")
all_detections = discover_detections(user_email=user_email)

print(f"\nTotal detections available: {len(all_detections)}")

# COMMAND ----------

# Generate the notebook content
notebook_content = generate_user_notebook(
    user_email=user_email,
    time_range_days=time_range_days,
    all_detections=all_detections
)

# Create output file name
output_filename = f"user_analysis_{user_email.replace('@', '_at_').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
output_path = os.path.join(get_repo_root(), "generated", output_filename)

# Save the notebook
w.workspace.upload(output_path, io.BytesIO(notebook_content.encode('utf-8')), format=ImportFormat.SOURCE, language=Language.PYTHON)

print()
print("=" * 60)
print("✅ User-specific notebook generated successfully!")
print(f"📁 Saved to: {output_path}")
print(f"📊 Will analyze {len(all_detections)} detections")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Detection Summary

# COMMAND ----------

# Display summary of what will be analyzed
detection_list = []
for name, det in all_detections.items():
    detection_list.append({
        "Detection": det.get('name', name),
        "Description": det.get('description', 'No description')[:100] + "..." if len(det.get('description', '')) > 100 else det.get('description', 'No description'),
        "File": f"{name}.py"
    })

summary_df = spark.createDataFrame(detection_list)

print(f"Detections that will be included in the analysis ({len(all_detections)} total):")
display(summary_df.orderBy(col("Detection")))
