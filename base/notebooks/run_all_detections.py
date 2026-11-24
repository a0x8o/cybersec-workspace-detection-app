# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC # Run all detection notebooks
# MAGIC
# MAGIC Example: 
# MAGIC
# MAGIC `workspace_dir="/Workspace/Users/<USER_EMAIL>/cybersec-workspace-detection-app/base/detections"
# MAGIC run_all_detections(workspace_dir=workspace_dir, earliest="2025-06-15 12:00:00", latest="2025-06-16 12:00:00")`

# COMMAND ----------

# workspace_dir is derived automatically from the current notebook path.
# Time window comes from the earliest/latest widgets (default: last 24 hours),
# so a scheduled run always scans a fresh window instead of a fixed one.
earliest, latest = get_time_range_from_widgets()
run_all_detections(earliest=earliest, latest=latest)
