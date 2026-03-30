# Databricks notebook source
# MAGIC %md
# MAGIC # Threat Model: Potential Compromise of Databricks
# MAGIC
# MAGIC ## Risk Description
# MAGIC
# MAGIC Security-minded customers sometimes voice a concern that Databricks itself might be compromised, which could result in the compromise of their environment.
# MAGIC
# MAGIC *Source: Databricks Security Best Practices for AWS (Version 2.2 - December 2025)*
# MAGIC
# MAGIC ## Detection Coverage
# MAGIC
# MAGIC Generates investigation notebook containing detections relevant to:
# MAGIC - Databricks employee access monitoring
# MAGIC - Account-level configuration changes
# MAGIC - SSO configuration tampering
# MAGIC - Administrative privilege changes
# MAGIC
# MAGIC **Parameters:**
# MAGIC - `time_range_days`: Behavioral detection window (default: 30)
# MAGIC - `binary_time_range_hours`: Binary detection window (default: 24)

# COMMAND ----------

dbutils.widgets.text("time_range_days", "30", "Behavioral Window (days)")
dbutils.widgets.text("binary_time_range_hours", "24", "Binary Window (hours)")

# COMMAND ----------

# MAGIC %pip install pyyaml

# COMMAND ----------

# MAGIC %run ../../../lib/threat_model_mappings

# COMMAND ----------

# MAGIC %run ../../../lib/notebook_generator_base

# COMMAND ----------

run_threat_model_investigation("databricks_compromise")

# COMMAND ----------
