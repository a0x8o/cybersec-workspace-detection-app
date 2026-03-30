# Databricks notebook source
# MAGIC %md
# MAGIC # Threat Model: Resource Abuse
# MAGIC
# MAGIC ## Risk Description
# MAGIC
# MAGIC Databricks can deploy large amounts of compute power. As such, it could be a valuable target for crypto mining if a customer's user account were compromised.
# MAGIC
# MAGIC *Source: Databricks Security Best Practices for AWS (Version 2.2 - December 2025)*
# MAGIC
# MAGIC ## Detection Coverage
# MAGIC
# MAGIC Generates investigation notebook containing detections relevant to:
# MAGIC - Unusual compute and resource usage patterns
# MAGIC - Suspicious account creation
# MAGIC - Anomalous token generation
# MAGIC - Crypto mining indicators
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

run_threat_model_investigation("resource_abuse")

# COMMAND ----------
