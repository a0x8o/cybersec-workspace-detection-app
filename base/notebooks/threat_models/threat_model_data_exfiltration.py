# Databricks notebook source
# MAGIC %md
# MAGIC # Threat Model: Data Exfiltration
# MAGIC
# MAGIC ## Risk Description
# MAGIC
# MAGIC If a malicious user or an attacker is able to log into a customer's environment, they may be able to exfiltrate sensitive data and then store it, sell it, or ransom it.
# MAGIC
# MAGIC *Source: Databricks Security Best Practices for AWS (Version 2.2 - December 2025)*
# MAGIC
# MAGIC ## Detection Coverage
# MAGIC
# MAGIC Generates investigation notebook containing detections relevant to:
# MAGIC - Unauthorized data movement and extraction
# MAGIC - Credential and token abuse
# MAGIC - Secret scanning activity
# MAGIC - High-volume data access patterns
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

run_threat_model_investigation("data_exfiltration")

# COMMAND ----------
