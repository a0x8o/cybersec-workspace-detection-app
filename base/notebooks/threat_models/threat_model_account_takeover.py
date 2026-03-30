# Databricks notebook source
# MAGIC %md
# MAGIC # Threat Model: Account Takeover or Compromise
# MAGIC
# MAGIC ## Risk Description
# MAGIC
# MAGIC Databricks is a general-purpose compute platform that customers can set up to access critical data sources. If credentials belonging to a user were compromised by phishing, brute force, or other methods, an attacker might get access to all of the data accessible from the environment.
# MAGIC
# MAGIC *Source: Databricks Security Best Practices for AWS (Version 2.2 - December 2025)*
# MAGIC
# MAGIC ## Detection Coverage
# MAGIC
# MAGIC Generates investigation notebook containing detections relevant to:
# MAGIC - Credential theft and reuse
# MAGIC - Session hijacking
# MAGIC - MFA bypass attempts
# MAGIC - Anomalous authentication patterns
# MAGIC - Privilege escalation
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

run_threat_model_investigation("account_takeover")

# COMMAND ----------
