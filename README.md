# 🧠 SOCMate — Mini Security Operations Center

SOCMate is a Python-based Mini Security Operations Center designed to simulate the basic workflow of a Security Operations Center (SOC).

It analyzes security logs, detects suspicious activity, calculates risk levels, stores incidents in SQLite, generates security alerts, and presents the results through an interactive Flask dashboard.

---

## 🚀 Features

- 🔍 Security log analysis using Python and Pandas
- 🚨 Brute-force login detection
- 🔐 Suspicious login detection
- 👥 Multi-user attack detection
- ⚠️ Privilege change detection
- 🔑 Successful login after repeated failures detection
- 📊 Risk scoring and risk-level classification
- 🚨 Automated security alerts
- 🗄️ SQLite incident database
- 🔎 Incident investigation page
- 🔄 Incident status workflow
- 📈 Threat analytics
- 🌐 Interactive SOC dashboard
- 🌐 3D SOC network visualization
- 🧪 Automated testing with Pytest

---

## 🏗️ Architecture

```text
Security Logs
      ↓
   Log Parser
      ↓
Threat Detection
      ↓
   Risk Scoring
      ↓
 SQLite Database
      ↓
 Flask SOC Dashboard
      ↓
Incident Investigation