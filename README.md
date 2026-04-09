# Sentinel Rule Viewer

A Streamlit dashboard for visualising exported Microsoft Sentinel analytics rules.

## Features

**Overview tab**
- Key metrics: total rules, enabled/disabled counts, high-severity count
- Severity breakdown bar chart (High / Medium / Low / Informational)
- Rule type breakdown (Scheduled, NRT, Fusion, etc.)
- MITRE ATT&CK tactics breakdown

**Rules tab**
- Searchable, filterable table of all rules
- Filter by severity, rule type, and enabled status
- Select any rule to inspect its full metadata and KQL query

## Requirements

- Python 3.9+
- streamlit
- pandas
- altair

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install streamlit pandas altair
```

## Running

```bash
streamlit run app.py
```

Then open [http://localhost:8501](http://localhost:8501) in your browser.

## Usage

Export your Sentinel analytics rules as JSON from the Azure portal or via the Azure CLI:

```bash
az sentinel alert-rule list \
  --resource-group <resource-group> \
  --workspace-name <workspace> \
  > sentinel_rules.json
```

Upload the JSON file in the app to populate the dashboard.
