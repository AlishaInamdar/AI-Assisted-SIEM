# AI-Assisted SIEM — Integrated Incident Reporting

## Run locally (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The original dashboard is retained. In **Reports & Export**, use the new incident-report links and severity PDF downloads.

## Reporting routes

- `/incidents` — searchable/filterable incident list
- `/reports/overall` — overall aggregate report
- `/reports/severity/LOW` — change LOW to MEDIUM, HIGH, or CRITICAL for severity-specific aggregate reports
- `/reports/download/overall` — detailed PDF for all incidents
- `/reports/download/severity/LOW` — change LOW to MEDIUM, HIGH, or CRITICAL for severity-specific detailed PDFs
- `/reports/export/overall` and `/reports/export/severity/LOW` — CSV exports
- `/incident/<incident_id>` — detailed incident page

Each PDF contains one formatted incident report per page. The reporting adapter accepts dashboard alert CSV rows and rule-engine rows with `rules` and `reasons`. The individual incident page has a CSV download and print action.

## Important limitations

This is a local academic prototype using CSV/synthetic data. It does not connect to live security infrastructure or automatically block attacks. Check alert content before using reports operationally.
