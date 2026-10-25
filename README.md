# Web Application Security Toolkit

A Windows desktop toolkit for reviewing websites you own or have explicit permission to assess. It combines read-only web checks with separate network and security-layer modules. Findings are indicators for review, not proof that a vulnerability can be exploited.

## Start the app

From PowerShell in this folder, create an environment if needed, install the packages, and launch the login window:

```powershell
python -m venv .venv
\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python gui/login.py
```

The app asks you to confirm authorization before a scan starts. Use a test or staging site when possible.

## Scan profiles

- **Quick** runs reconnaissance.
- **Standard** runs reconnaissance and security configuration checks.
- **Deep** runs every module in the Other Modules workspace, including the website crawl, technology checks, WAF indicators, and the fixed-list port and latency checks.
- **Custom** lets you choose individual modules allowed for your account.
- **Layers** is a separate scan where you choose the security layers to review.

The website crawl stays on the exact same origin as the target, respects `robots.txt` when it can read it, follows up to 25 pages at a maximum link depth of 2, and reads at most 512 KB from each page. It does not follow query parameters or fragments, submit forms, or send attack payloads. It reports links, forms, HTTP status, and review indicators such as password forms using HTTP or GET. A missing CSRF token hint is informational because protection may be implemented elsewhere.

## Reports and history

Scans appear in the app's history. When the account can generate reports, the app saves a readable `.txt` report and a versioned `.json` report in `reports/`. The current scan screen also has **EXPORT JSON** so you can save structured results somewhere else for later analysis.

The JSON report has a top-level `schema_version`, scan metadata, summary, and results. Reports and history are stored locally in this project folder; treat them as potentially sensitive because they include target URLs and observed page details.

## Project map

- `gui/` contains the login, dashboard, layer scanner, and visuals.
- `modules/` contains the scanners, reporting, recommendations, and account controls.
- `reports/` contains generated scan reports.
- `gui_scan_history.json` stores GUI scan history.

The toolkit performs limited unauthenticated checks. It does not verify account permissions, authenticated workflows, or every application route. Review findings manually and use a dedicated, authorized test environment for checks that could affect application data.
