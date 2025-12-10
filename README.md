# OSINT-Recon 🌐

A compact, demo-friendly Streamlit app for passive OSINT reconnaissance: domain subdomain discovery (crt.sh), WHOIS metadata, IP geolocation (ip-api), threaded port checks, interactive network graph (PyVis), and quick PDF/PPTX exports. Built for authorized testing, learning, and prototype reporting.

---

## Table of contents
- [Why this exists](#why-this-exists)
- [Features](#features)
- [Tech stack](#tech-stack)
- [Quick start](#quick-start)
- [Usage examples](#usage-examples)
- [Files created / demo data](#files-created--demo-data)
- [Notes, limits & safety](#notes-limits--safety)
- [Development tips](#development-tips)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists
This repo is a lightweight, practical OSINT toolkit for:
- teaching and learning passive recon workflows,
- producing quick, readable PDF/PPTX summaries for reports,
- prototyping an attack-surface visualization that’s easy to extend.

It intentionally favors safety and demo data so you can test offline and avoid noisy active scanning.

---

## Features
- 🔎 Domain recon via `crt.sh` (subdomain enumeration)
- 🧾 WHOIS metadata extraction
- 📍 IP geolocation via `ip-api`
- 🔌 Threaded, single-connection port checks for common ports
- 🕸️ Interactive attack-surface graph saved as an HTML (PyVis)
- 📄 PDF and PPTX report generation (FPDF & python-pptx)
- ⚙️ Demo mode with sample reputation file to mark "bad" domains/IPs
- ✅ Streamlit UI with tabs for Domain, IP, and Demo utilities

---

## Tech stack
- Python 3.9+
- Streamlit (UI)
- requests, python-whois
- pandas, pyvis
- fpdf, python-pptx
- concurrent.futures (threaded port checks)

---

## Quick start

1. **Clone**
```bash
git clone https://github.com/<your-username>/osint-reconsuite-v3.git
cd osint-reconsuite-v3
```

2. **Create & activate virtual environment**
```bash
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows (PowerShell)
venv\\Scripts\\Activate.ps1
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

**Recommended `requirements.txt`** is provided in this repo (see file).

4. **Run the app**
```bash
streamlit run app.py
# or the filename you saved the provided script as (e.g., recon_app.py)
```

Open the local URL Streamlit prints (usually `http://localhost:8501`).

---

## Usage examples

### Domain Recon
- Enter a target domain (e.g., `tesla.com`) and click **Start Domain Scan**.
- The app:
  - queries `crt.sh` for subdomains,
  - fetches WHOIS,
  - draws an interactive PyVis graph you can explore,
  - generates downloadable PDF and PPTX summaries.

### IP Intel
- Enter an IP (e.g., `8.8.8.8`) and click **Scan IP Address**.
- The app:
  - fetches location and ISP info from `ip-api`,
  - tries PTR (reverse DNS),
  - runs quick threaded connection checks on common ports,
  - shows a simple map, port table, and produces PDF/PPTX exports.

---

## Files created / demo data
- `demo_reputation.json` — local reputation with `bad_ips` and `bad_domains`.
- `demo/` — sample files (e.g., `sample_subdomains.txt`, `sample_ip.json`).
- Temporary PyVis HTML files (written to system temp dir).
- Generated reports: `Recon_Report_*.pdf` and `Recon_Summary_*.pptx` (saved to working dir).

---

## Notes, limits & safety
- **Authorized use only** — This tool is for educational, defensive, or authorized assessments. Do not scan systems without permission.
- **Passive vs active:** Subdomain enumeration and WHOIS are passive; port checks use active connect attempts (limited, single-connection checks).
- **API limits & reliability:** The app uses public endpoints (crt.sh and `ip-api`). They may rate-limit or block heavy usage. Respect their TOS.
- **WHOIS behavior:** If WHOIS fails, check installed `whois` package name and platform dependencies.
- **Platform privileges:** Avoid scanning large port ranges or running scans as privileged users.
- **Privacy & logging:** The app writes demo files and generated reports to the working directory. Remove sensitive output when needed.

---

## Development tips & extension ideas
- Use a paid IP geolocation provider (MaxMind, IPinfo) for production-grade accuracy.
- Replace the simple threaded connect scan with an async approach for larger scans (careful with limits).
- Add API-key-backed integrations: Shodan, Censys, VirusTotal (ensure TOS compliance).
- Add authentication if exposing the UI beyond localhost.
- Unit tests for parsing, export functions, and graph generation.

---

## Contributing
- Open an issue for bugs or feature requests.
- Send small, focused PRs. Include tests when possible.
- Keep UI changes separate from core logic for easier review.

---

## License
Choose a license (e.g., MIT) and add a `LICENSE` file. This repo ships example/demo data only.
