# Cyber Attack Simulation Lab

A Python-based cybersecurity lab that simulates authentication attacks, detects repeated login failures, performs restricted localhost reconnaissance, and generates structured security investigation reports through a Streamlit dashboard.

## Project Overview

The Cyber Attack Simulation Lab is designed for defensive cybersecurity learning and investigation. It combines synthetic authentication-event simulation, basic TCP port checks on an explicitly allowlisted localhost target, automated detection logic, and JSON-based reporting.

## Key Features

- **Authentication Simulation:** Generates synthetic successful and failed login events.
- **Failure Detection:** Identifies repeated authentication failures using configurable thresholds.
- **Severity Classification:** Categorizes findings as High, Medium, or Low.
- **Local Reconnaissance:** Checks five allowlisted TCP ports on `127.0.0.1`.
- **Security Dashboard:** Displays authentication findings and reconnaissance results using Streamlit.
- **JSON Reporting:** Generates authentication, reconnaissance, and consolidated investigation reports.
- **Automated Testing:** Includes unit tests for simulation, detection, reconnaissance, and reporting.

## Technology Stack

- Python
- Streamlit
- Pandas
- Socket Programming
- JSON
- Unittest
- Kali Linux
- Git and GitHub

## Project Structure

```text
cyber-attack-simulation-lab/
├── app.py
├── modules/
│   ├── __init__.py
│   ├── auth_simulator.py
│   ├── recon.py
│   └── reporting.py
├── data/
├── reports/
│   └── .gitkeep
├── tests/
│   ├── test_auth_simulator.py
│   ├── test_recon.py
│   └── test_reporting.py
├── .gitignore
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/cyber-attack-simulation-lab.git
cd cyber-attack-simulation-lab
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install streamlit pandas
```

## Run the Application

```bash
python -m streamlit run app.py
```

Open the dashboard in your browser:

```text
http://localhost:8501
```

## Run Automated Tests

```bash
python -m unittest discover -s tests -v
```

**Current test status:** 13 tests passing.

## Generated Reports

The application can generate:

- `auth_simulation_report.json`
- `recon_report.json`
- `consolidated_incident_report.json`

These reports are generated locally and excluded from Git by default.

## Security Scope and Limitations

- Authentication events are synthetic; no real user accounts are attacked.
- Reconnaissance is restricted to `127.0.0.1`.
- Only the explicitly allowlisted TCP ports are checked.
- The project is an educational simulation, not a production security monitoring system.
- Do not modify the target restrictions to scan systems without explicit authorization.

## Future Enhancements

- Advanced detection rules and correlation.
- Interactive investigation timelines.
- Additional log-source support.
- PDF incident report generation.
- Improved dashboard visualizations.

## Author

**Malhar Sawant**

Cybersecurity Analyst Portfolio Project
