
from modules.auth_simulator import (
    simulate_authentication,
    detect_repeated_failures,
)
import csv
import io
from datetime import datetime, timezone
from modules.recon import scan_local_target
from modules.nmap_scanner import run_nmap_scan
from modules.attack_mapping import map_all_findings
from modules.pdf_generator import generate_incident_pdf

from modules.reporting import (
    save_auth_report,
    save_recon_report,
    save_consolidated_report,
)


import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Cyber Attack Simulation Lab",
    page_icon="🛡️",
    layout="wide",
)

if "events" not in st.session_state:
    st.session_state.events = []

st.title("🛡️ Cyber Attack Simulation Lab")
st.caption(
    "Controlled security simulations • Authorized lab testing • "
    "Evidence and reporting"
)

st.info(
    "Simulation mode: the scenarios below use mock data. "
    "They do not attack real accounts, systems, or networks."
)

# Summary metrics
events = st.session_state.events
df = pd.DataFrame(events)

col1, col2, col3 = st.columns(3)
col1.metric("Scenarios executed", len(events))
col2.metric(
    "Findings requiring review",
    sum(e["status"] == "REVIEW" for e in events),
)
col3.metric(
    "Unique scenarios",
    len({e["scenario"] for e in events}),
)

st.divider()
st.subheader("Simulation Control Panel")

scenario = st.selectbox(
    "Choose a scenario",
    [
        "Mock authentication guessing",
        "Input validation demonstration",
        "Synthetic suspicious activity",
    ],
)

st.write("**Scenario description**")

descriptions = {
    "Mock authentication guessing": (
        "Tests a local mock login function using synthetic attempts "
        "and demonstrates how repeated failures can be identified."
    ),
    "Input validation demonstration": (
        "Tests example inputs against a simple validation policy "
        "without sending requests to a real application."
    ),
    "Synthetic suspicious activity": (
        "Creates simulated security events for reviewing detection "
        "and reporting workflows."
    ),
}
st.write(descriptions[scenario])

if st.button("Run simulation", type="primary"):
    now = datetime.now(timezone.utc).isoformat()

    if scenario == "Mock authentication guessing":
        details = (
            "Simulation generated 5 mock failed logins. "
            "No real authentication service was contacted."
        )
        status = "REVIEW"
        severity = "MEDIUM"

    elif scenario == "Input validation demonstration":
        details = (
            "Mock validation checks completed. Review the example "
            "policy results before applying them to a real application."
        )
        status = "REVIEW"
        severity = "LOW"

    else:
        details = (
            "Synthetic suspicious activity event created for "
            "demonstration and reporting."
        )
        status = "REVIEW"
        severity = "MEDIUM"

    st.session_state.events.append({
        "timestamp": now,
        "scenario": scenario,
        "severity": severity,
        "status": status,
        "details": details,
    })
    st.success("Simulation completed.")
    st.rerun()


st.divider()
st.subheader("Authentication Simulation")

st.caption(
    "Synthetic events only. No real accounts are accessed."
)

attempts = st.slider(
    "Number of simulated login attempts",
    min_value=1,
    max_value=20,
    value=5,
)

failures = st.slider(
    "Number of simulated failures",
    min_value=0,
    max_value=20,
    value=5,
)

threshold = st.slider(
    "Detection threshold",
    min_value=1,
    max_value=10,
    value=3,
)

if failures > attempts:
    st.warning("Failures cannot exceed total attempts.")
else:
    if st.button("Run Authentication Simulation"):
        auth_events = simulate_authentication(
            attempts=attempts,
            failures=failures,
        )

        findings = detect_repeated_failures(
            auth_events,
            threshold=threshold,
        )

        st.session_state["auth_events"] = auth_events
        st.session_state["auth_findings"] = findings
        report_path = save_auth_report(auth_events, findings)
        st.success(f"Report saved to: {report_path}")

    auth_events = st.session_state.get("auth_events", [])
    auth_findings = st.session_state.get("auth_findings", [])

    if auth_events:
        st.markdown("**Generated authentication events**")
        st.dataframe(
            pd.DataFrame(auth_events),
            use_container_width=True,
            hide_index=True,
        )

    if auth_findings:
        st.error("Repeated authentication failures detected.")
        st.dataframe(
            pd.DataFrame(auth_findings),
            use_container_width=True,
            hide_index=True,
        )
    elif auth_events:
        st.success("No repeated-failure threshold was triggered.")

st.divider()
st.subheader("Local Network Reconnaissance")

st.caption(
    "Checks an allowlist of TCP ports on 127.0.0.1 only."
)

if st.button("Run Local Port Checks"):
    recon_results = scan_local_target("127.0.0.1")
    st.session_state["recon_results"] = recon_results

    report_path = save_recon_report(recon_results)
    st.success(f"Reconnaissance report saved: {report_path}")

recon_results = st.session_state.get("recon_results", [])

if recon_results:

    recon_df = pd.DataFrame(recon_results)
    st.dataframe(
        recon_df,
        use_container_width=True,
        hide_index=True,
    )

    open_count = sum(
        item["state"] == "open" for item in recon_results
    )
    st.metric("Open ports found", open_count)
    st.download_button(
        "Download Reconnaissance JSON",
        data=__import__("json").dumps(
            recon_results, indent=2
        ),
        file_name="recon_results.json",
        mime="application/json",
    )
else:
    st.info("No reconnaissance run yet.")

st.divider()

st.divider()
st.header("Security Findings Summary")


st.divider()
st.subheader("MITRE ATT&CK Mapping")

auth_findings = st.session_state.get("auth_findings", [])

attack_mappings = map_all_findings(auth_findings)

if attack_mappings:
    attack_df = pd.DataFrame(attack_mappings)

    st.dataframe(
        attack_df,
        use_container_width=True,
        hide_index=True,
    )

    for mapping in attack_mappings:
        if mapping.get("mapped"):
            st.markdown(
                f"**{mapping['technique_id']} — "
                f"{mapping['technique_name']}**"
            )
            st.write(f"Tactic: {mapping['tactic']}")
            st.write(
                f"Description: {mapping['description']}"
            )
            st.info(
                f"Recommendation: {mapping['recommendation']}"
            )
else:
    st.info(
        "Run the authentication simulation to generate "
        "findings for ATT&CK mapping."
    )


st.divider()
st.subheader("Nmap Network Scanner")

st.caption(
    "Authorized localhost scanning only. "
    "Uses Nmap service detection on five allowlisted TCP ports."
)

if st.button("Run Nmap Scan"):
    try:
        nmap_results = run_nmap_scan("127.0.0.1")
        st.session_state["nmap_results"] = nmap_results
        st.success("Nmap scan completed successfully.")
    except (RuntimeError, ValueError) as error:
        st.error(f"Nmap scan failed: {error}")

nmap_results = st.session_state.get("nmap_results", [])

if nmap_results:
    nmap_df = pd.DataFrame(nmap_results)

    st.dataframe(
        nmap_df,
        use_container_width=True,
        hide_index=True,
    )

    nmap_open = sum(
        item["state"] == "open"
        for item in nmap_results
    )

    st.metric("Nmap Open Ports", nmap_open)

    st.download_button(
        "Download Nmap Results",
        data=__import__("json").dumps(
            nmap_results, indent=2
        ),
        file_name="nmap_scan_results.json",
        mime="application/json",
    )
else:
    st.info("No Nmap scan performed yet.")


severity_counts = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
}

for finding in st.session_state.get("auth_findings", []):
    severity = finding.get("severity", "LOW").upper()
    if severity in severity_counts:
        severity_counts[severity] += 1

sev1, sev2, sev3 = st.columns(3)

with sev1:
    st.metric("High Severity", severity_counts["HIGH"])

with sev2:
    st.metric("Medium Severity", severity_counts["MEDIUM"])

with sev3:
    st.metric("Low Severity", severity_counts["LOW"])

auth_findings = st.session_state.get("auth_findings", [])

recon_results = st.session_state.get("recon_results", [])

total_auth_findings = len(auth_findings)
open_ports = sum(
    result["state"] == "open"
    for result in recon_results
)

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Authentication Findings", total_auth_findings)

with col2:
    st.metric("Open Local Ports", open_ports)

with col3:
    st.metric("Ports Checked", len(recon_results))

if auth_findings:
    st.subheader("Authentication Alerts")
    st.dataframe(
        pd.DataFrame(auth_findings),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No authentication findings available yet.")

if recon_results:
    st.subheader("Local Reconnaissance Results")
    st.dataframe(
        pd.DataFrame(recon_results),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("Run the local port checks to view reconnaissance results.")

st.divider()
st.subheader("Consolidated Incident Report")

if st.button("Generate Consolidated Report"):
    auth_findings = st.session_state.get("auth_findings", [])
    recon_results = st.session_state.get("recon_results", [])

    attack_mappings = map_all_findings(auth_findings)

report_path = save_consolidated_report(
    auth_findings,
    recon_results,
    attack_mappings=attack_mappings,
)


    import json
    with open(report_path, "r", encoding="utf-8") as report_file:
        report_data = json.load(report_file)

    st.success("Consolidated incident report generated!")

    st.download_button(
        "Download Consolidated JSON Report",
        data=json.dumps(report_data, indent=2),
        file_name="consolidated_incident_report.json",
        mime="application/json",
    )


st.divider()
st.subheader("PDF Incident Report")

if st.button("Generate PDF Incident Report"):
    auth_findings = st.session_state.get("auth_findings", [])
    recon_results = st.session_state.get("recon_results", [])

    attack_mappings = map_all_findings(auth_findings)

    pdf_path = generate_incident_pdf(
        auth_findings,
        recon_results,
        attack_mappings,
    )

    with open(pdf_path, "rb") as pdf_file:
        pdf_data = pdf_file.read()

    st.success("PDF incident report generated successfully!")

    st.download_button(
        "Download PDF Incident Report",
        data=pdf_data,
        file_name="cybersecurity_incident_report.pdf",
        mime="application/pdf",
    )


st.subheader("Simulation Evidence")

if not events:
    st.write("No simulations executed yet. Select a scenario above.")
else:
    df = pd.DataFrame(st.session_state.events)
    st.dataframe(df, use_container_width=True, hide_index=True)

    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False, quoting=csv.QUOTE_MINIMAL)

    st.download_button(
        "Download findings as CSV",
        data=csv_buffer.getvalue().encode("utf-8"),
        file_name="simulation_findings.csv",
        mime="text/csv",
    )

    json_data = df.to_json(orient="records", indent=2)
    st.download_button(
        "Download findings as JSON",
        data=json_data.encode("utf-8"),
        file_name="simulation_findings.json",
        mime="application/json",
    )

if st.button("Clear session results"):
    st.session_state.events = []
    st.rerun()

st.caption(
    "This starter version uses session-only results. "
    "Restarting the session may clear the findings."
)
