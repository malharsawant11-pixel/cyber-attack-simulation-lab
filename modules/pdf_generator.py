
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def generate_incident_pdf(
    auth_findings,
    recon_results,
    attack_mappings=None,
    output_path="reports/incident_report.pdf",
):
    """Generate a PDF cybersecurity investigation report."""

    if attack_mappings is None:
        attack_mappings = []

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    document = SimpleDocTemplate(
        str(output_file),
        pagesize=A4,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D"),
    )

    story = []

    story.append(Paragraph(
        "CYBERSECURITY INCIDENT INVESTIGATION REPORT",
        title_style,
    ))
    story.append(Spacer(1, 12))

    generated_at = datetime.now(timezone.utc).isoformat()

    story.append(Paragraph(
        f"<b>Generated:</b> {generated_at}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 16))

    # Investigation summary
    story.append(Paragraph(
        "1. Investigation Summary",
        styles["Heading2"],
    ))

    open_ports = sum(
        result.get("state") == "open"
        for result in recon_results
    )

    summary_data = [
        ["Metric", "Result"],
        ["Authentication Findings", str(len(auth_findings))],
        ["Ports Checked", str(len(recon_results))],
        ["Open Ports", str(open_ports)],
        [
            "Mapped ATT&CK Techniques",
            str(sum(m.get("mapped", False) for m in attack_mappings)),
        ],
    ]

    summary_table = Table(summary_data, colWidths=[3.2 * inch, 2.5 * inch])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 16))

    # Authentication findings
    story.append(Paragraph(
        "2. Authentication Findings",
        styles["Heading2"],
    ))

    if auth_findings:
        auth_data = [["Source", "Failed Attempts", "Severity", "Finding"]]

        for finding in auth_findings:
            auth_data.append([
                str(finding.get("source", "Unknown")),
                str(finding.get("failed_attempts", 0)),
                str(finding.get("severity", "Unknown")),
                str(finding.get("finding", "Unknown")),
            ])

        auth_table = Table(auth_data, repeatRows=1)
        auth_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(auth_table)
    else:
        story.append(Paragraph(
            "No authentication findings recorded.",
            styles["Normal"],
        ))

    story.append(Spacer(1, 16))

    # Reconnaissance results
    story.append(Paragraph(
        "3. Nmap / Reconnaissance Results",
        styles["Heading2"],
    ))

    if recon_results:
        recon_data = [["Target", "Port", "Protocol", "State", "Service"]]

        for result in recon_results:
            recon_data.append([
                str(result.get("target", "Unknown")),
                str(result.get("port", "Unknown")),
                str(result.get("protocol", "TCP")),
                str(result.get("state", "Unknown")),
                str(result.get("service", "Unknown")),
            ])

        recon_table = Table(recon_data, repeatRows=1)
        recon_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(recon_table)
    else:
        story.append(Paragraph(
            "No reconnaissance results recorded.",
            styles["Normal"],
        ))

    story.append(Spacer(1, 16))

    # MITRE ATT&CK mapping
    story.append(Paragraph(
        "4. MITRE ATT&CK Mapping",
        styles["Heading2"],
    ))

    mapped_findings = [
        mapping for mapping in attack_mappings
        if mapping.get("mapped")
    ]

    if mapped_findings:
        for mapping in mapped_findings:
            story.append(Paragraph(
                f"<b>{mapping.get('technique_id', 'Unknown')} - "
                f"{mapping.get('technique_name', 'Unknown')}</b>",
                styles["Normal"],
            ))
            story.append(Paragraph(
                f"Tactic: {mapping.get('tactic', 'Unknown')}",
                styles["Normal"],
            ))
            story.append(Paragraph(
                f"Description: {mapping.get('description', '')}",
                styles["Normal"],
            ))
            story.append(Paragraph(
                f"Recommendation: {mapping.get('recommendation', '')}",
                styles["Normal"],
            ))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph(
            "No mapped ATT&CK techniques available.",
            styles["Normal"],
        ))

    story.append(Spacer(1, 20))

    story.append(Paragraph(
        "<b>Report Scope:</b> Educational cybersecurity lab using "
        "synthetic authentication events and restricted localhost "
        "reconnaissance. Findings are not proof of malicious activity.",
        styles["Italic"],
    ))

    document.build(story)

    return output_file
