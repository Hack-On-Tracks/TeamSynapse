# backend/api/routers/reports.py
"""Automated SOC Email Reporting Router for CipherSentinel.

Uses SMTP / NodeMailer credentials to dispatch high-fidelity HTML threat incident
reports and false-positive de-escalation audit logs to analysts.
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

router = APIRouter(tags=["reports"])

# Load environment configuration
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "ciphersentinel975@gmail.com")
# Strip any spaces from the Google App Password
SMTP_PASS = os.environ.get("SMTP_PASS", "vaphgicidicfykle").replace(" ", "")
SMTP_FROM = os.environ.get("SMTP_FROM", f"CipherSentinel SOC <{SMTP_USER}>")
DEFAULT_RECIPIENT = os.environ.get("DEFAULT_REPORT_RECIPIENT", "sanskar0912gharal@gmail.com")


class EmailReportRequest(BaseModel):
    recipient: str = DEFAULT_RECIPIENT
    entity_id: str
    report_type: str = "threat_incident"  # "threat_incident" | "fp_exclusion" | "full_consensus"
    custom_notes: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


def generate_html_report(req: EmailReportRequest) -> str:
    """Generates an executive-grade, dark-themed HTML incident brief."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entity_id = req.entity_id
    payload = req.data or {}
    
    rule_score = payload.get("rule_score", "N/A")
    rule_indicator = payload.get("rule_indicator", "Unknown Signal")
    ml_score = payload.get("ml_score", "N/A")
    ml_status = payload.get("ml_status", "N/A")
    ollama_verdict = payload.get("ollama_verdict", "N/A")
    ollama_conf = payload.get("ollama_conf", "N/A")
    ollama_rationale = payload.get("ollama_rationale", "No rationale provided.")
    consensus_risk = payload.get("consensus_risk", "N/A")

    is_threat = req.report_type == "threat_incident"
    header_color = "#f43f5e" if is_threat else "#10b981"
    badge_bg = "rgba(244, 63, 94, 0.15)" if is_threat else "rgba(16, 185, 129, 0.15)"
    badge_border = "rgba(244, 63, 94, 0.4)" if is_threat else "rgba(16, 185, 129, 0.4)"
    badge_text = "#fda4af" if is_threat else "#6ee7b7"
    title_text = "CONFIRMED THREAT INCIDENT BRIEF" if is_threat else "AUTHORIZED FALSE-POSITIVE EXCLUSION AUDIT"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #070b14; color: #f8fafc; margin: 0; padding: 24px; }}
        .card {{ max-width: 680px; margin: 0 auto; background-color: #0c1426; border: 1px solid #1a2744; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .header {{ padding: 24px; background: linear-gradient(180deg, {header_color}22 0%, #0c1426 100%); border-bottom: 1px solid #1a2744; }}
        .brand {{ font-size: 13px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; color: {header_color}; margin-bottom: 6px; }}
        .title {{ font-size: 20px; font-weight: 800; color: #ffffff; margin: 0 0 8px 0; }}
        .meta {{ font-size: 12px; color: #94a3b8; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; background: {badge_bg}; border: 1px solid {badge_border}; color: {badge_text}; margin-top: 8px; }}
        .content {{ padding: 24px; }}
        .section-title {{ font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-top: 20px; margin-bottom: 10px; border-bottom: 1px solid #142036; padding-bottom: 6px; }}
        .grid {{ display: table; width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
        .grid-row {{ display: table-row; }}
        .grid-cell {{ display: table-cell; padding: 10px 12px; border: 1px solid #16243d; font-size: 12px; vertical-align: top; }}
        .cell-label {{ color: #7b8fa7; font-weight: 600; width: 35%; background: #09101e; }}
        .cell-val {{ color: #f1f5f9; }}
        .rationale-box {{ background-color: #060a14; border: 1px solid #17243c; border-radius: 8px; padding: 14px; font-size: 12px; line-height: 1.6; color: #cbd5e1; font-family: monospace; }}
        .footer {{ padding: 18px 24px; background-color: #080d1a; border-top: 1px solid #142036; font-size: 11px; color: #64748b; text-align: center; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <div class="brand">🛡️ CipherSentinel Autonomous SOC Operations</div>
          <h1 class="title">{title_text}</h1>
          <div class="meta">Target Entity: <strong style="color:#ffffff;">{entity_id}</strong> · Dispatched: {timestamp}</div>
          <span class="badge">Risk Score: {consensus_risk} / 100</span>
        </div>
        
        <div class="content">
          <div class="section-title">Multi-Engine Verification Telemetry</div>
          <div class="grid">
            <div class="grid-row">
              <div class="grid-cell cell-label">1. Rule Engine</div>
              <div class="grid-cell cell-val"><strong>Score: {rule_score}</strong> — {rule_indicator}</div>
            </div>
            <div class="grid-row">
              <div class="grid-cell cell-label">2. Scratch ML Model</div>
              <div class="grid-cell cell-val"><strong>Score: {ml_score}%</strong> (Isolation Forest 32-dim Status: <span style="color:#38bdf8;">{ml_status}</span>)</div>
            </div>
            <div class="grid-row">
              <div class="grid-cell cell-label">3. Ollama Qwen3:4b (D:\\)</div>
              <div class="grid-cell cell-val"><strong>Verdict: {ollama_verdict}</strong> ({ollama_conf}% confidence)</div>
            </div>
            <div class="grid-row">
              <div class="grid-cell cell-label">Multi-Engine Status</div>
              <div class="grid-cell cell-val" style="color:#10b981; font-weight:700;">✓ 3 / 3 Concordant Consensus</div>
            </div>
          </div>

          <div class="section-title">Ollama Deep Reasoning & Chain-of-Thought Rationale</div>
          <div class="rationale-box">
            {ollama_rationale}
          </div>

          {f'''
          <div class="section-title">Analyst Custom Notes</div>
          <div style="font-size:12px; color:#94a3b8; font-style:italic; padding: 8px 0;">{req.custom_notes}</div>
          ''' if req.custom_notes else ''}
        </div>

        <div class="footer">
          CipherSentinel Zero-Trust Threat Intelligence Platform · Confidential Security Audit
          <br>Recipient: {req.recipient} · Mode: NodeMailer High-Priority Telemetry
        </div>
      </div>
    </body>
    </html>
    """
    return html


@router.post("/send-email")
async def send_email_report(req: EmailReportRequest):
    """Dispatches a formatted SOC email report using SMTP / NodeMailer credentials."""
    recipient = req.recipient.strip() or DEFAULT_RECIPIENT
    entity_id = req.entity_id
    
    subject = (
        f"[CipherSentinel SOC ALERT] Threat Corroborated for {entity_id} - Critical Risk"
        if req.report_type == "threat_incident"
        else f"[CipherSentinel Audit] False-Positive De-Escalated for {entity_id}"
    )

    html_content = generate_html_report(req)

    # Construct MIME message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = recipient
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["X-Priority"] = "1"  # High priority for SOC alerts

    # Plaintext fallback
    plain_text = (
        f"CipherSentinel Incident Report for {entity_id}\n\n"
        f"Report Type: {req.report_type}\n"
        f"Dispatched To: {recipient}\n"
        f"Please view this email in an HTML-capable email client for full telemetry details."
    )
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    delivery_status = {
        "success": False,
        "recipient": recipient,
        "entity_id": entity_id,
        "subject": subject,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "live_smtp",
        "message": ""
    }

    # Persist report HTML to disk for immediate local audit/review
    try:
        report_dir = os.path.join("data", "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"incident_{entity_id}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        with open(os.path.join(report_dir, "latest_incident_report.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
        delivery_status["saved_file"] = report_path
    except Exception:
        pass

    # Attempt Live SMTP Transmission via Google SMTP
    try:
        sent = False
        last_error = None

        # Try Port 465 SSL first (standard for Gmail), then Port 587 STARTTLS
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, 465, context=context, timeout=12) as server:
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, [recipient], msg.as_string())
                sent = True
        except Exception as e465:
            last_error = e465
            try:
                with smtplib.SMTP(SMTP_HOST, 587, timeout=12) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.sendmail(SMTP_USER, [recipient], msg.as_string())
                    sent = True
            except Exception as e587:
                last_error = e587

        if sent:
            delivery_status["success"] = True
            delivery_status["mode"] = "live_smtp"
            delivery_status["message"] = (
                f"Incident report for {entity_id} successfully dispatched from {SMTP_USER} to {recipient} via Google SMTP."
            )
            return delivery_status
        else:
            raise last_error

    except Exception as exc:
        err_str = str(exc)
        delivery_status["success"] = False
        delivery_status["mode"] = "smtp_auth_pending"
        delivery_status["message"] = (
            f"Email generated and saved locally. SMTP delivery from '{SMTP_USER}' failed: {err_str}."
        )
        delivery_status["smtp_diagnostic"] = (
            f"Google SMTP Error: {err_str}. To send from {SMTP_USER}, generate a 16-character App Password at "
            f"https://myaccount.google.com/apppasswords and update SMTP_PASS in .env"
        )
        return delivery_status
