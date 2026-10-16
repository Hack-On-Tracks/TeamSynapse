// scripts/nodemailer_report_dispatcher.mjs
/**
 * CipherSentinel Autonomous SOC NodeMailer Dispatcher
 * Dispatches threat incident briefs and false-positive audit logs using Google SMTP.
 */

import nodemailer from 'nodemailer';

const SMTP_CONFIG = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '465'),
  secure: true,
  auth: {
    user: process.env.SMTP_USER || 'sanskar0912gharal@gmail.com',
    pass: (process.env.SMTP_PASS || 'vaphgicidicfykle').replace(/\s+/g, ''),
  },
};

const DEFAULT_RECIPIENT = process.env.DEFAULT_REPORT_RECIPIENT || 'sanskar0912gharal@gmail.com';

export async function sendNodeMailerReport({
  to = DEFAULT_RECIPIENT,
  entityId = 'EMP006',
  reportType = 'threat_incident',
  details = {},
}) {
  console.log(`[NodeMailer] Initializing transport for ${SMTP_CONFIG.auth.user} ...`);
  const transporter = nodemailer.createTransport(SMTP_CONFIG);

  const isThreat = reportType === 'threat_incident';
  const subject = isThreat
    ? `[CipherSentinel SOC ALERT] Threat Corroborated for ${entityId} - Critical Risk`
    : `[CipherSentinel Audit] False-Positive De-Escalated for ${entityId}`;

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #080c16; color: #f8fafc; padding: 28px; border-radius: 14px; border: 1px solid #1e293b; max-width: 650px;">
      <div style="border-bottom: 1px solid #1e2c4d; padding-bottom: 16px; margin-bottom: 20px;">
        <span style="font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; color: ${isThreat ? '#f43f5e' : '#10b981'};">🛡️ CipherSentinel SOC Operations</span>
        <h2 style="margin: 8px 0 4px; font-size: 20px; color: #ffffff;">${isThreat ? 'High-Priority Threat Incident Brief' : 'Authorized Operational Exclusion Audit'}</h2>
        <p style="margin: 0; font-size: 12px; color: #94a3b8;">Entity: <strong style="color: #ffffff;">${entityId}</strong> · Dispatched via NodeMailer</p>
      </div>

      <div style="background: #0f1c38; border: 1px solid #203358; border-radius: 10px; padding: 18px; margin-bottom: 20px;">
        <p style="margin: 6px 0; font-size: 13px;"><strong>1. Rule Engine:</strong> Score ${details.ruleScore || 83.75} (${details.ruleIndicator || 'R1_VOLUME_SPIKE'})</p>
        <p style="margin: 6px 0; font-size: 13px;"><strong>2. Scratch ML Model:</strong> Score ${details.mlScore || 53.4}% (Status: ${details.mlStatus || 'OUTLIER'})</p>
        <p style="margin: 6px 0; font-size: 13px;"><strong>3. Ollama Qwen3:4b:</strong> ${details.ollamaVerdict || 'CONFIRMED_THREAT'} (${details.ollamaConf || 96}% confidence)</p>
        <p style="margin: 6px 0; font-size: 13px; color: ${isThreat ? '#f43f5e' : '#10b981'};"><strong>Triangulated Risk:</strong> ${details.consensusRisk || 88.7} / 100</p>
      </div>

      <div style="background: #060a14; border: 1px solid #17243c; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 11.5px; color: #cbd5e1; line-height: 1.6; margin-bottom: 20px;">
        ${details.rationale || 'Consensus triangulation: Malicious behavioral patterns confirmed across all 3 independent analytical engines.'}
      </div>

      <div style="font-size: 11px; color: #64748b; text-align: center; border-top: 1px solid #142036; padding-top: 14px;">
        CipherSentinel Zero-Trust SOC Intelligence Platform · Confidential Telemetry
      </div>
    </div>
  `;

  try {
    const info = await transporter.sendMail({
      from: `"CipherSentinel SOC" <${SMTP_CONFIG.auth.user}>`,
      to,
      subject,
      html,
    });
    console.log(`[+] Email successfully sent via NodeMailer! Message ID: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.warn(`[-] NodeMailer delivery error:`, err.message);
    return { success: false, error: err.message };
  }
}

// Allow direct CLI execution: node scripts/nodemailer_report_dispatcher.mjs
if (process.argv[1]?.endsWith('nodemailer_report_dispatcher.mjs')) {
  const target = process.argv[2] || DEFAULT_RECIPIENT;
  console.log(`Triggering NodeMailer report dispatch to ${target}...`);
  sendNodeMailerReport({ to: target }).then((res) => {
    console.log('Result:', res);
  });
}
