import nodemailer from 'nodemailer';

async function testMail() {
  console.log('Testing nodemailer with Gmail SMTP...');
  
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // SSL
    auth: {
      user: 'ciphersentinel975@gmail.com',
      pass: 'vaphgicidicfykle',
    },
  });

  try {
    const verified = await transporter.verify();
    console.log('[+] SMTP Connection verified successfully:', verified);

    const info = await transporter.sendMail({
      from: '"CipherSentinel SOC Security" <ciphersentinel975@gmail.com>',
      to: 'sanskar0912gharal@gmail.com',
      subject: '[CipherSentinel] NodeMailer Integration Verified - Security Operations',
      html: `
        <div style="font-family: Arial, sans-serif; background: #080c16; color: #f8fafc; padding: 24px; border-radius: 12px; border: 1px solid #1e293b;">
          <h2 style="color: #10b981; margin-top: 0;">🛡️ CipherSentinel Incident Dispatch Online</h2>
          <p style="color: #94a3b8; font-size: 14px;">This is an automated verification confirming NodeMailer integration with Google SMTP.</p>
          <div style="background: #0f1c38; padding: 16px; border-radius: 8px; border: 1px solid #203358; margin: 16px 0;">
            <p style="margin: 4px 0;"><strong>Recipient:</strong> sanskar0912gharal@gmail.com</p>
            <p style="margin: 4px 0;"><strong>Status:</strong> Engine Active & Ready</p>
            <p style="margin: 4px 0;"><strong>Triangulation:</strong> Rule Engine + Isolation Forest + Ollama Qwen3:4b</p>
          </div>
          <p style="color: #64748b; font-size: 12px;">CipherSentinel Autonomous Security Operations Center</p>
        </div>
      `,
    });

    console.log('[+] Test email sent successfully! Message ID:', info.messageId);
    return true;
  } catch (err) {
    console.error('[-] SMTP verification error:', err);
    return false;
  }
}

testMail();
