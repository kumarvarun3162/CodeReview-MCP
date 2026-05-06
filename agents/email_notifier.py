# agents/email_notifier.py
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from agents.pr_creator import CreatedPR
from agents.code_reviewer import ReviewReport
from api.models import AnalysisJob
from core.config import settings


# Token expires after 48 hours
TOKEN_MAX_AGE_SECONDS = 48 * 60 * 60


class EmailNotifierAgent:
    """
    Sends an HTML approval email to the developer when a review PR is opened.

    The email contains two buttons:
    ✅ Approve → merges the PR
    ❌ Reject  → closes the PR and deletes the review branch

    Each button URL contains a signed token so:
    - Only the person with the email can approve/reject
    - Tokens expire after 48h
    - Tokens can't be forged (HMAC signed with SECRET_KEY)
    """

    def __init__(self):
        self.serializer = URLSafeTimedSerializer(settings.secret_key)

    def _create_token(self, pr: CreatedPR, action: str) -> str:
        """
        Creates a signed token encoding the action details.
        action: "approve" or "reject"

        itsdangerous signs the payload with SECRET_KEY using HMAC.
        If anyone tampers with the token, verification fails.
        """
        payload = {
            "repo": pr.repo_full_name,
            "pr_number": pr.pr_number,
            "branch": pr.branch_name,
            "action": action,
        }
        return self.serializer.dumps(payload, salt=action)

    def verify_token(self, token: str, action: str) -> dict:
        """
        Verifies a token from the approval URL.
        Raises SignatureExpired or BadSignature if invalid.
        Returns the payload dict if valid.
        """
        return self.serializer.loads(
            token,
            salt=action,
            max_age=TOKEN_MAX_AGE_SECONDS,
        )

    async def send_approval_email(
        self,
        pr: CreatedPR,
        report: ReviewReport,
        job: AnalysisJob,
    ) -> bool:
        """
        Sends the approval email. Returns True if sent successfully.
        """
        recipient = job.author_email
        if not recipient:
            print("[Email] No recipient email — skipping notification")
            return False

        # Build signed URLs
        approve_token = self._create_token(pr, "approve")
        reject_token  = self._create_token(pr, "reject")
        approve_url   = f"{settings.server_base_url}/callback/approve/{approve_token}"
        reject_url    = f"{settings.server_base_url}/callback/reject/{reject_token}"

        subject = f"[Code Review] {pr.title}"
        html_body = self._build_html_email(
            pr, report, approve_url, reject_url
        )

        return self._send_smtp(recipient, subject, html_body)

    def _send_smtp(self, to_email: str, subject: str, html: str) -> bool:
        """Sends an HTML email via Gmail SMTP"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = settings.smtp_email
        msg["To"]      = to_email
        msg.attach(MIMEText(html, "html"))

        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(settings.smtp_email, settings.smtp_password)
                server.sendmail(settings.smtp_email, to_email, msg.as_string())
            print(f"[Email] Sent approval email to {to_email}")
            return True
        except smtplib.SMTPAuthenticationError:
            print("[Email] Gmail auth failed. Check SMTP_EMAIL and SMTP_PASSWORD in .env")
            print("[Email] Make sure you're using a Gmail App Password, not your account password")
            return False
        except Exception as e:
            print(f"[Email] Failed to send email: {e}")
            return False

    def _build_html_email(
        self,
        pr: CreatedPR,
        report: ReviewReport,
        approve_url: str,
        reject_url: str,
    ) -> str:
        """Builds a clean, professional HTML email"""

        severity_rows = f"""
        <tr><td style="padding:6px 12px;color:#dc2626;">🔴 Critical</td><td style="padding:6px 12px;font-weight:bold;">{report.critical_count}</td></tr>
        <tr><td style="padding:6px 12px;color:#ea580c;">🟠 High</td><td style="padding:6px 12px;font-weight:bold;">{report.high_count}</td></tr>
        <tr><td style="padding:6px 12px;color:#ca8a04;">🟡 Medium</td><td style="padding:6px 12px;font-weight:bold;">{report.medium_count}</td></tr>
        <tr><td style="padding:6px 12px;color:#16a34a;">🟢 Low</td><td style="padding:6px 12px;font-weight:bold;">{report.low_count}</td></tr>
        """

        top_findings = ""
        for f in (report.llm_findings or [])[:5]:
            emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(f.severity,"⚪")
            top_findings += f"""
            <tr>
              <td style="padding:6px 12px;">{emoji} {f.severity.upper()}</td>
              <td style="padding:6px 12px;font-family:monospace;font-size:13px;">{f.file_path}</td>
              <td style="padding:6px 12px;">{f.title}</td>
            </tr>"""

        return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;margin:0;padding:20px;">
  <div style="max-width:600px;margin:0 auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:32px;text-align:center;">
      <div style="font-size:32px;margin-bottom:8px;">🤖</div>
      <h1 style="color:white;margin:0;font-size:22px;font-weight:700;">Code Review Complete</h1>
      <p style="color:#94a3b8;margin:8px 0 0;">{report.repo_full_name}</p>
    </div>

    <!-- Body -->
    <div style="padding:32px;">
      <p style="color:#475569;margin:0 0 24px;line-height:1.6;">{report.overall_summary}</p>

      <!-- Stats table -->
      <h3 style="color:#1e293b;margin:0 0 12px;font-size:16px;">📊 Findings Summary</h3>
      <table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:8px;overflow:hidden;margin-bottom:24px;">
        <thead><tr style="background:#e2e8f0;">
          <th style="padding:8px 12px;text-align:left;font-size:13px;color:#64748b;">Severity</th>
          <th style="padding:8px 12px;text-align:left;font-size:13px;color:#64748b;">Count</th>
        </tr></thead>
        <tbody>{severity_rows}</tbody>
      </table>

      <!-- Top findings -->
      {"<h3 style='color:#1e293b;margin:0 0 12px;font-size:16px;'>🔍 Top Issues Found</h3><table style='width:100%;border-collapse:collapse;background:#f8fafc;border-radius:8px;overflow:hidden;margin-bottom:24px;'><thead><tr style='background:#e2e8f0;'><th style='padding:8px 12px;text-align:left;font-size:13px;color:#64748b;'>Severity</th><th style='padding:8px 12px;text-align:left;font-size:13px;color:#64748b;'>File</th><th style='padding:8px 12px;text-align:left;font-size:13px;color:#64748b;'>Issue</th></tr></thead><tbody>" + top_findings + "</tbody></table>" if top_findings else ""}

      <!-- View PR button -->
      <div style="text-align:center;margin-bottom:24px;">
        <a href="{pr.pr_url}" style="display:inline-block;background:#3b82f6;color:white;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px;">
          👁️ View Pull Request #{pr.pr_number}
        </a>
      </div>

      <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0;">

      <!-- Approve / Reject -->
      <h3 style="color:#1e293b;margin:0 0 8px;text-align:center;font-size:16px;">What would you like to do?</h3>
      <p style="color:#64748b;text-align:center;font-size:13px;margin:0 0 20px;">These links expire in 48 hours.</p>

      <div style="display:flex;gap:16px;justify-content:center;">
        <a href="{approve_url}"
           style="display:inline-block;background:#16a34a;color:white;padding:14px 36px;border-radius:8px;text-decoration:none;font-weight:700;font-size:16px;">
          ✅ Approve &amp; Merge
        </a>
        <a href="{reject_url}"
           style="display:inline-block;background:#dc2626;color:white;padding:14px 36px;border-radius:8px;text-decoration:none;font-weight:700;font-size:16px;">
          ❌ Reject &amp; Close
        </a>
      </div>
    </div>

    <!-- Footer -->
    <div style="background:#f1f5f9;padding:16px;text-align:center;border-top:1px solid #e2e8f0;">
      <p style="color:#94a3b8;font-size:12px;margin:0;">
        Sent by Code Review MCP Server · Do not forward this email (links are single-use)
      </p>
    </div>
  </div>
</body>
</html>"""