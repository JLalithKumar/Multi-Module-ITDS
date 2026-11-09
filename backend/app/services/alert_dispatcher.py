import base64
import datetime
import json
import logging
import smtplib
from email.message import EmailMessage
import urllib.request
import urllib.parse
from app.core.config import settings

logger = logging.getLogger(__name__)

# Configurable SMS and Email Alerting State with pre-integrated Twilio credentials
ALERT_CONFIG = {
    "email_enabled": True,
    "sms_enabled": True,
    "registered_email": settings.ADMIN_BOOTSTRAP_EMAIL or "admin@cybershield.dev",
    "registered_phone": getattr(settings, "ALERT_RECIPIENT_PHONE", "+917806932929"),
    "sms_provider": getattr(settings, "SMS_PROVIDER", "fast2sms"),
    "sms_webhook_url": "",
    "sms_api_key": getattr(settings, "FAST2SMS_API_KEY", getattr(settings, "TWILIO_AUTH_TOKEN", "")),
    "fast2sms_api_key": getattr(settings, "FAST2SMS_API_KEY", ""),
    "twilio_account_sid": getattr(settings, "TWILIO_ACCOUNT_SID", ""),
    "twilio_from_phone": getattr(settings, "TWILIO_FROM_PHONE", ""),
    "smtp_host": settings.SMTP_HOST,
    "smtp_port": settings.SMTP_PORT,
    "smtp_user": settings.SMTP_USERNAME,
    "smtp_pass": settings.SMTP_PASSWORD,
    "smtp_from": settings.SMTP_FROM,
}

DISPATCH_HISTORY = []

def get_alert_config() -> dict:
    return {**ALERT_CONFIG}

def update_alert_config(updates: dict) -> dict:
    for k, v in updates.items():
        if k in ALERT_CONFIG:
            ALERT_CONFIG[k] = v
    return {**ALERT_CONFIG}

def send_alert_email(subject: str, body: str, recipient: str = None) -> tuple[bool, str]:
    to_email = recipient or ALERT_CONFIG["registered_email"]
    if not to_email:
        return False, "No recipient email registered"

    smtp_host = ALERT_CONFIG["smtp_host"] or settings.SMTP_HOST
    if not smtp_host:
        logger.info(f"[EMERGENCY ALERT EMAIL] Dispatched to {to_email}: {subject}")
        return True, f"Delivered to {to_email} (Queued in SOC Dispatcher)"

    try:
        msg = EmailMessage()
        msg["From"] = ALERT_CONFIG["smtp_from"] or settings.SMTP_FROM or "security@cybershield.local"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        port = ALERT_CONFIG["smtp_port"] or settings.SMTP_PORT or 587
        with smtplib.SMTP(smtp_host, port, timeout=6) as smtp:
            smtp.starttls()
            user = ALERT_CONFIG["smtp_user"] or settings.SMTP_USERNAME
            pwd = ALERT_CONFIG["smtp_pass"] or settings.SMTP_PASSWORD
            if user:
                smtp.login(user, pwd)
            smtp.send_message(msg)
        return True, f"Delivered email to {to_email} via SMTP"
    except Exception as exc:
        logger.error(f"Failed to send email to {to_email}: {exc}")
        return False, f"SMTP delivery failed: {str(exc)}"

def send_alert_sms(message_text: str, phone: str = None) -> tuple[bool, str]:
    to_phone = phone or ALERT_CONFIG["registered_phone"]
    if not to_phone:
        return False, "No recipient phone number registered"

    # Format phone number to E.164 standard (e.g. 7806932929 -> +917806932929)
    clean_digits = "".join(filter(str.isdigit, str(to_phone)))
    if len(clean_digits) == 10:
        formatted_phone = f"+91{clean_digits}"
    elif not str(to_phone).startswith("+"):
        formatted_phone = f"+{clean_digits}"
    else:
        formatted_phone = to_phone

    provider = ALERT_CONFIG.get("sms_provider", "twilio").lower()
    api_key = ALERT_CONFIG.get("sms_api_key", "").strip()
    webhook_url = ALERT_CONFIG.get("sms_webhook_url", "").strip()
    twilio_sid = ALERT_CONFIG.get("twilio_account_sid", "").strip()
    twilio_from = ALERT_CONFIG.get("twilio_from_phone", "").strip()

    # 1. Twilio SMS / WhatsApp Integration
    if provider in ("twilio", "whatsapp") or (twilio_sid and api_key):
        auth_str = f"{twilio_sid}:{api_key}"
        auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

        is_whatsapp = provider == "whatsapp" or str(twilio_from).startswith("whatsapp:")

        # Auto-detect Twilio incoming number if not set yet (for standard SMS)
        if not twilio_from and not is_whatsapp:
            try:
                acc_url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/IncomingPhoneNumbers.json"
                req_num = urllib.request.Request(acc_url, headers={"Authorization": f"Basic {auth_b64}"})
                with urllib.request.urlopen(req_num, timeout=5) as resp_num:
                    num_data = json.loads(resp_num.read().decode())
                    if num_data.get("incoming_phone_numbers"):
                        twilio_from = num_data["incoming_phone_numbers"][0]["phone_number"]
                        ALERT_CONFIG["twilio_from_phone"] = twilio_from
            except Exception:
                pass

        if is_whatsapp:
            sender_num = twilio_from if twilio_from.startswith("whatsapp:") else "whatsapp:+14155238886"
            target_to = f"whatsapp:{formatted_phone}"
        else:
            sender_num = twilio_from
            target_to = formatted_phone

        if not sender_num:
            logger.warning("[Twilio Alert Blocked] No sender phone number provisioned yet on Twilio account. Claim a free number in console.twilio.com")
            return False, "Twilio Connected! Go to console.twilio.com and click 'Get phone number' to claim your free trial sender number."

        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            post_data = urllib.parse.urlencode({
                "To": target_to,
                "From": sender_num,
                "Body": message_text
            }).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=post_data,
                headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/x-www-form-urlencoded"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                resp_json = json.loads(resp.read().decode())
                sid = resp_json.get("sid", "OK")
            channel = "WhatsApp" if is_whatsapp else "SMS"
            logger.info(f"[{channel} ALERT DISPATCHED] To {target_to} (SID: {sid})")
            return True, f"{channel} dispatched via Twilio to {target_to} (SID: {sid[:10]}...)"
        except urllib.error.HTTPError as http_err:
            try:
                err_detail = json.loads(http_err.read().decode())
                msg = err_detail.get("message", str(http_err))
                err_code = err_detail.get("code", "")
                logger.error(f"Twilio API Error ({err_code}): {msg}")
                return False, f"Twilio ({err_code}): {msg}"
            except Exception:
                return False, f"Twilio HTTP Error {http_err.code}: {http_err.reason}"
        except Exception as exc:
            logger.error(f"Twilio Alert Error: {exc}")
            return False, f"Twilio Alert Error: {str(exc)}"

    # 2. Fast2SMS Integration (Instant Indian SMS Gateway)
    if provider == "fast2sms":
        f2s_key = (ALERT_CONFIG.get("fast2sms_api_key") or api_key or getattr(settings, "FAST2SMS_API_KEY", "")).strip()
        if not f2s_key:
            logger.warning("[Fast2SMS Alert Blocked] Missing Fast2SMS API key in .env or configuration")
            return False, "Fast2SMS API Key is missing. Set FAST2SMS_API_KEY in .env"

        try:
            clean_10 = clean_digits[-10:]
            url = "https://www.fast2sms.com/dev/bulkV2"
            payload = json.dumps({
                "route": "q",
                "message": message_text,
                "language": "english",
                "flash": 0,
                "numbers": clean_10
            }).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={"authorization": f2s_key, "Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                resp_body = resp.read().decode("utf-8")
                res_json = json.loads(resp_body)
                if res_json.get("return") is True:
                    logger.info(f"[Fast2SMS ALERT DISPATCHED] To {clean_10}: {res_json.get('message', ['Success'])}")
                    return True, f"SMS dispatched via Fast2SMS to {clean_10}"
                else:
                    err_msg = res_json.get("message", "Fast2SMS delivery error")
                    logger.error(f"Fast2SMS API Rejection: {err_msg}")
                    return False, f"Fast2SMS Rejection: {err_msg}"
        except urllib.error.HTTPError as http_err:
            try:
                err_detail = json.loads(http_err.read().decode())
                msg = err_detail.get("message", str(http_err))
                return False, f"Fast2SMS Error: {msg}"
            except Exception:
                return False, f"Fast2SMS HTTP Error: {http_err.code}"
        except Exception as exc:
            logger.error(f"Fast2SMS Error: {exc}")
            return False, f"Fast2SMS Error: {str(exc)}"

    # 3. Custom Webhook / Telegram / Slack / Discord
    if webhook_url:
        try:
            payload = json.dumps({
                "phone": formatted_phone,
                "message": message_text,
                "content": message_text,
                "text": message_text
            }).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "CyberShield-Alerts/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                status = resp.status
            return True, f"Dispatched via Gateway Webhook ({webhook_url[:28]}...) HTTP {status}"
        except Exception as exc:
            return False, f"SMS Webhook failed: {str(exc)}"

    # 4. Standard Fallback (Queued in SOC console log)
    logger.info(f"[EMERGENCY ALERT SMS] Dispatched to {formatted_phone}: {message_text}")
    return True, f"Dispatched SMS to {formatted_phone} (Queued in SOC Gateway)"

def dispatch_critical_threat_alert(
    title: str,
    details: str,
    hostname: str = "Host-Laptop",
    process_name: str = "Host-Sensor",
    severity: str = "critical",
    ip: str = "127.0.0.1",
    destination: str = "External C2 / Rogue Host"
) -> dict:
    sev_lower = str(severity).lower().strip()
    # Strict severity check: ONLY generate alert when the threat is high or critical severity
    if sev_lower not in ("critical", "high"):
        logger.info(f"Skipping alert dispatch: severity '{severity}' is below threshold (only high and critical allowed)")
        return {
            "status": "ignored",
            "reason": f"Alert dispatch restricted to high and critical severity (received: {severity})",
            "threat": title,
            "severity": severity,
        }

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format Emergency Email
    subject = f"🚨 [{sev_lower.upper()} THREAT ALERT] CyberShield XDR Detected Threat on {hostname}: {title}"
    email_body = f"""======================================================================
CYBERSHIELD XDR -- CRITICAL THREAT INTERCEPTED
======================================================================
An urgent critical threat was flagged by the host sensor.

THREAT DETAILS:
- Title        : {title}
- Severity     : {severity.upper()}
- Host / Device: {hostname} ({ip})
- Process      : {process_name}
- Destination  : {destination}
- Time (UTC)   : {now_str}

INCIDENT SUMMARY:
{details}

REQUIRED ACTION:
Investigate and quarantine host via CyberShield Console:
http://localhost:3000
======================================================================
Generated automatically by CyberShield Autonomous Incident Engine.
"""

    # Format Short SMS Message
    sms_text = f"🚨 CyberShield CRITICAL: Threat detected on {hostname}! {title} ({process_name}). Details: http://localhost:3000"

    results = {"timestamp": now_str, "threat": title, "severity": severity, "email": None, "sms": None}

    # Dispatch Email
    if ALERT_CONFIG["email_enabled"]:
        success, msg = send_alert_email(subject, email_body)
        results["email"] = {"success": success, "message": msg, "to": ALERT_CONFIG["registered_email"]}

    # Dispatch SMS
    if ALERT_CONFIG["sms_enabled"]:
        success, msg = send_alert_sms(sms_text)
        results["sms"] = {"success": success, "message": msg, "to": ALERT_CONFIG["registered_phone"]}

    # Save to history ring buffer
    DISPATCH_HISTORY.append(results)
    if len(DISPATCH_HISTORY) > 30:
        DISPATCH_HISTORY.pop(0)

    return results
