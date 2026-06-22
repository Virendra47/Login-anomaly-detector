from database import db, Alert
from datetime import datetime
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertGenerator:
    
    def __init__(self, email_config=None):
        self.email_config = email_config or {
            'enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': '',
            'sender_password': '',
            'admin_emails': []
        }
    
    def generate_alert(self, user_id, alert_type, severity, message, details=None):
        """Generate and store an alert"""
        alert = Alert(
            user_id=user_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            details=json.dumps(details) if details else None,
            timestamp=datetime.now()
        )
        
        db.session.add(alert)
        db.session.commit()
        
        # Log to console (simulates real-time alert)
        print(f"\n{'='*60}")
        print(f"🚨 ALERT [{severity.upper()}] - {alert_type}")
        print(f"📝 {message}")
        print(f"⏰ {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        if details:
            print(f"📊 Details: {details}")
        print(f"{'='*60}\n")
        
        # Send email notification for high/critical alerts
        if severity in ['high', 'critical'] and self.email_config['enabled']:
            self._send_email_alert(alert_type, severity, message, details)
        
        # Could also integrate with:
        # - Slack webhook
        # - SMS via Twilio
        # - PagerDuty
        # - Webhook to SIEM system
        
        return alert
    
    def _send_email_alert(self, alert_type, severity, message, details):
        """Send email notification to administrators"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender_email']
            msg['To'] = ', '.join(self.email_config['admin_emails'])
            msg['Subject'] = f"[{severity.upper()}] Security Alert: {alert_type}"
            
            body = f"""
            Security Alert Generated
            
            Type: {alert_type}
            Severity: {severity}
            Message: {message}
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Details: {json.dumps(details, indent=2) if details else 'N/A'}
            
            Please check the admin dashboard for more information.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['sender_email'], self.email_config['sender_password'])
            server.send_message(msg)
            server.quit()
            
            print(f"📧 Email alert sent to {len(self.email_config['admin_emails'])} admins")
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def get_unacknowledged_alerts(self):
        """Retrieve all unacknowledged alerts"""
        return Alert.query.filter_by(acknowledged=False).order_by(Alert.timestamp.desc()).all()
    
    def acknowledge_alert(self, alert_id):
        """Mark alert as acknowledged"""
        alert = Alert.query.get(alert_id)
        if alert:
            alert.acknowledged = True
            db.session.commit()
            return True
        return False