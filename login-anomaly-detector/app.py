from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from database import db, User, LoginAttempt, Alert, init_db
from behavioral_profile import BehavioralProfiler
from alerting import AlertGenerator
from datetime import datetime, timedelta
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///login_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Initialize components
behavioral_profiler = BehavioralProfiler()
alert_generator = AlertGenerator()

# Configuration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 15  # minutes
ALERT_THRESHOLD = 3  # alerts after 3 failed attempts

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_client_ip():
    return request.remote_addr or request.headers.get('X-Forwarded-For', 'unknown')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip_address = get_client_ip()
    login_time = datetime.now()
    hour = login_time.hour
    
    user = User.query.filter_by(username=username).first()
    
    # Check for lockout
    if user and user.is_locked and user.lockout_until > login_time:
        return render_template('index.html', error=f"Account locked. Try after {user.lockout_until.strftime('%H:%M:%S')}")
    
    # Record login attempt
    attempt = LoginAttempt(
        username=username,
        ip_address=ip_address,
        timestamp=login_time,
        hour=hour,
        success=False
    )
    
    is_valid = user and user.password_hash == hash_password(password)
    
    if not user:
        # Create user record for tracking
        user = User(username=username, password_hash=hash_password(password))
        user.baseline_hours = "9-17"  # Default business hours
        db.session.add(user)
        db.session.commit()
        is_valid = False
    
    if is_valid:
        attempt.success = True
        db.session.add(attempt)
        
        # Reset failed attempts
        user.failed_attempts = 0
        user.last_successful_login = login_time
        user.is_locked = False
        db.session.commit()
        
        # Check for unusual timing
        is_unusual = behavioral_profiler.check_unusual_timing(user.id, hour)
        
        if is_unusual:
            alert_generator.generate_alert(
                user_id=user.id,
                alert_type='unusual_timing',
                severity='medium',
                message=f"Unusual login for {username} at {hour}:00",
                details={'hour': hour, 'ip': ip_address}
            )
        
        session['username'] = username
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    else:
        # Failed login
        attempt.success = False
        db.session.add(attempt)
        
        if user:
            user.failed_attempts += 1
            
            # Generate alert for failed attempts
            if user.failed_attempts >= ALERT_THRESHOLD:
                alert_generator.generate_alert(
                    user_id=user.id,
                    alert_type='multiple_failures',
                    severity='high',
                    message=f"Multiple failed login attempts for {username} ({user.failed_attempts} attempts)",
                    details={'failed_count': user.failed_attempts, 'ip': ip_address}
                )
            
            # Lock account if threshold exceeded
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                user.lockout_until = login_time + timedelta(minutes=LOCKOUT_DURATION)
                alert_generator.generate_alert(
                    user_id=user.id,
                    alert_type='account_locked',
                    severity='critical',
                    message=f"Account {username} locked due to {MAX_FAILED_ATTEMPTS} failed attempts",
                    details={'lockout_duration': LOCKOUT_DURATION}
                )
        
        db.session.commit()
        remaining = MAX_FAILED_ATTEMPTS - (user.failed_attempts if user else 0)
        return render_template('index.html', error=f"Invalid credentials. {remaining} attempts remaining.")
    
    return render_template('index.html', error="Login failed")

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    # Get statistics
    total_alerts = Alert.query.count()
    high_severity = Alert.query.filter_by(severity='high').count()
    critical_severity = Alert.query.filter_by(severity='critical').count()
    
    # Get recent alerts
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    
    # Get failed attempts stats
    last_24h = datetime.now() - timedelta(hours=24)
    failed_attempts_last_24h = LoginAttempt.query.filter(
        LoginAttempt.success == False,
        LoginAttempt.timestamp > last_24h
    ).count()
    
    unusual_logins = Alert.query.filter_by(alert_type='unusual_timing').count()
    
    return render_template('dashboard.html',
                         username=session['username'],
                         total_alerts=total_alerts,
                         high_severity=high_severity,
                         critical_severity=critical_severity,
                         failed_attempts_last_24h=failed_attempts_last_24h,
                         unusual_logins=unusual_logins,
                         recent_alerts=recent_alerts)

@app.route('/alerts')
def alerts():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    all_alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    user = User.query.get(session['user_id'])
    login_history = LoginAttempt.query.filter_by(username=user.username).order_by(LoginAttempt.timestamp.desc()).limit(20).all()
    
    # Calculate behavior patterns
    successful_logins = LoginAttempt.query.filter_by(username=user.username, success=True).all()
    hour_distribution = {}
    for login in successful_logins:
        hour_distribution[login.hour] = hour_distribution.get(login.hour, 0) + 1
    
    return render_template('profile.html', user=user, login_history=login_history, hour_distribution=hour_distribution)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/alerts/unacknowledged')
def api_unacknowledged_alerts():
    alerts = Alert.query.filter_by(acknowledged=False).all()
    return jsonify([{
        'id': a.id,
        'type': a.alert_type,
        'severity': a.severity,
        'message': a.message,
        'timestamp': a.timestamp.isoformat()
    } for a in alerts])

@app.route('/api/acknowledge/<int:alert_id>', methods=['POST'])
def acknowledge_alert(alert_id):
    alert = Alert.query.get(alert_id)
    if alert:
        alert.acknowledged = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 404

if __name__ == '__main__':
    with app.app_context():
        init_db(app)
        # Create sample admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password_hash=hash_password('admin123'), role='admin')
            admin.baseline_hours = "9-17"
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)