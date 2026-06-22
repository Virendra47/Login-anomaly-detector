from database import db, User, LoginAttempt
from datetime import datetime, timedelta
from collections import defaultdict

class BehavioralProfiler:
    
    def __init__(self, learning_days=7):
        self.learning_days = learning_days
        
    def get_user_baseline(self, user_id):
        """Calculate baseline login hours for a user"""
        cutoff_date = datetime.now() - timedelta(days=self.learning_days)
        
        user = User.query.get(user_id)
        if not user:
            return None
            
        successful_logins = LoginAttempt.query.filter(
            LoginAttempt.username == user.username,
            LoginAttempt.success == True,
            LoginAttempt.timestamp > cutoff_date
        ).all()
        
        if len(successful_logins) < 3:
            return None  # Not enough data
        
        hour_counts = defaultdict(int)
        for login in successful_logins:
            hour_counts[login.hour] += 1
        
        # Determine usual hours (top 60% of logins)
        total = len(successful_logins)
        usual_hours = []
        sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
        
        cumulative = 0
        for hour, count in sorted_hours:
            if cumulative / total < 0.6:
                usual_hours.append(hour)
                cumulative += count
            else:
                break
        
        return usual_hours if usual_hours else None
    
    def check_unusual_timing(self, user_id, login_hour):
        """Check if login at given hour is unusual for the user"""
        user = User.query.get(user_id)
        if not user:
            return False
        
        # Get baseline
        baseline = self.get_user_baseline(user_id)
        
        if baseline is None or len(baseline) == 0:
            # Use configured baseline hours if available
            if user.baseline_hours:
                try:
                    if '-' in user.baseline_hours:
                        baseline_range = user.baseline_hours.split('-')
                        if len(baseline_range) == 2:
                            start, end = int(baseline_range[0]), int(baseline_range[1])
                            baseline = list(range(start, end + 1))
                        else:
                            baseline = list(range(9, 18))
                    elif ',' in user.baseline_hours:
                        baseline = [int(h) for h in user.baseline_hours.split(',')]
                    else:
                        baseline = list(range(9, 18))
                except:
                    baseline = list(range(9, 18))
            else:
                baseline = list(range(9, 18))  # Default 9 AM to 5 PM
        
        # Check if login hour is outside baseline
        is_unusual = login_hour not in baseline
        
        # Additional: Check if it's extremely unusual (e.g., 12 AM - 5 AM)
        is_extreme_unusual = login_hour < 6 or login_hour > 22
        
        if is_extreme_unusual:
            return True
        
        return is_unusual
    
    def update_user_profile(self, user_id):
        """Update user's behavioral profile based on recent activity"""
        user = User.query.get(user_id)
        if not user:
            return
        
        baseline_hours = self.get_user_baseline(user_id)
        if baseline_hours and len(baseline_hours) > 0:
            # Convert to range string if consecutive
            sorted_hours = sorted(baseline_hours)
            if len(sorted_hours) > 1 and max(sorted_hours) - min(sorted_hours) == len(sorted_hours) - 1:
                user.baseline_hours = f"{min(sorted_hours)}-{max(sorted_hours)}"
            else:
                user.baseline_hours = ','.join(map(str, sorted_hours))
            
            db.session.commit()
    
    def detect_brute_force_pattern(self, ip_address, time_window_minutes=5):
        """Detect possible brute force attack from same IP"""
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)
        
        failed_attempts = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.timestamp > cutoff
        ).count()
        
        return failed_attempts >= 10  # 10 failed attempts in 5 minutes