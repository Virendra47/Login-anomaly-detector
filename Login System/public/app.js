// ==========================================================================
// AEGIS FRONTEND LOGIC & ENGINE BINDING (PRO VERSION)
// Controls 12 user profiles, multi-tab routing, progress checklists,
// CSV downloads, IP firewall blocklists, and advisory logic.
// ==========================================================================

// Global state
let currentDashboardData = null;
let loginHoursChart = null;
let selectedChartUser = 'alice'; // Default selected user for behavior chart
let dashboardPollInterval = null;
let clockInterval = null;
let currentUserSession = null;

// User baselines data model
const userBaselines = {
  alice: {
    name: 'Alice Smith',
    role: 'Finance Analyst',
    hours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
    ip: '192.168.1.15',
    avatar: '👩‍💼'
  },
  bob: {
    name: 'Bob Chen',
    role: 'Lead Systems Engineer',
    hours: [19, 20, 21, 22, 23, 0, 1, 2],
    ip: '10.0.0.42',
    avatar: '👨‍💻'
  },
  charlie: {
    name: 'Charlie Miller',
    role: 'Operations Specialist',
    hours: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    ip: '172.16.85.10',
    avatar: '🧑‍🔧'
  },
  diana_hr: {
    name: 'Diana Prince',
    role: 'HR Director',
    hours: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    ip: '192.168.1.55',
    avatar: '👩‍⚕️'
  },
  ethan_dev: {
    name: 'Ethan Hunt',
    role: 'Frontend Developer',
    hours: [12, 13, 14, 15, 16, 17, 18, 19, 20],
    ip: '192.168.2.110',
    avatar: '🧑‍💻'
  },
  fiona_sales: {
    name: 'Fiona Gallagher',
    role: 'Intl Sales Director',
    hours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22],
    ip: '192.168.1.80',
    avatar: '👩‍💻'
  },
  george_ceo: {
    name: 'George Stark',
    role: 'Chief Executive Officer',
    hours: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
    ip: '10.0.0.5',
    avatar: '👨‍💼'
  },
  hannah_support: {
    name: 'Hannah Abbott',
    role: 'Customer Support (A)',
    hours: [6, 7, 8, 9, 10, 11, 12, 13, 14],
    ip: '192.168.10.15',
    avatar: '👩‍💼'
  },
  ian_support: {
    name: 'Ian Malcolm',
    role: 'Customer Support (B)',
    hours: [14, 15, 16, 17, 18, 19, 20, 21, 22],
    ip: '192.168.10.16',
    avatar: '👨‍💼'
  },
  julia_sysadmin: {
    name: 'Julia Roberts',
    role: 'Cloud Ops Administrator',
    hours: [22, 23, 0, 1, 2, 3, 4, 5, 6],
    ip: '10.0.8.99',
    avatar: '👩‍🚀'
  },
  kevin_marketing: {
    name: 'Kevin Bacon',
    role: 'Marketing Lead',
    hours: [10, 11, 12, 13, 14, 15, 16, 17, 18],
    ip: '192.168.1.4',
    avatar: '🧑‍🎨'
  },
  sec_admin: {
    name: 'Security Administrator',
    role: 'Sysadmin Warden',
    hours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    ip: '192.168.1.2',
    avatar: '🛡️'
  },
  unknown_intruder: {
    name: 'Unknown User',
    role: 'Untracked Origin',
    hours: [],
    ip: '198.51.100.22',
    avatar: '🥷'
  }
};

// Initial Setup on DOM Load
document.addEventListener('DOMContentLoaded', () => {
  updateSelectedUserBaseline();
  onHourSliderChange(document.getElementById('login-hour').value);
  initChart();
  // Show auth modal if no session yet; otherwise start data polling
  try {
    const stored = localStorage.getItem('aegis_user');
    if (stored) {
      currentUserSession = JSON.parse(stored);
      finishInitAfterLogin();
    } else {
      showAuthModal();
    }
  } catch (e) {
    showAuthModal();
  }
});

// --- Authentication Modal Helpers ---
function showAuthModal() {
  const modal = document.getElementById('startup-auth-modal');
  if (!modal) return;
  modal.style.display = 'flex';
}

function hideAuthModal() {
  const modal = document.getElementById('startup-auth-modal');
  if (!modal) return;
  modal.style.display = 'none';
}

function showAuthTab(tab) {
  document.getElementById('auth-tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('auth-tab-register').classList.toggle('active', tab === 'register');
  document.getElementById('auth-tab-content-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('auth-tab-content-register').classList.toggle('hidden', tab !== 'register');
}

async function handleStartupLogin(e) {
  e.preventDefault();
  const username = document.getElementById('startup-username').value.trim();
  const password = document.getElementById('startup-password').value;
  const msgEl = document.getElementById('startup-login-msg');
  msgEl.innerText = '';

  try {
    const resp = await fetch('/api/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await resp.json();
    if (resp.ok) {
      // Save session (minimal)
      currentUserSession = { username, displayName: data.user ? data.user.realName : username };
      localStorage.setItem('aegis_user', JSON.stringify(currentUserSession));
      hideAuthModal();
      finishInitAfterLogin();
      showToast('success', 'Signed in', `Welcome ${currentUserSession.displayName}`);
      // show logout and user indicator
      const logoutBtn = document.getElementById('btn-logout');
      if (logoutBtn) logoutBtn.style.display = 'inline-block';
    } else {
      msgEl.innerText = data.message || 'Login failed.';
      showToast('warning', 'Login failed', data.message || 'Check credentials');
    }
  } catch (err) {
    msgEl.innerText = 'Server unreachable.';
    console.error(err);
  }
}

async function handleStartupRegister(e) {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const displayName = document.getElementById('reg-displayname').value.trim();
  const role = document.getElementById('reg-role').value.trim();
  const password = document.getElementById('reg-password').value;
  const passwordConfirm = document.getElementById('reg-password-confirm').value;
  const msgEl = document.getElementById('startup-register-msg');
  msgEl.innerText = '';
  // Validate passwords
  if (password !== passwordConfirm) {
    msgEl.innerText = 'Passwords do not match.';
    return;
  }

  const strength = checkPasswordStrength(password);
  if (!strength.ok) {
    msgEl.innerText = `Weak password: ${strength.reason}`;
    return;
  }

  try {
    const resp = await fetch('/api/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName, role, password })
    });
    const data = await resp.json();
    if (resp.ok) {
      // Auto-login using provided password
      const loginResp = await fetch('/api/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: data.userKey, password })
      });
      if (loginResp.ok) {
        currentUserSession = { username: data.userKey, displayName: displayName || data.userKey };
        localStorage.setItem('aegis_user', JSON.stringify(currentUserSession));
        hideAuthModal();
        finishInitAfterLogin();
        showToast('success', 'Registered', `Account ${currentUserSession.displayName} created and signed in.`);
        const logoutBtn = document.getElementById('btn-logout');
        if (logoutBtn) logoutBtn.style.display = 'inline-block';
        // After registration an email verification token was sent (if configured)
        showVerifyModal();
      } else {
        msgEl.innerText = 'Registered but auto-login failed.';
      }
    } else {
      msgEl.innerText = data.message || 'Registration failed.';
    }
  } catch (err) {
    msgEl.innerText = 'Server unreachable.';
    console.error(err);
  }
}

// --- Reset & Verify Flows ---
function openRequestResetModal() {
  document.getElementById('startup-auth-modal').style.display = 'none';
  document.getElementById('request-reset-modal').classList.remove('hidden');
}

function closeRequestResetModal() {
  document.getElementById('request-reset-modal').classList.add('hidden');
  document.getElementById('startup-auth-modal').style.display = 'flex';
  document.getElementById('rr-msg').innerText = '';
}

async function handleRequestReset(e) {
  e.preventDefault();
  const id = document.getElementById('rr-identifier').value.trim();
  const msg = document.getElementById('rr-msg');
  msg.innerText = '';
  try {
    const resp = await fetch('/api/users/request-reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernameOrEmail: id }) });
    const data = await resp.json();
    if (resp.ok) {
      msg.innerText = data.message || 'Reset token sent.';
      showResetTokenModal();
      setTimeout(() => closeRequestResetModal(), 1200);
    } else {
      msg.innerText = data.message || 'Failed.';
    }
  } catch (err) {
    msg.innerText = 'Server error.';
  }
}

function showResetTokenModal() {
  document.getElementById('reset-token-modal').classList.remove('hidden');
}

function closeResetTokenModal() {
  document.getElementById('reset-token-modal').classList.add('hidden');
  document.getElementById('rt-msg').innerText = '';
}

async function handleResetWithToken(e) {
  e.preventDefault();
  const token = document.getElementById('rt-token').value.trim();
  const newPw = document.getElementById('rt-new').value;
  const confirm = document.getElementById('rt-confirm').value;
  const msg = document.getElementById('rt-msg');
  msg.innerText = '';
  if (newPw !== confirm) { msg.innerText = 'Passwords do not match.'; return; }
  const strength = checkPasswordStrength(newPw);
  if (!strength.ok) { msg.innerText = `Weak password: ${strength.reason}`; return; }
  try {
    const resp = await fetch('/api/users/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, newPassword: newPw }) });
    const data = await resp.json();
    if (resp.ok) {
      msg.innerText = 'Password reset complete. Please login.';
      showToast('success', 'Password Reset', data.message || 'Password updated');
      setTimeout(() => { closeResetTokenModal(); showAuthModal(); }, 1200);
    } else {
      msg.innerText = data.message || 'Failed to reset.';
    }
  } catch (err) {
    msg.innerText = 'Server error.';
  }
}

function showVerifyModal() {
  document.getElementById('verify-token-modal').classList.remove('hidden');
}

function closeVerifyModal() {
  document.getElementById('verify-token-modal').classList.add('hidden');
  document.getElementById('vt-msg').innerText = '';
}

async function handleVerifyToken(e) {
  e.preventDefault();
  const token = document.getElementById('vt-token').value.trim();
  const msg = document.getElementById('vt-msg');
  msg.innerText = '';
  try {
    const resp = await fetch('/api/users/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    const data = await resp.json();
    if (resp.ok) {
      msg.innerText = data.message || 'Verified.';
      showToast('success', 'Email Verified', data.message || 'Email verified');
      setTimeout(() => closeVerifyModal(), 900);
    } else {
      msg.innerText = data.message || 'Invalid token.';
    }
  } catch (err) {
    msg.innerText = 'Server error.';
  }
}

// Password strength check: returns {ok: boolean, reason: string}
function checkPasswordStrength(pw) {
  if (!pw || pw.length < 8) return { ok: false, reason: 'minimum 8 characters' };
  if (!/[a-z]/.test(pw)) return { ok: false, reason: 'include a lowercase letter' };
  if (!/[A-Z]/.test(pw)) return { ok: false, reason: 'include an uppercase letter' };
  if (!/[0-9]/.test(pw)) return { ok: false, reason: 'include a digit' };
  if (!/[\W_]/.test(pw)) return { ok: false, reason: 'include a special character' };
  return { ok: true };
}

function finishInitAfterLogin() {
  // Initial sync after auth
  fetchDashboardData(true);
  fetchEmailStatus();

  // Start Polling (every 1.5 seconds)
  if (dashboardPollInterval) clearInterval(dashboardPollInterval);
  dashboardPollInterval = setInterval(() => { fetchDashboardData(false); }, 1500);

  if (clockInterval) clearInterval(clockInterval);
  clockInterval = setInterval(updateClock, 1000);

  // Show logout button
  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) logoutBtn.style.display = 'inline-block';
  const cpBtn = document.getElementById('btn-change-pass');
  if (cpBtn) cpBtn.style.display = 'inline-block';
  // Update header user display
  updateHeaderUser();
}

// Handle logout: clear session, stop polling, show auth modal again
function handleLogout() {
  localStorage.removeItem('aegis_user');
  currentUserSession = null;
  if (dashboardPollInterval) { clearInterval(dashboardPollInterval); dashboardPollInterval = null; }
  if (clockInterval) { clearInterval(clockInterval); clockInterval = null; }
  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) logoutBtn.style.display = 'none';
  showAuthModal();
  showToast('info', 'Signed out', 'You have been logged out.');
  // hide header user
  const display = document.getElementById('current-user-display');
  if (display) display.style.display = 'none';
}

function updateHeaderUser() {
  if (!currentUserSession) return;
  const display = document.getElementById('current-user-display');
  const avatar = document.getElementById('current-user-avatar');
  const name = document.getElementById('current-user-name');
  const role = document.getElementById('current-user-role');
  if (!display || !avatar || !name || !role) return;
  // Use data from currentDashboardData if available to show role/avatar
  let userInfo = { avatar: '👤', username: currentUserSession.username, role: '' };
  if (currentDashboardData && currentDashboardData.users) {
    const u = currentDashboardData.users.find(us => us.key === currentUserSession.username);
    if (u) {
      userInfo.avatar = u.avatar || userInfo.avatar;
      userInfo.username = u.username || userInfo.username;
      userInfo.role = u.role || '';
    }
  }
  avatar.innerText = userInfo.avatar;
  name.innerText = userInfo.username;
  role.innerText = userInfo.role;
  display.style.display = 'flex';
}

function showChangePasswordModal() {
  const modal = document.getElementById('change-password-modal');
  if (!modal) return;
  modal.classList.remove('hidden');
}

function hideChangePasswordModal() {
  const modal = document.getElementById('change-password-modal');
  if (!modal) return;
  modal.classList.add('hidden');
  document.getElementById('cp-msg').innerText = '';
}

async function handleChangePassword(e) {
  e.preventDefault();
  const oldPw = document.getElementById('cp-old').value;
  const newPw = document.getElementById('cp-new').value;
  const confirm = document.getElementById('cp-confirm').value;
  const msgEl = document.getElementById('cp-msg');
  msgEl.innerText = '';

  if (!currentUserSession || !currentUserSession.username) {
    msgEl.innerText = 'Not signed in.';
    return;
  }

  if (newPw !== confirm) {
    msgEl.innerText = 'New passwords do not match.';
    return;
  }

  const strength = checkPasswordStrength(newPw);
  if (!strength.ok) {
    msgEl.innerText = `Weak password: ${strength.reason}`;
    return;
  }

  try {
    const resp = await fetch('/api/users/change-password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: currentUserSession.username, oldPassword: oldPw, newPassword: newPw })
    });
    const data = await resp.json();
    if (resp.ok) {
      msgEl.innerText = 'Password updated successfully.';
      showToast('success', 'Password Updated', 'Your password was changed.');
      hideChangePasswordModal();
    } else {
      msgEl.innerText = data.message || 'Failed to change password.';
    }
  } catch (err) {
    msgEl.innerText = 'Server error.';
    console.error(err);
  }
}

async function fetchEmailStatus() {
  try {
    const response = await fetch('/api/email-status');
    if (!response.ok) return;

    const data = await response.json();
    const statusEl = document.getElementById('stat-email-status');
    if (data.enabled) {
      statusEl.innerText = `Active → ${data.alertEmailTo}`;
      statusEl.classList.remove('text-glow-red');
      statusEl.classList.add('text-glow-amber');
      showToast('success', 'Email Alerts Active', `Sending alerts to ${data.alertEmailTo}.`);
    } else {
      statusEl.innerText = data.smtpPassConfigured ? 'Disabled' : 'Needs SMTP_PASS';
      statusEl.classList.remove('text-glow-amber');
      statusEl.classList.add('text-glow-red');
      showToast('warning', 'Email Alerts Not Active', 'SMTP is not fully configured. Set SMTP_PASS and restart the server.');
    }
  } catch (error) {
    console.error('Email status check failed:', error);
  }
}

function updateClock() {
  const clockEl = document.getElementById('system-clock');
  const now = new Date();
  clockEl.innerText = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ==========================================
// 1. DYNAMIC NAVIGATION TABS
// ==========================================

function switchTab(tabId) {
  // Toggle button active state
  const buttons = document.querySelectorAll('.tab-btn');
  buttons.forEach(btn => {
    if (btn.getAttribute('onclick').includes(tabId)) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Toggle content active state
  const contents = document.querySelectorAll('.tab-content');
  contents.forEach(content => {
    if (content.id === tabId) {
      content.classList.add('active-content');
    } else {
      content.classList.remove('active-content');
    }
  });

  // Refresh chart sizing when rendering tab 2
  if (tabId === 'behavior-tab' && loginHoursChart) {
    setTimeout(() => {
      loginHoursChart.resize();
      loginHoursChart.update();
    }, 100);
  }
}

// ==========================================
// 2. CORE REST POLL & ENGINE SYNCHRONIZATION
// ==========================================

async function fetchDashboardData(isFirstLoad = false) {
  try {
    const response = await fetch('/api/dashboard');
    if (!response.ok) throw new Error('API server unreachable');
    
    const data = await response.json();
    currentDashboardData = data;
    
    // Update simple analytics widgets
    updateMetrics(data.metrics);
    
    // Update System HUD state
    updateThreatStateHUD(data.alerts, data.metrics.lockedAccounts);
    
    // Update Mini Profile Cards (Tab 2)
    updateUserProfileCards(data.users);
    
    // Update Alerts listing
    renderAlertsStream(data.alerts);
    
    // Update Logs audit sheet
    renderAuditLogs(data.logs);
    
    // Update Charts data
    updateChartVisuals(data.logs);

    // Update IP blocklist elements (Tab 3)
    renderIPBlacklist(data.blockedIPs);

    // Update MFA Switch Lists (Tab 3)
    renderMFAUsers(data.users);

    // Update Security mitigation suggestions (Tab 3)
    renderSecurityAdvisories(data.users, data.alerts, data.blockedIPs);

    if (isFirstLoad) {
      updateConfigUI(data.config);
    }
  } catch (error) {
    console.error('Synchronization failure:', error);
  }
}

function updateMetrics(metrics) {
  document.getElementById('stat-total-logins').innerText = metrics.totalLogins;
  document.getElementById('stat-failed-attempts').innerText = metrics.failedLogins;
  document.getElementById('stat-active-alerts').innerText = metrics.activeAlerts;
  document.getElementById('stat-locked-accounts').innerText = metrics.lockedAccounts;
}

function updateThreatStateHUD(alerts, lockedCount) {
  const dot = document.getElementById('threat-dot');
  const label = document.getElementById('threat-level-val');
  
  const activeAlerts = alerts.filter(a => a.status === 'active');
  const highAlerts = activeAlerts.filter(a => a.severity === 'high').length;
  const medAlerts = activeAlerts.filter(a => a.severity === 'medium').length;

  if (highAlerts > 0 || lockedCount > 0) {
    dot.className = 'threat-status-dot red';
    label.className = 'threat-value danger';
    label.innerText = 'ATTACK ACTIVE / CRITICAL BREACH RISK';
  } else if (medAlerts > 0) {
    dot.className = 'threat-status-dot amber';
    label.className = 'threat-value warning';
    label.innerText = 'GUARDED / ANOMALOUS ACCESS PATTERNS';
  } else {
    dot.className = 'threat-status-dot green';
    label.className = 'threat-value safe';
    label.innerText = 'SHIELD NOMINAL / ACTIVE PATROLS';
  }
}

function updateConfigUI(config) {
  document.getElementById('cfg-failed-attempts').value = config.failedAttemptsLimit;
  document.getElementById('val-failed-attempts').innerText = config.failedAttemptsLimit + ' fails';
  
  document.getElementById('cfg-window').value = config.bruteForceWindowSeconds;
  document.getElementById('val-window').innerText = config.bruteForceWindowSeconds + 's';
  
  document.getElementById('cfg-lockout').value = config.lockoutDurationMinutes;
  document.getElementById('val-lockout').innerText = config.lockoutDurationMinutes + ' mins';

  document.getElementById('cfg-autolearn').checked = config.autoLearnHours;
}

// ==========================================
// 3. ADVANCED ACCESS SIMULATOR WITH CHECKLIST
// ==========================================

async function handleManualLogin(e) {
  e.preventDefault();
  
  const select = document.getElementById('login-username');
  const userKey = select.value;
  const username = userKey === 'unknown_intruder' ? 'intruder_x' : userKey;
  const password = document.getElementById('login-password').value;
  const simulatedHour = document.getElementById('login-hour').value;
  const ipAddress = document.getElementById('login-ip').value;
  
  const submitBtn = document.getElementById('btn-submit-auth');
  const checklistEl = document.getElementById('auth-progress-checklist');
  const feedbackEl = document.getElementById('login-result-alert');

  // Disable UI
  submitBtn.disabled = true;
  feedbackEl.classList.add('hidden');
  checklistEl.classList.remove('hidden');

  // Clear previous step states
  const steps = ['step-1', 'step-2', 'step-3', 'step-4'];
  steps.forEach(id => {
    const el = document.getElementById(id);
    el.className = 'check-step';
  });

  // Helper to trigger loading steps sequentially for rich feedback
  const runStep = (stepId, text, status) => {
    const el = document.getElementById(stepId);
    el.className = `check-step ${status}`;
  };

  try {
    // Step 1: Input parsing
    runStep('step-1', '', 'active');
    await delay(600);
    runStep('step-1', '', 'done');

    // Step 2: Firewall rules audit
    runStep('step-2', '', 'active');
    await delay(700);
    
    // client-side block status preview
    if (currentDashboardData && currentDashboardData.blockedIPs.includes(ipAddress)) {
      runStep('step-2', '', 'failed');
      throw { status: 403, message: `FIREWALL INTERCEPT: Origin IP address ${ipAddress} blocked by security rules.` };
    }
    runStep('step-2', '', 'done');

    // Step 3: Cryptographic verification
    runStep('step-3', '', 'active');
    await delay(700);
    if (password !== 'password123') {
      runStep('step-3', '', 'failed');
      // continues, let server handle bad password reject
    } else {
      runStep('step-3', '', 'done');
    }

    // Step 4: Schedule analysis
    runStep('step-4', '', 'active');
    await delay(600);
    runStep('step-4', '', 'done');

    // Call REST endpoint
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, simulatedHour, ipAddress })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      displayLoginFeedback(true, data);
      showToast('success', 'Access Authorized', data.message);
    } else {
      displayLoginFeedback(false, data);
      showToast(data.lockout ? 'danger' : 'warning', 'Access Denied', data.message);
    }
  } catch (err) {
    displayLoginFeedback(false, { message: err.message || 'Credentials mismatch or Profile locked.' });
    showToast('danger', 'Suspicious Login Terminated', err.message || 'Authentication halted by Aegis.');
  } finally {
    submitBtn.disabled = false;
    // Hide checklist after brief delay
    setTimeout(() => {
      checklistEl.classList.add('hidden');
    }, 1500);
    fetchDashboardData(false);
  }
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function displayLoginFeedback(isSuccess, data) {
  const feedback = document.getElementById('login-result-alert');
  feedback.className = 'login-feedback-panel';
  
  if (isSuccess) {
    feedback.classList.add('success');
    feedback.innerHTML = `<strong>🟢 APPROVED</strong><br>${data.message}`;
  } else {
    if (data.lockout) {
      feedback.classList.add('lockout');
      feedback.innerHTML = `<strong>🚨 PROFILE SUSPENDED</strong><br>${data.message}`;
    } else {
      feedback.classList.add('failure');
      feedback.innerHTML = `<strong>❌ ACCESS REJECTED</strong><br>${data.message}`;
    }
  }
  feedback.classList.remove('hidden');
}

// ==========================================
// 4. BEHAVIOR EXPLORER TABS RENDERING
// ==========================================

function updateUserProfileCards(userList) {
  const container = document.getElementById('behavioral-profiles-cards');
  if (!container) return;
  container.innerHTML = '';
  
  userList.forEach(user => {
    const isLocked = user.lockoutUntil && new Date(user.lockoutUntil) > new Date();
    const isSelected = user.key === selectedChartUser;
    
    let riskClass = 'low';
    if (user.riskScore > 35) riskClass = 'medium';
    if (user.riskScore > 70) riskClass = 'high';
    
    const baselineText = `${user.baselineHours[0].toString().padStart(2, '0')}:00 - ${user.baselineHours[user.baselineHours.length - 1].toString().padStart(2, '0')}:00`;

    const card = document.createElement('div');
    card.className = `profile-sm-card interactive-profile-card ${isLocked ? 'locked' : ''} ${isSelected ? 'selected' : ''}`;
    card.onclick = () => selectUserForChart(user.key);
    
    card.innerHTML = `
      <div class="profile-header-sm">
        <div class="profile-avatar-info">
          <span class="profile-avatar-sm">${user.avatar}</span>
          <div>
            <h4 class="profile-name-sm">${user.username}</h4>
            <span class="profile-role-sm">${user.role}</span>
          </div>
        </div>
        <span class="profile-status-badge ${isLocked ? 'locked' : 'active'}">${isLocked ? 'Locked' : 'Active'}</span>
      </div>

      <div class="profile-risk-container">
        <div class="profile-risk-label">
          <span>Risk Factor</span>
          <span class="risk-level-badge ${riskClass}">${user.riskScore}%</span>
        </div>
        <div class="profile-risk-bar-outer">
          <div class="profile-risk-bar-inner ${riskClass}" style="width: ${user.riskScore}%"></div>
        </div>
      </div>

      <div class="mfa-badge-row">
        <span>MFA State: <strong>${user.mfaEnforced ? 'Enabled' : 'Disabled'}</strong></span>
      </div>

      <div class="profile-baseline-hours-sm">
        <span>⏰ Baseline Hours:</span>
        <strong>${baselineText}</strong>
      </div>
    `;
    
    container.appendChild(card);
  });
}

function selectUserForChart(userKey) {
  selectedChartUser = userKey;
  
  // Highlight card UI
  const cards = document.querySelectorAll('.interactive-profile-card');
  // Just update UI lists
  if (currentDashboardData) {
    updateUserProfileCards(currentDashboardData.users);
    
    const user = userBaselines[userKey];
    document.getElementById('chart-user-heading').innerText = `${user.name}'s Baseline schedule Integrity Chart`;
    updateChartBaseline(userKey);
  }
}

// Draw Slider preview hours
function updateSelectedUserBaseline() {
  const select = document.getElementById('login-username');
  if (!select) return;
  const userKey = select.value;
  const user = userBaselines[userKey];
  
  document.getElementById('login-ip').value = user.ip;
  
  const previewContainer = document.getElementById('user-baseline-preview');
  previewContainer.innerHTML = '';
  
  const currentSliderHour = parseInt(document.getElementById('login-hour').value);
  
  for (let hour = 0; hour < 24; hour++) {
    const block = document.createElement('div');
    block.className = 'baseline-hour-block';
    block.title = `${formatHourLabel(hour)}: ${user.hours.includes(hour) ? 'Expected Hour' : 'Out-of-Hours'}`;
    
    const isUserBaseline = user.hours.includes(hour);
    const isSliderSelection = (hour === currentSliderHour);
    
    if (isSliderSelection) {
      if (isUserBaseline) block.className += ' selected';
      else block.className += ' anomaly-selected';
    } else if (isUserBaseline) {
      block.className += ' active';
    } else {
      block.className += ' inactive';
    }
    
    previewContainer.appendChild(block);
  }
}

function onHourSliderChange(val) {
  const hour = parseInt(val);
  const labelEl = document.getElementById('hour-badge');
  labelEl.innerText = formatHourLabel(hour);
  updateSelectedUserBaseline();
}

function formatHourLabel(hour) {
  if (hour === 0) return '12:00 AM';
  if (hour === 12) return '12:00 PM';
  const ampm = hour >= 12 ? 'PM' : 'AM';
  const displayHour = hour % 12 === 0 ? 12 : hour % 12;
  return `${displayHour}:00 ${ampm}`;
}

// ==========================================
// 5. FIREWALL & BLACKLIST MANAGER
// ==========================================

function renderIPBlacklist(ips) {
  const listContainer = document.getElementById('blacklist-ips-list');
  if (!listContainer) return;
  
  if (ips.length === 0) {
    listContainer.innerHTML = `<li class="blacklist-empty">🟢 Firewall rules clean. No IPs blocked.</li>`;
    return;
  }

  let html = '';
  ips.forEach(ip => {
    html += `
      <li class="blacklist-item">
        <code>${ip}</code>
        <button class="btn btn-small btn-outline-danger" onclick="unblockIP('${ip}')">Unblock</button>
      </li>
    `;
  });
  listContainer.innerHTML = html;
}

async function handleBlockIP(e) {
  e.preventDefault();
  const ipInput = document.getElementById('blacklist-ip-input');
  const ipAddress = ipInput.value.trim();
  if (!ipAddress) return;

  try {
    const response = await fetch('/api/ip/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ipAddress })
    });
    if (response.ok) {
      showToast('success', 'Firewall Rules Updated', `Blocked packets from IP ${ipAddress} globally.`);
      ipInput.value = '';
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

async function unblockIP(ipAddress) {
  try {
    const response = await fetch('/api/ip/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ipAddress })
    });
    if (response.ok) {
      showToast('success', 'Firewall Rules Updated', `Restored connection passes for IP ${ipAddress}.`);
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

// ==========================================
// 6. MULTI-FACTOR AUTH switch CONTROL
// ==========================================

function renderMFAUsers(userList) {
  const container = document.getElementById('mfa-users-list-container');
  if (!container) return;
  container.innerHTML = '';
  
  userList.forEach(user => {
    const item = document.createElement('div');
    item.className = 'mfa-user-item';
    item.innerHTML = `
      <div class="mfa-user-details">
        <span class="mfa-avatar">${user.avatar}</span>
        <div>
          <strong>${user.username}</strong>
          <span>${user.role}</span>
        </div>
      </div>
      <div class="switch-wrapper">
        <input type="checkbox" id="mfa-switch-${user.key}" class="toggle-checkbox" ${user.mfaEnforced ? 'checked' : ''} onchange="toggleUserMFA('${user.key}')">
        <label for="mfa-switch-${user.key}" class="toggle-label"></label>
      </div>
    `;
    container.appendChild(item);
  });
}

async function toggleUserMFA(username) {
  try {
    const response = await fetch('/api/users/mfa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    
    if (response.ok) {
      const data = await response.json();
      showToast('success', 'Security Policy Updated', data.message);
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

// ==========================================
// 7. SECURITY MITIGATION ADVISORIES ENGINE
// ==========================================

function renderSecurityAdvisories(users, alerts, blockedIPs) {
  const container = document.getElementById('mitigation-advisories');
  if (!container) return;
  container.innerHTML = '';
  
  let advisories = [];

  // Advisory 1: High Risk User Check
  const highRiskUsers = users.filter(u => u.riskScore >= 75);
  highRiskUsers.forEach(u => {
    advisories.push({
      type: 'danger',
      title: `Critical Risk Breach: ${u.username}`,
      desc: `${u.username} has spiked to ${u.riskScore}% risk factor. Mitigate immediately.`,
      actionText: u.mfaEnforced ? 'De-escalate Suspicion' : 'Enforce Multi-Factor MFA',
      action: () => toggleUserMFA(u.key)
    });
  });

  // Advisory 2: Unresolved timing anomalies suggestion
  const timingAlerts = alerts.filter(a => a.status === 'active' && a.type === 'unusual_timing');
  if (timingAlerts.length > 0) {
    const a = timingAlerts[0];
    advisories.push({
      type: 'warning',
      title: `Schedule Violation: ${a.realName}`,
      desc: `Detected out-of-hours timing anomaly. Train baseline hours?`,
      actionText: 'Resolve & Train Engine',
      action: () => resolveAndLearnAlert(a.id)
    });
  }

  // Advisory 3: Firewall suggestions on bad IP attacks
  const failedLogs = currentDashboardData ? currentDashboardData.logs.filter(l => l.status === 'failed') : [];
  if (failedLogs.length > 3) {
    const lastBadIp = failedLogs[0].ipAddress;
    if (!blockedIPs.includes(lastBadIp) && lastBadIp !== '127.0.0.1') {
      advisories.push({
        type: 'danger',
        title: `Brute Scan Vector: IP ${lastBadIp}`,
        desc: `IP origin registered multiple sequential login failures. Block to secure ports.`,
        actionText: 'Block IP Address',
        action: () => blockAttackerIP(lastBadIp)
      });
    }
  }

  // Default clean state
  if (advisories.length === 0) {
    container.innerHTML = `
      <div class="advisory-card success">
        <div class="advisory-body">
          <div class="advisory-title">🟢 Defensive Protocols Nominal</div>
          <div class="advisory-desc">System registers zero active anomalies. All baselines verified and operating safely.</div>
        </div>
      </div>
    `;
    return;
  }

  // Draw cards
  advisories.forEach((adv, idx) => {
    const card = document.createElement('div');
    card.className = `advisory-card ${adv.type}`;
    
    const icon = adv.type === 'danger' ? '🚨' : '⚠️';
    
    card.innerHTML = `
      <div class="advisory-body">
        <div class="advisory-title">${icon} ${adv.title}</div>
        <div class="advisory-desc">${adv.desc}</div>
        <button class="btn btn-small btn-primary" id="btn-adv-${idx}" style="margin-top:10px;">${adv.actionText}</button>
      </div>
    `;
    
    container.appendChild(card);
    
    // Bind action
    document.getElementById(`btn-adv-${idx}`).onclick = adv.action;
  });
}

async function blockAttackerIP(ipAddress) {
  try {
    const response = await fetch('/api/ip/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ipAddress })
    });
    if (response.ok) {
      showToast('success', 'Firewall Rules Updated', `Blocked IP ${ipAddress} successfully.`);
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

// Special machine learning resolver
async function resolveAndLearnAlert(alertId) {
  try {
    const response = await fetch('/api/alerts/resolve-and-learn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alertId })
    });
    if (response.ok) {
      showToast('success', 'Neural Shield Calibrated', 'Aegis learned timing schedule. No future alerts for this user hour.');
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

// ==========================================
// 8. SECURITY ALERTS STREAM AND ACTIONS
// ==========================================

function renderAlertsStream(alerts) {
  const feed = document.getElementById('alerts-feed');
  if (!feed) return;
  
  if (alerts.length === 0) {
    feed.innerHTML = `
      <div class="empty-alerts">
        <p>🟢 System shields clean. No active alerts.</p>
      </div>`;
    return;
  }
  
  let html = '';
  alerts.forEach(alert => {
    const timeStr = new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const isResolved = alert.status === 'resolved';
    
    let severityClass = alert.severity;
    if (isResolved) severityClass = 'resolved';

    html += `
      <div class="alert-card ${severityClass}" id="card-${alert.id}">
        <div class="alert-content">
          <div class="alert-meta">
            <span class="alert-type-badge">${alert.type.replace('_', ' ')}</span>
            <span class="alert-time">${timeStr}</span>
          </div>
          <p class="alert-message">${alert.message}</p>
        </div>
        <div class="alert-actions">
          ${!isResolved ? `
            <button class="btn btn-small btn-outline" onclick="resolveAlert('${alert.id}')">Acknowledge</button>
            ${alert.type === 'unusual_timing' ? `
              <button class="btn btn-small btn-primary" onclick="resolveAndLearnAlert('${alert.id}')">💡 Resolve & Learn</button>
            ` : ''}
          ` : `<span class="badge text-dark" style="background:none; border:none; padding:0;">RESOLVED</span>`}
          ${alert.type === 'account_lockout' && !isResolved ? `
            <button class="btn btn-small btn-danger" onclick="forceUnlockUser('${alert.username}')">🔓 Unlock Profile</button>
          ` : ''}
        </div>
      </div>
    `;
  });
  
  feed.innerHTML = html;
}

async function resolveAlert(alertId) {
  try {
    const response = await fetch('/api/alerts/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alertId })
    });
    if (response.ok) {
      showToast('success', 'Anomaly Flag Lowered', `Acknowledged alert #${alertId}.`);
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

async function forceUnlockUser(username) {
  try {
    const response = await fetch('/api/users/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    if (response.ok) {
      showToast('success', 'Profile Restored', `Access tokens re-synchronized for ${username.toUpperCase()}.`);
      fetchDashboardData();
    }
  } catch (error) {
    console.error(error);
  }
}

async function clearAllData() {
  if (!confirm('Are you sure you want to clean database logs, custom rules, and blacklists?')) return;
  try {
    const response = await fetch('/api/alerts/clear-all', { method: 'POST' });
    if (response.ok) {
      showToast('success', 'Kernel Sanitized', 'All historical audit trails purged.');
      fetchDashboardData(true);
    }
  } catch (error) {
    console.error(error);
  }
}

// ==========================================
// 9. THREAT ACTIONS AND CSV EXPORTER
// ==========================================

async function triggerSimulation(scenario) {
  const btnId = {
    'brute_force': 'btn-sim-bruteforce',
    'unusual_timing': 'btn-sim-timing',
    'credential_stuffing': 'btn-sim-stuffing',
    'test_alert': 'btn-sim-test',
    'clean_traffic': 'btn-sim-clean'
  }[scenario];
  
  const btn = document.getElementById(btnId);
  const oldText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="animate-pulse">⌛ Emulating...</span>`;

  try {
    const response = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
    const data = await response.json();
    if (data.success) {
      const title = scenario === 'clean_traffic' ? 'Traffic Normalized' : scenario === 'test_alert' ? 'Test Alert Sent' : 'Threat Injected';
      const variant = scenario === 'clean_traffic' ? 'success' : scenario === 'test_alert' ? 'info' : 'danger';
      showToast(variant, title, data.message);
    }
  } catch {
    showToast('danger', 'Emulation Halted', 'Failed to communicate with simulator subsystem.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = oldText;
    fetchDashboardData(false);
  }
}

async function handleConfigUpdate(e) {
  e.preventDefault();
  const failedAttemptsLimit = document.getElementById('cfg-failed-attempts').value;
  const bruteForceWindowSeconds = document.getElementById('cfg-window').value;
  const lockoutDurationMinutes = document.getElementById('cfg-lockout').value;
  const autoLearnHours = document.getElementById('cfg-autolearn').checked;
  
  const saveBtn = document.getElementById('btn-save-config');
  saveBtn.innerText = '⌛ Calibrating rules...';
  
  try {
    const response = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ failedAttemptsLimit, bruteForceWindowSeconds, lockoutDurationMinutes, autoLearnHours })
    });
    if (response.ok) {
      showToast('success', 'Firewall Rules Calibrated', 'Aegis analytical parameters adjusted successfully.');
    }
  } catch {
    showToast('danger', 'Engine Sync Error', 'Could not apply settings across firewall nodes.');
  } finally {
    saveBtn.innerText = '💾 Synchronize Engine Guidelines';
    fetchDashboardData(false);
  }
}

// Download Security Logs as clean formatted CSV
function exportLogsToCSV() {
  if (!currentDashboardData || currentDashboardData.logs.length === 0) {
    showToast('warning', 'Export Ignored', 'Zero log entries exist to compile report.');
    return;
  }

  const csvRows = [];
  // Headers
  csvRows.push(['Log ID', 'Timestamp', 'Username', 'Identity', 'Simulated Hour', 'IP Address', 'Result', 'Timing Anomaly', 'Brute Force Trigger', 'Risk Level']);
  
  currentDashboardData.logs.forEach(log => {
    csvRows.push([
      log.id,
      log.timestamp,
      log.username,
      log.realName,
      log.simulatedHour + ':00',
      log.ipAddress,
      log.status.toUpperCase(),
      log.isAnomalousTime ? 'YES' : 'NO',
      log.isBruteForce ? 'YES' : 'NO',
      log.riskScore + '%'
    ]);
  });

  const csvContent = "data:text/csv;charset=utf-8," + csvRows.map(e => e.join(",")).join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", `aegis_security_audit_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  showToast('success', 'Audit Compiled', 'CSV security report compiled and downloaded.');
}

// ==========================================
// 10. CHRONOLOGICAL SECURITY EVENT LOG TABLE
// ==========================================

function renderAuditLogs(logs) {
  const tbody = document.getElementById('audit-log-body');
  if (!tbody) return;
  
  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dark); padding: 40px;">No records found. simulate attempts to populate logs.</td></tr>`;
    return;
  }
  
  let html = '';
  logs.forEach(log => {
    const date = new Date(log.timestamp);
    const dateStr = date.toLocaleDateString();
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    const user = userBaselines[log.username] || { name: log.realName, avatar: '🥷' };
    const statusClass = log.status === 'success' ? 'success' : 'failed';
    const statusText = log.status === 'success' ? 'APPROVED' : 'REJECTED';
    
    let riskClass = 'low';
    if (log.riskScore > 35) riskClass = 'medium';
    if (log.riskScore > 70) riskClass = 'high';

    let anomalyHtml = '';
    if (log.isAnomalousTime) anomalyHtml += `<span class="anomaly-badge timing">Timing Anomaly</span>`;
    if (log.isBruteForce) anomalyHtml += `<span class="anomaly-badge bruteforce">Brute Force Lock</span>`;
    if (!log.isAnomalousTime && !log.isBruteForce) anomalyHtml += `<span style="color: var(--text-dark); font-size:11px;">--</span>`;

    html += `
      <tr>
        <td>
          <div>${dateStr}</div>
          <span class="table-time">${timeStr}</span>
        </td>
        <td>
          <span class="table-user-avatar">${user.avatar}</span>
          <strong>${user.name}</strong>
          <div style="font-size:10px; color: var(--text-muted); padding-left: 20px;">@${log.username}</div>
        </td>
        <td>
          <strong>${log.simulatedHour.toString().padStart(2, '0')}:00</strong>
        </td>
        <td>
          <code style="color: var(--accent-blue);">${log.ipAddress}</code>
        </td>
        <td>
          <span class="status-badge ${statusClass}">${statusText}</span>
        </td>
        <td>
          ${anomalyHtml}
        </td>
        <td>
          <strong class="risk-level-badge ${riskClass}">${log.riskScore}%</strong>
        </td>
      </tr>
    `;
  });
  
  tbody.innerHTML = html;
}

// ==========================================
// 11. TOASTER FLOATING WIDGET
// ==========================================

function showToast(type, title, desc) {
  const container = document.getElementById('toast-container');
  let icon = '🛡️';
  if (type === 'success') icon = '🟢';
  if (type === 'warning') icon = '⚠️';
  if (type === 'danger') icon = '🚨';
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <div class="toast-icon">${icon}</div>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      <div class="toast-desc">${desc}</div>
    </div>
  `;
  
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'slideIn 0.3s reverse forwards';
    setTimeout(() => { toast.remove(); }, 300);
  }, 4500);
}

// ==========================================
// 12. COMPARISON CHART ENGINE
// ==========================================

function initChart() {
  const ctx = document.getElementById('loginHoursChart').getContext('2d');
  const hoursLabels = Array.from({ length: 24 }, (_, i) => `${i.toString().padStart(2, '0')}:00`);
  
  loginHoursChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hoursLabels,
      datasets: [
        {
          label: 'Allowed Working Schedule Baseline',
          data: Array(24).fill(0),
          backgroundColor: 'rgba(0, 245, 160, 0.22)',
          borderColor: 'rgba(0, 245, 160, 0.85)',
          borderWidth: 1.5,
          borderRadius: 4,
          type: 'bar',
          order: 2
        },
        {
          label: 'System Access Audits (Cyan)',
          data: Array(24).fill(0),
          backgroundColor: 'rgba(0, 210, 255, 0.65)',
          borderColor: 'rgba(0, 210, 255, 1)',
          borderWidth: 2,
          borderRadius: 4,
          type: 'bar',
          order: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: '#8c9ba5',
            font: { family: 'Outfit', size: 11 }
          }
        },
        tooltip: {
          backgroundColor: '#0c0f17',
          titleFont: { family: 'Outfit', size: 12 },
          bodyFont: { family: 'Outfit', size: 12 },
          borderColor: 'rgba(255,255,255,0.08)',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.03)' },
          ticks: { color: '#8c9ba5', font: { family: 'Outfit', size: 9 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.03)' },
          ticks: { color: '#8c9ba5', precision: 0, font: { family: 'Outfit', size: 10 } },
          beginAtZero: true
        }
      }
    }
  });

  selectUserForChart('alice');
}

function updateChartBaseline(userKey) {
  const user = userBaselines[userKey];
  const baselineData = Array(24).fill(0);
  
  if (user && user.hours.length > 0) {
    user.hours.forEach(hour => {
      baselineData[hour] = 1.0; 
    });
  }
  
  loginHoursChart.data.datasets[0].label = `${user.name} Baseline Working Windows`;
  loginHoursChart.data.datasets[0].data = baselineData;
  loginHoursChart.update();
}

function updateChartVisuals(logs) {
  if (!loginHoursChart) return;
  const hourCounts = Array(24).fill(0);
  
  logs.forEach(log => {
    if (log.simulatedHour !== undefined) {
      hourCounts[log.simulatedHour] += 1;
    }
  });
  
  loginHoursChart.data.datasets[1].data = hourCounts;
  loginHoursChart.update();
}
