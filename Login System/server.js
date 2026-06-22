const express = require('express');
const path = require('path');
const nodemailer = require('nodemailer');
const fs = require('fs');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const DB_FILE = path.join(DATA_DIR, 'aegis.db');
let db = null;

function initDatabase() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    db = new sqlite3.Database(DB_FILE);
    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS users (
        key TEXT PRIMARY KEY,
        username TEXT,
        role TEXT,
        avatar TEXT,
        baselineHours TEXT,
        failedAttemptsCount INTEGER,
        lockoutUntil TEXT,
        riskScore INTEGER,
        consecutiveFails TEXT,
        ipBaseline TEXT,
        mfaEnforced INTEGER,
        passwordSalt TEXT,
        passwordHash TEXT,
        email TEXT,
        emailVerified INTEGER,
        verifyToken TEXT,
        verifyTokenExpires TEXT,
        resetToken TEXT,
        resetTokenExpires TEXT
      )`);
    });
    console.log('SQLite DB initialized:', DB_FILE);
  } catch (err) {
    console.error('Failed to initialize DB:', err && err.message);
    db = null;
  }
}

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT) || 587;
const SMTP_USER = process.env.SMTP_USER || 'virendrapandule7070@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || 'Virendra@0407';

const EMAIL_TRANSPORTER = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: String(SMTP_PORT) === '465',
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS
  }
});

const ALERT_EMAIL_TO = process.env.ALERT_EMAIL_TO || '202301040078@mitaoe.ac.in';
const ALERT_EMAIL_FROM = process.env.ALERT_EMAIL_FROM || SMTP_USER || 'alerts@aegis.local';
const EMAIL_ALERTS_ENABLED = Boolean(ALERT_EMAIL_TO && SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS);

console.log('--- AEGIS EMAIL ALERT CONFIG ---');
console.log(`SMTP_HOST: ${SMTP_HOST}`);
console.log(`SMTP_PORT: ${SMTP_PORT}`);
console.log(`SMTP_USER: ${SMTP_USER}`);
console.log(`ALERT_EMAIL_TO: ${ALERT_EMAIL_TO}`);
console.log(`EMAIL_ALERTS_ENABLED: ${EMAIL_ALERTS_ENABLED}`);
console.log('--------------------------------');

async function sendAlertEmail(alert) {
  if (!EMAIL_ALERTS_ENABLED) {
    console.log('Email alerts disabled. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and ALERT_EMAIL_TO to enable.');
    return;
  }

  const subject = `[AEGIS ALERT] ${alert.severity.toUpperCase()} - ${alert.type.replace(/_/g, ' ')}`;
  const body = `Alert ID: ${alert.id}\nType: ${alert.type}\nSeverity: ${alert.severity}\nUser: ${alert.realName} (${alert.username})\nTime: ${alert.timestamp}\nMessage: ${alert.message}\n\nDetails:\n${JSON.stringify(alert.meta || {}, null, 2)}\n`;

  try {
    await EMAIL_TRANSPORTER.sendMail({
      from: ALERT_EMAIL_FROM,
      to: ALERT_EMAIL_TO,
      subject,
      text: body
    });
    console.log(`Email alert sent to ${ALERT_EMAIL_TO} for ${alert.id}`);
  } catch (error) {
    console.error(`Failed to send alert email for ${alert.id}:`, error.message || error);
  }
}

function generateToken(len = 32) {
  return crypto.randomBytes(len).toString('hex');
}

async function sendVerificationEmail(user, token) {
  if (!EMAIL_ALERTS_ENABLED) return;
  const to = user.email || ALERT_EMAIL_TO;
  const subject = '[AEGIS] Verify your account';
  const text = `Hello ${user.username},\n\nPlease verify your account by using this token in the application: ${token}\n\n(For demo builds this token can be pasted into the verify dialog.)`;
  try {
    await EMAIL_TRANSPORTER.sendMail({ from: ALERT_EMAIL_FROM, to, subject, text });
    console.log(`Verification email sent to ${to}`);
  } catch (err) {
    console.error('Failed to send verification email:', err && err.message);
  }
}

async function sendResetEmail(user, token) {
  if (!EMAIL_ALERTS_ENABLED) return;
  const to = user.email || ALERT_EMAIL_TO;
  const subject = '[AEGIS] Password reset request';
  const text = `Hello ${user.username},\n\nUse this password reset token to update your password: ${token}\n\nIf you did not request this, ignore this message.`;
  try {
    await EMAIL_TRANSPORTER.sendMail({ from: ALERT_EMAIL_FROM, to, subject, text });
    console.log(`Password reset email sent to ${to}`);
  } catch (err) {
    console.error('Failed to send reset email:', err && err.message);
  }
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. IN-MEMORY DATABASE & CONFIGURATIONS
// ==========================================

let config = {
  failedAttemptsLimit: 5,
  bruteForceWindowSeconds: 60,
  lockoutDurationMinutes: 5,
  anomalySensitivity: 0.5,
  autoLearnHours: true, // Auto-learn hours when anomalies are resolved
};

// Global firewall block list
let blockedIPs = new Set(['198.51.100.99']); // Seed with one known threat IP

// Seed 12 Diverse User Profiles
let users = {
  alice: {
    username: 'Alice Smith',
    role: 'Finance Analyst',
    avatar: '👩‍💼',
    baselineHours: [9, 10, 11, 12, 13, 14, 15, 16, 17], // 9 AM to 5 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.1.15',
    mfaEnforced: false,
  },
  bob: {
    username: 'Bob Chen',
    role: 'Lead Systems Engineer',
    avatar: '👨‍💻',
    baselineHours: [0, 1, 2, 19, 20, 21, 22, 23], // Night Shift: 7 PM to 3 AM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '10.0.0.42',
    mfaEnforced: false,
  },
  charlie: {
    username: 'Charlie Miller',
    role: 'Operations Specialist',
    avatar: '🧑‍🔧',
    baselineHours: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18], // 7 AM to 6 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '172.16.85.10',
    mfaEnforced: false,
  },
  diana_hr: {
    username: 'Diana Prince',
    role: 'HR Director',
    avatar: '👩‍⚕️',
    baselineHours: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15], // Early Morning: 6 AM to 3 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.1.55',
    mfaEnforced: false,
  },
  ethan_dev: {
    username: 'Ethan Hunt',
    role: 'Frontend Developer',
    avatar: '🧑‍💻',
    baselineHours: [12, 13, 14, 15, 16, 17, 18, 19, 20], // Midday Shift: 12 PM to 8 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.2.110',
    mfaEnforced: false,
  },
  fiona_sales: {
    username: 'Fiona Gallagher',
    role: 'Intl Sales Director',
    avatar: '👩‍💻',
    baselineHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22], // Extended Day: 8 AM to 10 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.1.80',
    mfaEnforced: false,
  },
  george_ceo: {
    username: 'George Stark',
    role: 'Chief Executive Officer',
    avatar: '👨‍💼',
    baselineHours: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23], // Extended Executive: 6 AM to 11 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '10.0.0.5',
    mfaEnforced: false,
  },
  hannah_support: {
    username: 'Hannah Abbott',
    role: 'Customer Support (A)',
    avatar: '👩‍💼',
    baselineHours: [6, 7, 8, 9, 10, 11, 12, 13, 14], // Support Shift A: 6 AM to 2 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.10.15',
    mfaEnforced: false,
  },
  ian_support: {
    username: 'Ian Malcolm',
    role: 'Customer Support (B)',
    avatar: '👨‍💼',
    baselineHours: [14, 15, 16, 17, 18, 19, 20, 21, 22], // Support Shift B: 2 PM to 10 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.10.16',
    mfaEnforced: false,
  },
  julia_sysadmin: {
    username: 'Julia Roberts',
    role: 'Cloud Ops Administrator',
    avatar: '👩‍🚀',
    baselineHours: [22, 23, 0, 1, 2, 3, 4, 5, 6], // Late Night Ops: 10 PM to 6 AM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '10.0.8.99',
    mfaEnforced: false,
  },
  kevin_marketing: {
    username: 'Kevin Bacon',
    role: 'Marketing Lead',
    avatar: '🧑‍🎨',
    baselineHours: [10, 11, 12, 13, 14, 15, 16, 17, 18], // Office Core: 10 AM to 6 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.1.4',
    mfaEnforced: false,
  },
  sec_admin: {
    username: 'Security Administrator',
    role: 'Sysadmin Warden',
    avatar: '🛡️',
    baselineHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18], // 8 AM to 6 PM
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: '192.168.1.2',
    mfaEnforced: true, // Seed Admin with active MFA
  }
};

// Load persisted users from disk (if present) and merge/override seeded users
function loadUsersFromDisk() {
  // Migrate from SQLite if available, otherwise keep JSON fallback
  if (db) {
    try {
      db.serialize(() => {
        db.all('SELECT * FROM users', (err, rows) => {
          if (err) {
            console.error('Failed to read users from DB:', err.message || err);
            return;
          }
          if (!rows || rows.length === 0) {
            console.log('No users in DB; retaining seeded in-memory users.');
            return;
          }
          users = {};
          rows.forEach(r => {
            users[r.key] = {
              username: r.username,
              role: r.role,
              avatar: r.avatar,
              baselineHours: r.baselineHours ? JSON.parse(r.baselineHours) : [],
              failedAttemptsCount: r.failedAttemptsCount || 0,
              lockoutUntil: r.lockoutUntil,
              riskScore: r.riskScore || 0,
              consecutiveFails: r.consecutiveFails ? JSON.parse(r.consecutiveFails) : [],
              ipBaseline: r.ipBaseline,
              mfaEnforced: Boolean(r.mfaEnforced),
              passwordSalt: r.passwordSalt,
              passwordHash: r.passwordHash,
              email: r.email,
              emailVerified: Boolean(r.emailVerified)
            };
          });
          console.log(`Loaded ${Object.keys(users).length} users from SQLite DB.`);
        });
      });
      return;
    } catch (err) {
      console.error('DB load failed; falling back to JSON file:', err.message || err);
    }
  }

  // JSON fallback
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf8');
      const diskUsers = JSON.parse(raw || '{}');
      users = Object.assign({}, users, diskUsers);
      console.log('Loaded persisted users from disk (JSON).');
    }
  } catch (err) {
    console.error('Failed to load users from disk:', err.message || err);
  }
}

function saveUsersToDisk() {
  // Persist into SQLite DB if available
  if (db) {
    try {
      const stmt = db.prepare(`INSERT OR REPLACE INTO users (
        key, username, role, avatar, baselineHours, failedAttemptsCount, lockoutUntil,
        riskScore, consecutiveFails, ipBaseline, mfaEnforced, passwordSalt, passwordHash,
        email, emailVerified, verifyToken, verifyTokenExpires, resetToken, resetTokenExpires
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        Object.keys(users).forEach(k => {
          const u = users[k];
          stmt.run(
            k,
            u.username || '',
            u.role || '',
            u.avatar || '',
            JSON.stringify(u.baselineHours || []),
            u.failedAttemptsCount || 0,
            u.lockoutUntil || null,
            u.riskScore || 0,
            JSON.stringify(u.consecutiveFails || []),
            u.ipBaseline || null,
            u.mfaEnforced ? 1 : 0,
            u.passwordSalt || null,
            u.passwordHash || null,
            u.email || null,
            u.emailVerified ? 1 : 0,
            u.verifyToken || null,
            u.verifyTokenExpires || null,
            u.resetToken || null,
            u.resetTokenExpires || null
          );
        });
        db.run('COMMIT');
      });
      stmt.finalize();
      // Also write a JSON backup
      try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8'); } catch (e) {}
      console.log('Persisted users to SQLite DB.');
      return;
    } catch (err) {
      console.error('Failed to persist users to DB:', err.message || err);
    }
  }

  // JSON fallback
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    console.log('Persisted users to disk (JSON).');
  } catch (err) {
    console.error('Failed to save users to disk:', err.message || err);
  }
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.pbkdf2Sync(String(password), salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash: derived };
}

initDatabase();
loadUsersFromDisk();

let loginLogs = [];
let alerts = [];
let alertIdCounter = 1;

// ==========================================
// 2. BEHAVIOR ANALYSIS & RULE ENGINE
// ==========================================

function updateRiskScore(userKey) {
  const user = users[userKey];
  if (!user) return;

  let baseRisk = 0;
  
  if (user.lockoutUntil && new Date(user.lockoutUntil) > new Date()) {
    baseRisk += 60;
  }

  const now = Date.now();
  const recentFails = user.consecutiveFails.filter(t => (now - t) < 300 * 1000);
  baseRisk += recentFails.length * 15;

  const activeUserAlerts = alerts.filter(a => a.username === userKey && a.status === 'active');
  activeUserAlerts.forEach(a => {
    if (a.severity === 'high') baseRisk += 30;
    if (a.severity === 'medium') baseRisk += 15;
  });

  // MFA protection mitigates risk
  if (user.mfaEnforced) {
    baseRisk = Math.floor(baseRisk * 0.4); // 60% risk reduction
  }

  user.riskScore = Math.min(100, Math.max(0, baseRisk));
}

function triggerAlert(type, severity, username, message, meta = {}) {
  const newAlert = {
    id: `alert_${alertIdCounter++}`,
    timestamp: new Date().toISOString(),
    username: username,
    realName: users[username] ? users[username].username : 'Unknown Node',
    type,
    severity,
    message,
    status: 'active',
    meta,
    emailSent: false
  };
  alerts.unshift(newAlert);
  sendAlertEmail(newAlert).then(() => {
    newAlert.emailSent = true;
  }).catch(() => {
    newAlert.emailSent = false;
  });
  return newAlert;
}

// Generate realistic logs on launch
function seedHistoricalData() {
  const now = new Date();
  const usernames = Object.keys(users);
  
  for (let i = 80; i > 0; i--) {
    const logTime = new Date(now.getTime() - i * 20 * 60 * 1000);
    const userKey = usernames[i % usernames.length];
    const user = users[userKey];
    
    const isSuccess = Math.random() > 0.12; // 88% success rate
    const hour = user.baselineHours.length > 0 
      ? user.baselineHours[Math.floor(Math.random() * user.baselineHours.length)] 
      : 10;
    
    logTime.setHours(hour, Math.floor(Math.random() * 60));

    loginLogs.push({
      id: `log_${80 - i}`,
      timestamp: logTime.toISOString(),
      username: userKey,
      realName: user.username,
      status: isSuccess ? 'success' : 'failed',
      simulatedHour: hour,
      ipAddress: isSuccess ? user.ipBaseline : `198.51.100.${Math.floor(Math.random() * 254) + 1}`,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0',
      isAnomalousTime: false,
      isBruteForce: false,
      riskScore: isSuccess ? 0 : 15
    });
  }
}

seedHistoricalData();

// ==========================================
// 3. API ENDPOINTS (DASHBOARD & ENGINE CONTROL)
// ==========================================

// GET Email Status
app.get('/api/email-status', (req, res) => {
  res.json({
    enabled: EMAIL_ALERTS_ENABLED,
    smtpHost: SMTP_HOST,
    smtpPort: SMTP_PORT,
    smtpUser: SMTP_USER,
    alertEmailTo: ALERT_EMAIL_TO,
    smtpPassConfigured: Boolean(SMTP_PASS),
    missing: {
      smtpPass: !SMTP_PASS,
      alertEmailTo: !ALERT_EMAIL_TO
    }
  });
});

// GET Dashboard Data
app.get('/api/dashboard', (req, res) => {
  const now = new Date();
  
  Object.keys(users).forEach(key => {
    const user = users[key];
    if (user.lockoutUntil && new Date(user.lockoutUntil) <= now) {
      user.lockoutUntil = null;
      user.failedAttemptsCount = 0;
      user.consecutiveFails = [];
    }
    updateRiskScore(key);
  });

  const activeAlerts = alerts.filter(a => a.status === 'active').length;
  const lockedAccounts = Object.values(users).filter(u => u.lockoutUntil && new Date(u.lockoutUntil) > now).length;

  res.json({
    metrics: {
      totalLogins: loginLogs.length,
      failedLogins: loginLogs.filter(l => l.status === 'failed').length,
      activeAlerts,
      lockedAccounts
    },
    users: Object.keys(users).map(key => ({
      key,
      ...users[key]
    })),
    blockedIPs: Array.from(blockedIPs),
    logs: loginLogs.slice(0, 150),
    alerts: alerts.slice(0, 50),
    config
  });
});

// POST Login Endpoint (with Firewall checks & MFA)
app.post('/api/login', (req, res) => {
  const { username, password, simulatedHour, ipAddress } = req.body;
  const now = new Date();
  const userKey = username ? username.toLowerCase().trim() : '';
  const currentHour = simulatedHour !== undefined ? Number(simulatedHour) : now.getHours();
  const clientIp = ipAddress || req.ip || '127.0.0.1';
  const clientUserAgent = req.headers['user-agent'] || 'Mock Agent';

  // 1. IP Firewall Check
  if (blockedIPs.has(clientIp)) {
    return res.status(403).json({
      success: false,
      message: `FIREWALL BLOCK: Access denied. IP address ${clientIp} is listed on the Aegis blacklist.`,
      firewallBlock: true
    });
  }

  // 2. Validate User Existence
  const user = users[userKey];
  if (!user) {
    const logItem = {
      id: `log_${Date.now()}`,
      timestamp: now.toISOString(),
      username: userKey,
      realName: `Unknown Node (${userKey})`,
      status: 'failed',
      simulatedHour: currentHour,
      ipAddress: clientIp,
      userAgent: clientUserAgent,
      isAnomalousTime: false,
      isBruteForce: false,
      riskScore: 40
    };
    loginLogs.unshift(logItem);

    // IP Spanning Scanner
    const ipFailsCount = loginLogs.filter(l => l.ipAddress === clientIp && l.status === 'failed' && (now - new Date(l.timestamp)) < config.bruteForceWindowSeconds * 1000).length;
    if (ipFailsCount >= config.failedAttemptsLimit) {
      triggerAlert('brute_force', 'high', 'unknown', `Active brute scan vector flagged from IP ${clientIp}. Blocking recommended.`, { ipAddress: clientIp });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  }

  // 3. Check Lockout State
  if (user.lockoutUntil && new Date(user.lockoutUntil) > now) {
    const remainingTime = Math.ceil((new Date(user.lockoutUntil) - now) / 1000);
    return res.status(403).json({
      success: false,
      message: `Profile suspended. Security breach trigger active. Wait ${remainingTime}s before retry.`,
      lockout: true,
      remainingTime
    });
  }

  // 4. Validate Credentials (support hashed password stored on profile)
  let isPasswordCorrect = false;
  if (user.passwordHash && user.passwordSalt) {
    try {
      const derived = crypto.pbkdf2Sync(String(password), user.passwordSalt, 100000, 64, 'sha512').toString('hex');
      isPasswordCorrect = derived === user.passwordHash;
    } catch (e) {
      isPasswordCorrect = false;
    }
  } else {
    // fallback to legacy behavior
    isPasswordCorrect = (password === 'password123');
  }
  let isAnomalousTime = false;
  let isBruteForce = false;
  let msg = '';

  if (isPasswordCorrect) {
    // SUCCESSFUL AUTH
    isAnomalousTime = !user.baselineHours.includes(currentHour);
    
    if (isAnomalousTime) {
      msg = 'Access cleared, but dynamic timing anomaly detected.';
      triggerAlert(
        'unusual_timing',
        'medium',
        userKey,
        `Timing anomaly: ${user.username} logged in at ${currentHour.toString().padStart(2, '0')}:00. Profile standard schedule: ${user.baselineHours[0].toString().padStart(2, '0')}:00 to ${user.baselineHours[user.baselineHours.length - 1].toString().padStart(2, '0')}:00`,
        { anomalousHour: currentHour }
      );
    } else {
      msg = 'Authentication fully approved and validated.';
    }

    user.failedAttemptsCount = 0;
    user.consecutiveFails = [];

    const logItem = {
      id: `log_${Date.now()}`,
      timestamp: now.toISOString(),
      username: userKey,
      realName: user.username,
      status: 'success',
      simulatedHour: currentHour,
      ipAddress: clientIp,
      userAgent: clientUserAgent,
      isAnomalousTime,
      isBruteForce: false,
      riskScore: user.riskScore
    };
    loginLogs.unshift(logItem);
    updateRiskScore(userKey);

    return res.json({
      success: true,
      message: msg,
      anomalousTime: isAnomalousTime,
      user: {
        username: userKey,
        realName: user.username,
        riskScore: user.riskScore,
        mfaEnforced: user.mfaEnforced
      }
    });

  } else {
    // FAILED AUTH
    user.failedAttemptsCount += 1;
    const failTimestamp = now.getTime();
    user.consecutiveFails.push(failTimestamp);

    user.consecutiveFails = user.consecutiveFails.filter(t => (failTimestamp - t) < config.bruteForceWindowSeconds * 1000);
    const recentFails = user.consecutiveFails.length;

    if (recentFails >= config.failedAttemptsLimit) {
      isBruteForce = true;
      user.lockoutUntil = new Date(now.getTime() + config.lockoutDurationMinutes * 60 * 1000).toISOString();
      
      triggerAlert(
        'account_lockout',
        'high',
        userKey,
        `Account Locked: ${user.username} exceeded maximum failed limits (${config.failedAttemptsLimit} fails) within ${config.bruteForceWindowSeconds}s window.`
      );
      msg = 'Profile locked out. Multiple failed auth passes flagged as brute force.';
    } else {
      msg = `Credentials mismatch. Attempt ${recentFails} of ${config.failedAttemptsLimit}.`;
    }

    const logItem = {
      id: `log_${Date.now()}`,
      timestamp: now.toISOString(),
      username: userKey,
      realName: user.username,
      status: 'failed',
      simulatedHour: currentHour,
      ipAddress: clientIp,
      userAgent: clientUserAgent,
      isAnomalousTime: false,
      isBruteForce,
      riskScore: user.riskScore
    };
    loginLogs.unshift(logItem);
    updateRiskScore(userKey);

    return res.status(401).json({
      success: false,
      message: msg,
      failedAttempts: recentFails,
      lockout: isBruteForce,
      lockoutUntil: user.lockoutUntil
    });
  }
});

// POST Resolve & Auto-Train Baseline (Feedback loop)
app.post('/api/alerts/resolve-and-learn', (req, res) => {
  const { alertId } = req.body;
  const alert = alerts.find(a => a.id === alertId);

  if (!alert) {
    return res.status(404).json({ success: false, message: 'Alert not found.' });
  }

  alert.status = 'resolved';

  // Perform "baselines re-learning"
  if (alert.type === 'unusual_timing' && alert.meta && alert.meta.anomalousHour !== undefined) {
    const user = users[alert.username];
    if (user) {
      const trainedHour = Number(alert.meta.anomalousHour);
      if (!user.baselineHours.includes(trainedHour)) {
        user.baselineHours.push(trainedHour);
        // sort baseline hours chronologically
        user.baselineHours.sort((a, b) => a - b);
        alert.message += ` [Engine updated: Learned ${trainedHour}:00 into baseline]`;
      }
    }
  }

  if (alert.username && users[alert.username]) {
    updateRiskScore(alert.username);
  }

  res.json({ success: true, message: `Alert resolved and baseline hours auto-trained!`, alert });
});

// POST Resolve alert standard
app.post('/api/alerts/resolve', (req, res) => {
  const { alertId } = req.body;
  const alert = alerts.find(a => a.id === alertId);

  if (!alert) {
    return res.status(404).json({ success: false, message: 'Alert not found.' });
  }

  alert.status = 'resolved';
  if (alert.username && users[alert.username]) {
    updateRiskScore(alert.username);
  }

  res.json({ success: true, message: `Alert ${alertId} marked resolved.` });
});

// POST Toggle MFA (Risk Mitigation)
app.post('/api/users/mfa', (req, res) => {
  const { username } = req.body;
  const userKey = username ? username.toLowerCase() : '';
  const user = users[userKey];

  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found.' });
  }

  user.mfaEnforced = !user.mfaEnforced;
  updateRiskScore(userKey);

  res.json({
    success: true, 
    message: `${user.username} Multi-Factor Auth state set to: ${user.mfaEnforced ? 'ENFORCED' : 'OFF'}`,
    mfaEnforced: user.mfaEnforced
  });
});

// POST Unlock Account
app.post('/api/users/unlock', (req, res) => {
  const { username } = req.body;
  const userKey = username ? username.toLowerCase() : '';
  const user = users[userKey];

  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found.' });
  }

  user.lockoutUntil = null;
  user.failedAttemptsCount = 0;
  user.consecutiveFails = [];
  
  alerts.forEach(a => {
    if (a.username === userKey && a.type === 'account_lockout') {
      a.status = 'resolved';
    }
  });

  updateRiskScore(userKey);
  res.json({ success: true, message: `Suspension lifted for ${user.username}.` });
});

// POST Change Password
app.post('/api/users/change-password', (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  if (!username || !oldPassword || !newPassword) return res.status(400).json({ success: false, message: 'username, oldPassword and newPassword required.' });

  const userKey = username.toLowerCase();
  const user = users[userKey];
  if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

  // verify old password
  let ok = false;
  if (user.passwordHash && user.passwordSalt) {
    try {
      const derived = crypto.pbkdf2Sync(String(oldPassword), user.passwordSalt, 100000, 64, 'sha512').toString('hex');
      ok = derived === user.passwordHash;
    } catch (e) {
      ok = false;
    }
  } else {
    ok = (oldPassword === 'password123');
  }

  if (!ok) return res.status(401).json({ success: false, message: 'Current password incorrect.' });

  // set new password
  const { salt, hash } = hashPassword(newPassword);
  user.passwordSalt = salt;
  user.passwordHash = hash;
  saveUsersToDisk();

  res.json({ success: true, message: 'Password updated.' });
});

// POST Request password reset (sends reset token to user's email)
app.post('/api/users/request-reset', (req, res) => {
  const { usernameOrEmail } = req.body;
  if (!usernameOrEmail) return res.status(400).json({ success: false, message: 'usernameOrEmail required.' });

  // try find by username key or by email
  const key = (usernameOrEmail || '').toLowerCase();
  let userKey = Object.keys(users).find(k => k === key || (users[k].email && users[k].email.toLowerCase() === key));
  if (!userKey) return res.status(404).json({ success: false, message: 'User not found.' });

  const user = users[userKey];
  const resetToken = generateToken(16);
  user.resetToken = resetToken;
  user.resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  saveUsersToDisk();
  sendResetEmail(user, resetToken).catch(() => {});
  res.json({ success: true, message: 'Password reset token sent to the registered email (if configured).' });
});

// POST perform reset by token
app.post('/api/users/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ success: false, message: 'token and newPassword required.' });

  const userKey = Object.keys(users).find(k => users[k].resetToken === token);
  if (!userKey) return res.status(404).json({ success: false, message: 'Invalid token.' });

  const user = users[userKey];
  if (!user.resetTokenExpires || new Date(user.resetTokenExpires) < new Date()) {
    return res.status(400).json({ success: false, message: 'Token expired.' });
  }

  const { salt, hash } = hashPassword(newPassword);
  user.passwordSalt = salt;
  user.passwordHash = hash;
  delete user.resetToken;
  delete user.resetTokenExpires;
  saveUsersToDisk();

  res.json({ success: true, message: 'Password updated via reset token.' });
});

// POST verify email token
app.post('/api/users/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ success: false, message: 'token required.' });

  const userKey = Object.keys(users).find(k => users[k].verifyToken === token);
  if (!userKey) return res.status(404).json({ success: false, message: 'Invalid token.' });

  const user = users[userKey];
  if (!user.verifyTokenExpires || new Date(user.verifyTokenExpires) < new Date()) {
    return res.status(400).json({ success: false, message: 'Token expired.' });
  }

  user.emailVerified = true;
  delete user.verifyToken;
  delete user.verifyTokenExpires;
  saveUsersToDisk();
  res.json({ success: true, message: 'Email verified.' });
});

// POST Firewall Rules Adjustments
app.post('/api/ip/block', (req, res) => {
  const { ipAddress } = req.body;
  if (!ipAddress) return res.status(400).json({ success: false, message: 'IP address required.' });
  
  blockedIPs.add(ipAddress.trim());
  res.json({ success: true, message: `IP ${ipAddress} blocked globally.`, blockedIPs: Array.from(blockedIPs) });
});

app.post('/api/ip/unblock', (req, res) => {
  const { ipAddress } = req.body;
  if (!ipAddress) return res.status(400).json({ success: false, message: 'IP address required.' });
  
  blockedIPs.delete(ipAddress.trim());
  res.json({ success: true, message: `IP ${ipAddress} unblocked.`, blockedIPs: Array.from(blockedIPs) });
});

// POST Register new user (simple in-memory registration)
app.post('/api/register', (req, res) => {
  const { username, displayName, role, password, email } = req.body;
  if (!username) return res.status(400).json({ success: false, message: 'Username is required.' });

  const userKey = username.toLowerCase().trim();
  if (users[userKey]) {
    return res.status(409).json({ success: false, message: 'User already exists.' });
  }

  // Create a minimal profile; password scheme is mocked (server accepts 'password123')
  const newUser = {
    username: displayName || username,
    role: role || 'User',
    avatar: '👤',
    baselineHours: [9,10,11,12,13,14,15,16],
    failedAttemptsCount: 0,
    lockoutUntil: null,
    riskScore: 0,
    consecutiveFails: [],
    ipBaseline: req.ip || '127.0.0.1',
    mfaEnforced: false
  };

  // If password provided, persist a hashed credential
  if (password) {
    const { salt, hash } = hashPassword(password);
    newUser.passwordSalt = salt;
    newUser.passwordHash = hash;
  } else {
    // default to same behaviour as legacy (accept password123) but store a hash of password123
    const { salt, hash } = hashPassword('password123');
    newUser.passwordSalt = salt;
    newUser.passwordHash = hash;
  }

  users[userKey] = newUser;

  // Persist users
  saveUsersToDisk();

  // Create a lightweight registration log
  loginLogs.unshift({
    id: `reg_${Date.now()}`,
    timestamp: new Date().toISOString(),
    username: userKey,
    realName: users[userKey].username,
    status: 'registered',
    simulatedHour: new Date().getHours(),
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Registration-Client',
    isAnomalousTime: false,
    isBruteForce: false,
    riskScore: 0
  });
  // generate email verification token and send (async)
  const verifyToken = generateToken(12);
  users[userKey].verifyToken = verifyToken;
  users[userKey].verifyTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  users[userKey].email = email || null;
  saveUsersToDisk();
  sendVerificationEmail(users[userKey], verifyToken).catch(() => {});

  return res.json({ success: true, message: 'Registration successful. Verification email sent (if SMTP configured).', userKey });
});

// POST Save thresholds config
app.post('/api/config', (req, res) => {
  const { failedAttemptsLimit, bruteForceWindowSeconds, lockoutDurationMinutes, autoLearnHours } = req.body;
  
  if (failedAttemptsLimit !== undefined) config.failedAttemptsLimit = Number(failedAttemptsLimit);
  if (bruteForceWindowSeconds !== undefined) config.bruteForceWindowSeconds = Number(bruteForceWindowSeconds);
  if (lockoutDurationMinutes !== undefined) config.lockoutDurationMinutes = Number(lockoutDurationMinutes);
  if (autoLearnHours !== undefined) config.autoLearnHours = Boolean(autoLearnHours);

  res.json({ success: true, config });
});

// POST Clear Database
app.post('/api/alerts/clear-all', (req, res) => {
  alerts = [];
  loginLogs = [];
  blockedIPs.clear();
  Object.keys(users).forEach(key => {
    users[key].failedAttemptsCount = 0;
    users[key].lockoutUntil = null;
    users[key].consecutiveFails = [];
    users[key].riskScore = 0;
  });
  res.json({ success: true });
});

// POST Trigger Scenarios
app.post('/api/simulate', (req, res) => {
  const { scenario } = req.body;
  const now = new Date();
  
  if (scenario === 'brute_force') {
    const target = 'charlie';
    const user = users[target];
    user.consecutiveFails = [];
    user.failedAttemptsCount = 0;
    const fakeIp = `203.0.113.${Math.floor(Math.random() * 254) + 1}`;
    
    for (let i = 0; i < 5; i++) {
      const timeOffset = new Date(now.getTime() - (5 - i) * 1000);
      user.failedAttemptsCount += 1;
      user.consecutiveFails.push(timeOffset.getTime());
      
      loginLogs.unshift({
        id: `sim_bf_${Date.now()}_${i}`,
        timestamp: timeOffset.toISOString(),
        username: target,
        realName: user.username,
        status: 'failed',
        simulatedHour: now.getHours(),
        ipAddress: fakeIp,
        userAgent: 'Hydra/9.5 (Brute Force Simulator Tool)',
        isAnomalousTime: false,
        isBruteForce: false,
        riskScore: 25 + (i * 12)
      });
    }

    user.lockoutUntil = new Date(now.getTime() + config.lockoutDurationMinutes * 60 * 1000).toISOString();
    loginLogs.unshift({
      id: `sim_bf_lock_${Date.now()}`,
      timestamp: now.toISOString(),
      username: target,
      realName: user.username,
      status: 'failed',
      simulatedHour: now.getHours(),
      ipAddress: fakeIp,
      userAgent: 'Hydra/9.5 (Brute Force Simulator Tool)',
      isAnomalousTime: false,
      isBruteForce: true,
      riskScore: 100
    });

    triggerAlert('brute_force', 'high', target, `SIMULATED ATTACK: Brute force vector on ${user.username}. 5 failed attempts in 5s from IP ${fakeIp}.`, { ipAddress: fakeIp });
    triggerAlert('account_lockout', 'high', target, `SIMULATED MITIGATION: ${user.username} account suspended for ${config.lockoutDurationMinutes}m.`);
    
    updateRiskScore(target);
    return res.json({ success: true, message: 'Brute force attack simulation complete.' });

  } else if (scenario === 'unusual_timing') {
    const target = 'diana_hr'; // Diana Hr expected hours: 6 AM to 3 PM
    const user = users[target];
    const anomalousHour = 23; // 11 PM
    const fakeIp = user.ipBaseline;

    loginLogs.unshift({
      id: `sim_ut_${Date.now()}`,
      timestamp: now.toISOString(),
      username: target,
      realName: user.username,
      status: 'success',
      simulatedHour: anomalousHour,
      ipAddress: fakeIp,
      userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148',
      isAnomalousTime: true,
      isBruteForce: false,
      riskScore: 40
    });

    triggerAlert(
      'unusual_timing',
      'medium',
      target,
      `SIMULATED ANOMALY: Unusual timing. ${user.username} logged in at 11:00 PM. Baseline shifts: 06:00 AM - 03:00 PM.`,
      { anomalousHour }
    );

    updateRiskScore(target);
    return res.json({ success: true, message: 'Unusual timing attack simulation complete.' });

  } else if (scenario === 'credential_stuffing') {
    const attackerIp = '198.51.100.99';
    const targets = ['alice', 'bob', 'sec_admin', 'diana_hr', 'ethan_dev'];
    
    targets.forEach((target, idx) => {
      const isExist = users[target];
      const realName = isExist ? isExist.username : `Unknown (${target})`;
      
      loginLogs.unshift({
        id: `sim_cs_${Date.now()}_${idx}`,
        timestamp: new Date(now.getTime() - idx * 200).toISOString(),
        username: target,
        realName: realName,
        status: 'failed',
        simulatedHour: now.getHours(),
        ipAddress: attackerIp,
        userAgent: 'Sentry/0.8.2-beta (Stuffing Script)',
        isAnomalousTime: false,
        isBruteForce: false,
        riskScore: isExist ? 30 : 45
      });

      if (isExist) {
        isExist.failedAttemptsCount += 1;
        isExist.consecutiveFails.push(now.getTime());
        updateRiskScore(target);
      }
    });

    triggerAlert(
      'brute_force',
      'high',
      'multiple',
      `SIMULATED CRITICAL: Distributed Credential Stuffing detected. Rapid failures from known threat IP ${attackerIp} spanning multiple credentials.`,
      { ipAddress: attackerIp }
    );

    return res.json({ success: true, message: 'Credential stuffing simulation complete. IP logged.' });

  } else if (scenario === 'test_alert') {
    const target = 'sec_admin';
    const user = users[target];

    loginLogs.unshift({
      id: `sim_test_${Date.now()}`,
      timestamp: now.toISOString(),
      username: target,
      realName: user.username,
      status: 'success',
      simulatedHour: now.getHours(),
      ipAddress: user.ipBaseline,
      userAgent: 'Aegis Test Alert Generator',
      isAnomalousTime: false,
      isBruteForce: false,
      riskScore: 10
    });

    triggerAlert(
      'test_alert',
      'medium',
      target,
      `TEST ALERT: This is a test alert for ${user.username}. Verify email notification delivery.`,
      { test: true }
    );

    updateRiskScore(target);
    return res.json({ success: true, message: 'Test alert generated. Check your email if SMTP is configured.' });
  } else if (scenario === 'clean_traffic') {
    const keys = Object.keys(users);
    keys.forEach((key, idx) => {
      const user = users[key];
      const normalHour = user.baselineHours.length > 0 ? user.baselineHours[Math.floor(user.baselineHours.length / 2)] : 10;
      
      loginLogs.unshift({
        id: `sim_clean_${Date.now()}_${idx}`,
        timestamp: new Date(now.getTime() - idx * 10 * 1000).toISOString(),
        username: key,
        realName: user.username,
        status: 'success',
        simulatedHour: normalHour,
        ipAddress: user.ipBaseline,
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
        isAnomalousTime: false,
        isBruteForce: false,
        riskScore: 0
      });

      user.failedAttemptsCount = 0;
      user.consecutiveFails = [];
      updateRiskScore(key);
    });

    return res.json({ success: true, message: 'Normal network activity simulated.' });
  }

  res.status(400).json({ success: false, message: 'Invalid scenario.' });
});

// START
app.listen(PORT, () => {
  console.log(`🔒 Server is re-initialized and running on: http://localhost:${PORT}`);
});
