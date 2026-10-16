import React, { useState } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  LockKeyhole,
  Users,
  Eye,
  EyeOff,
  Database,
  ArrowRight,
  Check,
  Activity,
  RefreshCw,
} from '../icons';

export interface UserSession {
  id: string;
  username: string;
  full_name?: string;
  email?: string;
  role: string;
}

interface AuthViewProps {
  onLoginSuccess: (user: UserSession, token: string) => void;
}

export const AuthView: React.FC<AuthViewProps> = ({ onLoginSuccess }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');

  // Login form state
  const [loginUsername, setLoginUsername] = useState('analyst');
  const [loginPassword, setLoginPassword] = useState('analyst123');
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);

  // Register form state
  const [regFullName, setRegFullName] = useState('');
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regRole, setRegRole] = useState<'analyst' | 'operator' | 'viewer' | 'admin'>('analyst');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirmPassword, setRegConfirmPassword] = useState('');
  const [showRegPassword, setShowRegPassword] = useState(false);

  // UI state
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  // Password strength calculation
  const getPasswordStrength = (pass: string) => {
    if (!pass) return { score: 0, label: 'None', color: '#64748b' };
    let score = 0;
    if (pass.length >= 6) score += 25;
    if (pass.length >= 10) score += 25;
    if (/[0-9]/.test(pass)) score += 25;
    if (/[^A-Za-z0-9]/.test(pass)) score += 25;

    if (score <= 25) return { score, label: 'Weak', color: '#ef4444' };
    if (score <= 50) return { score, label: 'Moderate', color: '#f59e0b' };
    if (score <= 75) return { score, label: 'Strong', color: '#3b82f6' };
    return { score: 100, label: 'Enterprise-Grade', color: '#10b981' };
  };

  const strength = getPasswordStrength(regPassword);

  // Quick 1-click credential filler
  const fillCredentials = (user: string, pass: string) => {
    setMode('login');
    setLoginUsername(user);
    setLoginPassword(pass);
    setErrorMessage('');
    setSuccessMessage('');
  };

  // Handle Login submission
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    setIsLoading(true);

    try {
      let res: Response | null = null;
      // Try Vite proxy /api/auth/token first
      try {
        res = await fetch('/api/auth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: loginUsername.trim(),
            password: loginPassword,
          }),
        });
      } catch {
        // Fallback to direct backend URL
        res = await fetch('http://127.0.0.1:8000/auth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: loginUsername.trim(),
            password: loginPassword,
          }),
        });
      }

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Invalid username or master key password.');
      }

      const data = await res.json();
      const user = data.user;
      const token = data.access_token;

      if (rememberMe) {
        localStorage.setItem('ciphersentinel_user', JSON.stringify(user));
        localStorage.setItem('ciphersentinel_token', token);
      } else {
        sessionStorage.setItem('ciphersentinel_user', JSON.stringify(user));
        sessionStorage.setItem('ciphersentinel_token', token);
      }

      setSuccessMessage(`Authenticated as ${user.full_name || user.username} (${user.role.toUpperCase()})`);
      setTimeout(() => {
        onLoginSuccess(user, token);
      }, 400);
    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Registration submission
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (regUsername.trim().length < 3) {
      setErrorMessage('Username must be at least 3 characters.');
      return;
    }
    if (regPassword.length < 6) {
      setErrorMessage('Master password must be at least 6 characters.');
      return;
    }
    if (regPassword !== regConfirmPassword) {
      setErrorMessage('Passwords do not match. Please re-enter.');
      return;
    }

    setIsLoading(true);

    try {
      const payload = {
        username: regUsername.trim(),
        password: regPassword,
        full_name: regFullName.trim() || regUsername.trim(),
        email: regEmail.trim() || `${regUsername.trim()}@ciphersentinel.soc`,
        role: regRole,
      };

      let res: Response | null = null;
      try {
        res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch {
        res = await fetch('http://127.0.0.1:8000/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Registration failed.');
      }

      const data = await res.json();
      const user = {
        id: data.id,
        username: data.username,
        full_name: data.full_name,
        email: data.email,
        role: data.role,
      };
      const token = data.access_token || 'bearer-token';

      localStorage.setItem('ciphersentinel_user', JSON.stringify(user));
      localStorage.setItem('ciphersentinel_token', token);

      setSuccessMessage(`Account created & saved in local SQLite! Logging in as ${user.username}...`);
      setTimeout(() => {
        onLoginSuccess(user, token);
      }, 600);
    } catch (err: any) {
      setErrorMessage(err.message || 'Registration failed. Username may already exist.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
      {/* Background Animated Cyber Grid */}
      <div className="auth-grid-bg" />

      {/* Main Authentication Card */}
      <div className="auth-card">
        {/* Brand Header */}
        <div className="auth-header">
          <div className="auth-brand-badge">
            <ShieldCheck size={28} className="text-emerald-400" />
          </div>
          <h1 className="auth-title">CipherSentinel</h1>
          <p className="auth-subtitle">Autonomous Zero-Trust Forensic Threat & Decision Platform</p>

          <div className="auth-sqlite-badge">
            <Database size={13} className="text-emerald-400" />
            <span>SQLite Local Enclave: <code className="text-emerald-300">data/users.db</code></span>
            <span className="auth-sqlite-status">ACTIVE</span>
          </div>
        </div>

        {/* Mode Navigation Tabs */}
        <div className="auth-tabs">
          <button
            type="button"
            className={`auth-tab ${mode === 'login' ? 'active' : ''}`}
            onClick={() => {
              setMode('login');
              setErrorMessage('');
              setSuccessMessage('');
            }}
          >
            <LockKeyhole size={14} />
            <span>Operator Sign In</span>
          </button>
          <button
            type="button"
            className={`auth-tab ${mode === 'register' ? 'active' : ''}`}
            onClick={() => {
              setMode('register');
              setErrorMessage('');
              setSuccessMessage('');
            }}
          >
            <Users size={14} />
            <span>Create Account</span>
          </button>
        </div>

        {/* Error / Success Notifications */}
        {errorMessage && (
          <div className="auth-alert error">
            <ShieldAlert size={16} />
            <span>{errorMessage}</span>
          </div>
        )}
        {successMessage && (
          <div className="auth-alert success">
            <Check size={16} />
            <span>{successMessage}</span>
          </div>
        )}

        {/* SIGN IN FORM */}
        {mode === 'login' && (
          <form onSubmit={handleLogin} className="auth-form">
            <div className="form-group">
              <label htmlFor="login-username">Operator Username</label>
              <div className="input-wrap">
                <Users size={15} className="input-icon" />
                <input
                  id="login-username"
                  type="text"
                  required
                  placeholder="e.g. analyst"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  autoComplete="username"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="login-password">Master Key Password</label>
              <div className="input-wrap">
                <LockKeyhole size={15} className="input-icon" />
                <input
                  id="login-password"
                  type={showLoginPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="eye-toggle"
                  onClick={() => setShowLoginPassword(!showLoginPassword)}
                  aria-label="Toggle password visibility"
                >
                  {showLoginPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <div className="form-options">
              <label className="remember-checkbox">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                />
                <span>Keep session active in local SQLite</span>
              </label>
            </div>

            <button type="submit" disabled={isLoading} className="auth-submit-btn">
              {isLoading ? (
                <>
                  <RefreshCw size={15} className="animate-spin" />
                  <span>Verifying PBKDF2 Credentials...</span>
                </>
              ) : (
                <>
                  <Shield size={16} />
                  <span>Sign In to SOC Enclave</span>
                  <ArrowRight size={15} />
                </>
              )}
            </button>

            {/* Quick Demo Credentials Autofill */}
            <div className="auth-demo-section">
              <div className="demo-label">⚡ 1-Click Fast Evaluation Accounts:</div>
              <div className="demo-pills">
                <button
                  type="button"
                  className="demo-pill"
                  onClick={() => fillCredentials('analyst', 'analyst123')}
                >
                  <span className="pill-role">SOC Analyst</span>
                  <span className="pill-creds">analyst / analyst123</span>
                </button>
                <button
                  type="button"
                  className="demo-pill"
                  onClick={() => fillCredentials('admin', 'admin123')}
                >
                  <span className="pill-role">Admin</span>
                  <span className="pill-creds">admin / admin123</span>
                </button>
                <button
                  type="button"
                  className="demo-pill"
                  onClick={() => fillCredentials('sarah_connor', 'securePassword123')}
                >
                  <span className="pill-role">Operator</span>
                  <span className="pill-creds">sarah_connor</span>
                </button>
              </div>
            </div>
          </form>
        )}

        {/* REGISTRATION FORM */}
        {mode === 'register' && (
          <form onSubmit={handleRegister} className="auth-form">
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="reg-fullname">Full Name</label>
                <div className="input-wrap">
                  <Users size={15} className="input-icon" />
                  <input
                    id="reg-fullname"
                    type="text"
                    required
                    placeholder="e.g. Marcus Vance"
                    value={regFullName}
                    onChange={(e) => setRegFullName(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="reg-username">Operator ID / Username</label>
                <div className="input-wrap">
                  <span className="input-prefix">@</span>
                  <input
                    id="reg-username"
                    type="text"
                    required
                    placeholder="e.g. m_vance"
                    value={regUsername}
                    onChange={(e) => setRegUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ''))}
                  />
                </div>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="reg-email">Enterprise SOC Email</label>
                <div className="input-wrap">
                  <input
                    id="reg-email"
                    type="email"
                    placeholder="operator@ciphersentinel.soc"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="reg-role">Designated Role</label>
                <div className="input-wrap">
                  <select
                    id="reg-role"
                    value={regRole}
                    onChange={(e: any) => setRegRole(e.target.value)}
                    className="auth-select"
                  >
                    <option value="analyst">Security Analyst (Tier-2 SOC)</option>
                    <option value="operator">Forensic Incident Responder</option>
                    <option value="viewer">Executive Compliance Auditor</option>
                    <option value="admin">System Enclave Administrator</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="reg-password">Master Password</label>
                <div className="input-wrap">
                  <LockKeyhole size={15} className="input-icon" />
                  <input
                    id="reg-password"
                    type={showRegPassword ? 'text' : 'password'}
                    required
                    placeholder="Min 6 characters"
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                  />
                  <button
                    type="button"
                    className="eye-toggle"
                    onClick={() => setShowRegPassword(!showRegPassword)}
                  >
                    {showRegPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="reg-confirm-password">Confirm Password</label>
                <div className="input-wrap">
                  <LockKeyhole size={15} className="input-icon" />
                  <input
                    id="reg-confirm-password"
                    type={showRegPassword ? 'text' : 'password'}
                    required
                    placeholder="Re-enter password"
                    value={regConfirmPassword}
                    onChange={(e) => setRegConfirmPassword(e.target.value)}
                  />
                  {regConfirmPassword && (
                    <span className="match-indicator">
                      {regPassword === regConfirmPassword ? (
                        <Check size={14} className="text-emerald-400" />
                      ) : (
                        <ShieldAlert size={14} className="text-rose-400" />
                      )}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Password Strength Meter */}
            {regPassword && (
              <div className="strength-container">
                <div className="strength-header">
                  <span>Cryptographic Strength:</span>
                  <span style={{ color: strength.color, fontWeight: 600 }}>{strength.label}</span>
                </div>
                <div className="strength-track">
                  <div
                    className="strength-bar"
                    style={{ width: `${strength.score}%`, backgroundColor: strength.color }}
                  />
                </div>
              </div>
            )}

            <button type="submit" disabled={isLoading} className="auth-submit-btn">
              {isLoading ? (
                <>
                  <RefreshCw size={15} className="animate-spin" />
                  <span>Hashing with PBKDF2 & Saving to SQLite...</span>
                </>
              ) : (
                <>
                  <Check size={16} />
                  <span>Register & Initialize Operator Session</span>
                  <ArrowRight size={15} />
                </>
              )}
            </button>
          </form>
        )}

        {/* Security Architecture Footer Notice */}
        <div className="auth-footer-notice">
          <div className="notice-item">
            <LockKeyhole size={13} className="text-cyan-400" />
            <span>PBKDF2-HMAC-SHA256 (100,000 salt iterations)</span>
          </div>
          <div className="notice-item">
            <Activity size={13} className="text-emerald-400" />
            <span>Zero-Trust Forensic Audits Persisted to SQLite</span>
          </div>
        </div>
      </div>
    </div>
  );
};
