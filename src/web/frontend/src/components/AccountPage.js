import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { issueSessionToken } from '../api';

const heroImage = `${process.env.PUBLIC_URL}/images/rivendell.png`;

const AccountPage = () => {
  const navigate = useNavigate();
  const { user, logout, isAuthenticated } = useAuth();

  // Tab state
  const [activeTab, setActiveTab] = useState('profile');

  // Profile state
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // MFA state
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [showMfaSetup, setShowMfaSetup] = useState(false);

  // A token for scripts and Eru's MCP server (the sign-in's own kind; there are no long-lived ones)
  const [generatedToken, setGeneratedToken] = useState('');

  // Messages
  const [profileMessage, setProfileMessage] = useState({ type: '', text: '' });
  const [passwordMessage, setPasswordMessage] = useState({ type: '', text: '' });
  const [mfaMessage, setMfaMessage] = useState({ type: '', text: '' });
  const [tokenMessage, setTokenMessage] = useState({ type: '', text: '' });
  const [integrationMessage, setIntegrationMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    if (user) {
      setDisplayName(user.display_name || user.username || '');
      setEmail(user.email || '');
      setMfaEnabled(user.mfa_enabled || false);
    }
  }, [user]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    navigate('/login');
    return null;
  }

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setProfileMessage({ type: '', text: '' });

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch('/api/auth/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ display_name: displayName, email })
      });

      if (response.ok) {
        setProfileMessage({ type: 'success', text: 'Profile updated successfully.' });
      } else {
        const data = await response.json();
        setProfileMessage({ type: 'error', text: data.detail || 'Failed to update profile.' });
      }
    } catch (error) {
      setProfileMessage({ type: 'error', text: 'Failed to update profile. This feature requires backend support.' });
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPasswordMessage({ type: '', text: '' });

    if (newPassword !== confirmPassword) {
      setPasswordMessage({ type: 'error', text: 'New passwords do not match.' });
      return;
    }

    if (newPassword.length < 8) {
      setPasswordMessage({ type: 'error', text: 'Password must be at least 8 characters.' });
      return;
    }

    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });

      if (response.ok) {
        setPasswordMessage({ type: 'success', text: 'Password changed successfully.' });
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        const data = await response.json();
        setPasswordMessage({ type: 'error', text: data.detail || 'Failed to change password.' });
      }
    } catch (error) {
      setPasswordMessage({ type: 'error', text: 'Failed to change password. This feature requires backend support.' });
    }
  };

  const handleToggleMfa = async () => {
    setMfaMessage({ type: '', text: '' });

    if (!mfaEnabled) {
      setShowMfaSetup(true);
      setMfaMessage({ type: 'info', text: 'MFA setup requires backend implementation. Coming soon.' });
    } else {
      try {
        const token = localStorage.getItem('access_token');
        const response = await fetch('/api/auth/mfa/disable', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (response.ok) {
          setMfaEnabled(false);
          setMfaMessage({ type: 'success', text: 'MFA disabled successfully.' });
        } else {
          setMfaMessage({ type: 'error', text: 'Failed to disable MFA.' });
        }
      } catch (error) {
        setMfaMessage({ type: 'error', text: 'MFA management requires backend support.' });
      }
    }
  };

  const handleGenerateToken = async () => {
    setTokenMessage({ type: '', text: '' });
    try {
      setGeneratedToken((await issueSessionToken()).access_token);
    } catch (error) {
      setTokenMessage({ type: 'error', text: error.response?.data?.detail || 'Could not issue a token.' });
    }
  };

  const copyToken = async () => {
    try {
      await navigator.clipboard.writeText(generatedToken);
      setTokenMessage({ type: 'success', text: 'Copied.' });
    } catch {
      setTokenMessage({ type: 'error', text: 'Copy it from the box: the browser refused the clipboard.' });
    }
  };

  return (
    <div className="journey-detail">
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Rivendell - The Last Homely House"
          className="hero-image"
          style={{
            transform: 'scale(0.2)',
            transformOrigin: 'center top'
          }}
        />
      </section>

      <header>
        <h2>Account Settings</h2>
        <p>
          Manage your Rivendell DF Acceleration Suite account, security settings, and API access.
        </p>
      </header>

      {/* Tab Navigation */}
      <div data-guide="account.settings" className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{
          display: 'flex',
          borderBottom: '1px solid #3f4b2a',
          background: 'rgba(26, 32, 17, 0.5)'
        }}>
          <button
            onClick={() => setActiveTab('profile')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              background: activeTab === 'profile' ? 'rgba(138, 191, 77, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'profile' ? '3px solid #8abf4d' : '3px solid transparent',
              color: activeTab === 'profile' ? '#c3e88d' : '#a09580',
              cursor: 'pointer',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1rem',
              fontWeight: activeTab === 'profile' ? '600' : '400',
              transition: 'all 0.3s ease'
            }}
          >
            Profile
          </button>
          <button
            onClick={() => setActiveTab('security')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              background: activeTab === 'security' ? 'rgba(138, 191, 77, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'security' ? '3px solid #8abf4d' : '3px solid transparent',
              color: activeTab === 'security' ? '#c3e88d' : '#a09580',
              cursor: 'pointer',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1rem',
              fontWeight: activeTab === 'security' ? '600' : '400',
              transition: 'all 0.3s ease'
            }}
          >
            Security
          </button>
          <button
            onClick={() => setActiveTab('integrations')}
            style={{
              flex: 1,
              padding: '1rem 1.5rem',
              background: activeTab === 'integrations' ? 'rgba(138, 191, 77, 0.15)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === 'integrations' ? '3px solid #8abf4d' : '3px solid transparent',
              color: activeTab === 'integrations' ? '#c3e88d' : '#a09580',
              cursor: 'pointer',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1rem',
              fontWeight: activeTab === 'integrations' ? '600' : '400',
              transition: 'all 0.3s ease'
            }}
          >
            Integrations
          </button>
        </div>

        {/* Tab Content */}
        <div style={{ padding: '1.5rem' }}>

          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <>
              {/* Profile Information */}
              <div style={{ marginBottom: '2rem' }}>
                <h3 style={{ marginBottom: '1.5rem' }}>Profile Information</h3>

                {profileMessage.text && (
                  <div className={`alert-${profileMessage.type}`}>
                    {profileMessage.text}
                  </div>
                )}

                <form onSubmit={handleUpdateProfile}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1.5rem', alignItems: 'end' }}>
                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label>Username</label>
                      <input
                        type="text"
                        value={user?.username || ''}
                        disabled
                        style={{ backgroundColor: 'rgba(0,0,0,0.3)' }}
                      />
                    </div>

                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label>Email</label>
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="Enter your email"
                      />
                    </div>

                    <div className="form-group" style={{ marginBottom: 0 }}>
                      <label>Role</label>
                      <select
                        value={user?.role || 'user'}
                        disabled={user?.role !== 'admin'}
                        style={{
                          backgroundColor: user?.role !== 'admin' ? 'rgba(0,0,0,0.3)' : undefined,
                          height: '42px',
                          fontSize: '1rem',
                          textTransform: 'uppercase'
                        }}
                      >
                        <option value="admin">ADMIN</option>
                        <option value="analyst">ANALYST</option>
                        <option value="user">USER</option>
                        <option value="viewer">VIEWER</option>
                      </select>
                    </div>

                    <button type="submit" style={{ height: '42px' }}>Update Profile</button>
                  </div>
                </form>
              </div>

              {/* A token for scripts and Eru's MCP server */}
              <div style={{ paddingTop: '2rem', borderTop: '1px solid #3f4b2a' }}>
                <h3 style={{ marginBottom: '1.5rem' }}>Token for scripts and Eru's MCP server</h3>

                <p style={{ marginBottom: '1rem', color: '#a09580' }}>
                  A bearer token for your account, whichever way you signed in. It lasts as long as a sign-in does
                  (24 hours unless the server is set otherwise) and does what you can do, so keep it like a password.
                  For <code>rivendell mcp</code>, set it as <code>RIVENDELL_TOKEN</code> (docs/ERU.md).
                </p>

                {tokenMessage.text && (
                  <div className={tokenMessage.type === 'error' ? 'alert-error' : 'alert-success'}>{tokenMessage.text}</div>
                )}

                {generatedToken && (
                  <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
                    <input type="text" readOnly value={generatedToken} style={{ flex: 1, fontFamily: 'monospace' }}
                      onFocus={(e) => e.target.select()} />
                    <button type="button" className="secondary" onClick={copyToken}>Copy</button>
                  </div>
                )}

                <button type="button" onClick={handleGenerateToken}>{generatedToken ? 'Get another' : 'Get a token'}</button>
              </div>

            </>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1px 1fr', gap: '2rem' }}>
              {/* Left side - Change Password */}
              <div>
                <h3 style={{ marginBottom: '1.5rem' }}>Change Password</h3>

                {passwordMessage.text && (
                  <div className={`alert-${passwordMessage.type}`}>
                    {passwordMessage.text}
                  </div>
                )}

                <form onSubmit={handleChangePassword}>
                  <div className="form-group">
                    <label>Current Password</label>
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      placeholder="Enter current password"
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label>New Password</label>
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Enter new password"
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label>Confirm New Password</label>
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Confirm new password"
                      required
                    />
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                    <button
                      type="submit"
                      disabled={
                        !newPassword ||
                        newPassword.length < 16 ||
                        !/[A-Z]/.test(newPassword) ||
                        !/[a-z]/.test(newPassword) ||
                        !/[0-9]/.test(newPassword) ||
                        !/[-_+=:;<>.?!@£$%&]/.test(newPassword) ||
                        newPassword !== confirmPassword
                      }
                    >
                      Change Password
                    </button>

                    {/* Password Requirements Validator */}
                    {newPassword && (
                      <div style={{ fontSize: '0.95rem', lineHeight: '1.6', display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.25rem' }}>
                        <span style={{ color: newPassword.length >= 16 ? '#a6e22e' : '#f92672', marginRight: '0.75rem' }}>
                          {newPassword.length >= 16 ? '✓' : '✗'} 16+
                        </span>
                        <span style={{ color: /[A-Z]/.test(newPassword) ? '#a6e22e' : '#f92672', marginRight: '0.75rem' }}>
                          {/[A-Z]/.test(newPassword) ? '✓' : '✗'} A-Z
                        </span>
                        <span style={{ color: /[a-z]/.test(newPassword) ? '#a6e22e' : '#f92672', marginRight: '0.75rem' }}>
                          {/[a-z]/.test(newPassword) ? '✓' : '✗'} a-z
                        </span>
                        <span style={{ color: /[0-9]/.test(newPassword) ? '#a6e22e' : '#f92672', marginRight: '0.75rem' }}>
                          {/[0-9]/.test(newPassword) ? '✓' : '✗'} 0-9
                        </span>
                        <span style={{ color: /[-_+=:;<>.?!@£$%&]/.test(newPassword) ? '#a6e22e' : '#f92672', marginRight: '0.75rem' }}>
                          {/[-_+=:;<>.?!@£$%&]/.test(newPassword) ? '✓' : '✗'} !@#
                        </span>
                        <span style={{ color: confirmPassword && newPassword === confirmPassword ? '#a6e22e' : '#f92672' }}>
                          {confirmPassword && newPassword === confirmPassword ? '✓' : '✗'} Match
                        </span>
                      </div>
                    )}
                  </div>
                </form>
              </div>

              {/* Vertical Divider */}
              <div style={{ backgroundColor: '#3f4b2a' }}></div>

              {/* Right side - MFA and Backup Codes */}
              <div>
                <h3 style={{ marginBottom: '1.5rem' }}>Multi-Factor Authentication</h3>

                {mfaMessage.text && (
                  <div className={`alert-${mfaMessage.type}`}>
                    {mfaMessage.text}
                  </div>
                )}

                <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.9rem' }}>
                  Add an extra layer of security to your account using an authenticator app.
                </p>

                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
                  <span>Status:</span>
                  <span className={mfaEnabled ? 'status-badge status-completed' : 'status-badge status-pending'}>
                    {mfaEnabled ? 'Enabled' : 'Disabled'}
                  </span>
                  <button
                    onClick={handleToggleMfa}
                    className={mfaEnabled ? 'secondary' : ''}
                    style={{ marginLeft: 'auto' }}
                  >
                    {mfaEnabled ? 'Disable MFA' : 'Enable MFA'}
                  </button>
                </div>

                {showMfaSetup && !mfaEnabled && (
                  <div style={{ marginBottom: '1.5rem', padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }}>
                    <p style={{ color: '#66d9ef', fontSize: '0.9rem' }}>
                      MFA setup will display a QR code here for authenticator apps like Google Authenticator or Authy.
                    </p>
                  </div>
                )}

                <h4 style={{ color: '#f0dba5', marginBottom: '1rem', marginTop: '3rem', paddingTop: '3rem', borderTop: '1px solid #3f4b2a' }}>Backup Codes</h4>

                <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.9rem' }}>
                  Generate backup codes to access your account if you lose your authenticator device.
                </p>

                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <span>Remaining codes:</span>
                  <span className="status-badge status-pending">0 / 10</span>
                  <button
                    onClick={() => setMfaMessage({ type: 'info', text: 'Backup codes require backend implementation. Coming soon.' })}
                    disabled={!mfaEnabled}
                    style={{ marginLeft: 'auto' }}
                  >
                    Generate
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Integrations Tab */}
          {activeTab === 'integrations' && (
            <>
              {integrationMessage.text && (
                <div className={`alert-${integrationMessage.type}`} style={{ marginBottom: '1.5rem' }}>
                  {integrationMessage.text}
                </div>
              )}

              {/* AI API Keys */}
              <div style={{ marginBottom: '2.5rem' }}>
                <h3 style={{ marginBottom: '1.5rem' }}>AI Services</h3>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '2rem' }}>
                  {/* OpenAI API Key */}
                  <div>
                    <h4 style={{ color: '#f0dba5', marginBottom: '1rem' }}>OpenAI</h4>
                    <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.85rem' }}>
                      Required for Ask Eru AI assistant functionality.
                    </p>
                    <div className="form-group">
                      <label>API Key</label>
                      <input
                        type="password"
                        placeholder="sk-..."
                        style={{ fontFamily: 'monospace' }}
                      />
                    </div>
                    <button style={{ width: '100%' }}>Save Key</button>
                  </div>

                  {/* Anthropic API Key */}
                  <div>
                    <h4 style={{ color: '#f0dba5', marginBottom: '1rem' }}>Anthropic</h4>
                    <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.85rem' }}>
                      Alternative AI provider for Claude models.
                    </p>
                    <div className="form-group">
                      <label>API Key</label>
                      <input
                        type="password"
                        placeholder="sk-ant-..."
                        style={{ fontFamily: 'monospace' }}
                      />
                    </div>
                    <button style={{ width: '100%' }}>Save Key</button>
                  </div>

                  {/* VirusTotal API Key */}
                  <div>
                    <h4 style={{ color: '#f0dba5', marginBottom: '1rem' }}>VirusTotal</h4>
                    <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.85rem' }}>
                      For malware analysis and hash lookups.
                    </p>
                    <div className="form-group">
                      <label>API Key</label>
                      <input
                        type="password"
                        placeholder="Enter API key"
                        style={{ fontFamily: 'monospace' }}
                      />
                    </div>
                    <button style={{ width: '100%' }}>Save Key</button>
                  </div>
                </div>
              </div>

              {/* SIEM API Keys */}
              <div style={{ paddingTop: '2rem', borderTop: '1px solid #3f4b2a' }}>
                <h3 style={{ marginBottom: '1.5rem' }}>SIEM Integrations</h3>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                  {/* Splunk */}
                  <div>
                    <h4 style={{ color: '#f0dba5', marginBottom: '1rem' }}>Splunk</h4>
                    <div className="form-group">
                      <label>API Token</label>
                      <input
                        type="password"
                        placeholder="Enter Splunk HEC token"
                        style={{ fontFamily: 'monospace' }}
                      />
                    </div>
                    <button style={{ width: '100%' }}>Save Token</button>
                  </div>

                  {/* Elasticsearch */}
                  <div>
                    <h4 style={{ color: '#f0dba5', marginBottom: '1rem' }}>Elasticsearch</h4>
                    <div className="form-group">
                      <label>API Key</label>
                      <input
                        type="password"
                        placeholder="Enter Elasticsearch API key"
                        style={{ fontFamily: 'monospace' }}
                      />
                    </div>
                    <button style={{ width: '100%' }}>Save Key</button>
                  </div>
                </div>
              </div>
            </>
          )}

        </div>
      </div>
    </div>
  );
};

export default AccountPage;
