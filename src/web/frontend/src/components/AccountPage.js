import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { listApiTokens, createApiToken, revokeApiToken } from '../api';
import { CSRF_HEADERS } from '../apiBase';
import MfaPanels from './MfaPanels';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.png`;

const AccountPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout, isAuthenticated } = useAuth();

  // Tab state: sign-in sends someone a server requires MFA of straight to Security
  const [activeTab, setActiveTab] = useState(location.state?.tab || 'profile');

  // Profile state
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Long-lived tokens for scripts and Smith's MCP server (auth/tokens.py)
  const [generatedToken, setGeneratedToken] = useState('');
  const [apiTokens, setApiTokens] = useState([]);
  const [tokensAvailable, setTokensAvailable] = useState(true);
  const [tokenName, setTokenName] = useState('');
  const [tokenScope, setTokenScope] = useState('smith-mcp');
  const [tokenDays, setTokenDays] = useState(90);

  // Messages
  const [profileMessage, setProfileMessage] = useState({ type: '', text: '' });
  const [passwordMessage, setPasswordMessage] = useState({ type: '', text: '' });
  const [tokenMessage, setTokenMessage] = useState({ type: '', text: '' });
  const [integrationMessage, setIntegrationMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    if (user) {
      setDisplayName(user.display_name || user.username || '');
      setEmail(user.email || '');
    }
  }, [user]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  // Hooks before the redirect below: React needs the same hooks on every render
  const loadTokens = async () => {
    try {
      setApiTokens(await listApiTokens());
    } catch (error) {
      // 400 on an analyst's own machine: the API needs no token there
      if (error.response?.status === 400) setTokensAvailable(false);
      setTokenMessage({ type: 'error', text: error.response?.data?.detail || 'Could not list your tokens.' });
    }
  };

  useEffect(() => {
    if (isAuthenticated) loadTokens();
  }, [isAuthenticated]); // eslint-disable-line react-hooks/exhaustive-deps

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
          'Authorization': `Bearer ${token}`,
          ...CSRF_HEADERS
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
          'Authorization': `Bearer ${token}`,
          ...CSRF_HEADERS
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

  const handleGenerateToken = async (e) => {
    e.preventDefault();
    setTokenMessage({ type: '', text: '' });
    try {
      const made = await createApiToken(tokenName.trim(), tokenScope, Number(tokenDays));
      setGeneratedToken(made.token);
      setTokenName('');
      setTokenMessage({ type: 'success', text: 'Copy it now: it is not shown again.' });
      loadTokens();
    } catch (error) {
      setTokenMessage({ type: 'error', text: error.response?.data?.detail || 'Could not make a token.' });
    }
  };

  const handleRevokeToken = async (token) => {
    setTokenMessage({ type: '', text: '' });
    try {
      await revokeApiToken(token.id);
      setTokenMessage({ type: 'success', text: `Revoked ${token.name}.` });
      loadTokens();
    } catch (error) {
      setTokenMessage({ type: 'error', text: error.response?.data?.detail || 'Could not revoke the token.' });
    }
  };

  const shortDate = (value) => (value ? new Date(value).toLocaleDateString() : '–');
  const tokenState = (token) => {
    if (token.revoked_at) return 'revoked';
    return new Date(token.expires_at) < new Date() ? 'expired' : 'active';
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
          alt="Rowanholt"
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
          Manage your Rowanholt DF Acceleration Suite account, security settings, and API access.
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

              {/* Tokens for scripts and Smith's MCP server */}
              <div style={{ paddingTop: '2rem', borderTop: '1px solid #3f4b2a' }}>
                <h3 style={{ marginBottom: '1.5rem' }}>Tokens for scripts and Smith's MCP server</h3>

                <p style={{ marginBottom: '1rem', color: '#a09580' }}>
                  A token lasts until it expires or you revoke it, and is shown once, when it's made. An{' '}
                  <code>smith-mcp</code> token can only read, flag leads and add notes, recorded as Smith acting for you;
                  a <code>full</code> token does what you can do, so keep it like a password. For{' '}
                  <code>rowanholt mcp</code>, set it as <code>ROWANHOLT_TOKEN</code> (docs/SMITH.md).
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

                {tokensAvailable && (
                  <>
                    <form onSubmit={handleGenerateToken} style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: '1.5rem' }}>
                      <div style={{ flex: '2 1 12rem' }}>
                        <label>Name</label>
                        <input type="text" value={tokenName} onChange={(e) => setTokenName(e.target.value)}
                          placeholder="e.g. Claude Desktop on my laptop" maxLength={100} required />
                      </div>
                      <div style={{ flex: '1 1 8rem' }}>
                        <label>Scope</label>
                        <select value={tokenScope} onChange={(e) => setTokenScope(e.target.value)}>
                          <option value="smith-mcp">smith-mcp</option>
                          <option value="full">full</option>
                        </select>
                      </div>
                      <div style={{ flex: '1 1 6rem' }}>
                        <label>Days</label>
                        <input type="number" min={1} max={365} value={tokenDays} onChange={(e) => setTokenDays(e.target.value)} />
                      </div>
                      <button type="submit" style={{ height: '42px' }}>Make a token</button>
                    </form>

                    {apiTokens.length > 0 && (
                      <table style={{ width: '100%', fontSize: '0.9rem' }}>
                        <thead>
                          <tr><th>Name</th><th>Token</th><th>Scope</th><th>Made</th><th>Expires</th><th>Last used</th><th>State</th><th /></tr>
                        </thead>
                        <tbody>
                          {apiTokens.map((token) => (
                            <tr key={token.id}>
                              <td>{token.name}</td>
                              <td><code>{token.prefix}…</code></td>
                              <td>{token.scope}</td>
                              <td>{shortDate(token.created_at)}</td>
                              <td>{shortDate(token.expires_at)}</td>
                              <td>{shortDate(token.last_used_at)}</td>
                              <td>{tokenState(token)}</td>
                              <td>
                                {tokenState(token) === 'active' && (
                                  <button type="button" className="secondary" onClick={() => handleRevokeToken(token)}>Revoke</button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </>
                )}
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
              <MfaPanels />
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
                      Required for Ask Smith AI assistant functionality.
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
