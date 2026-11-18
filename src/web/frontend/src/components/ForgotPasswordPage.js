import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getAuthConfig } from '../api';
import { JOURNEYS } from './Home';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.webp`;

// Rowanholt sends no email, so a reset is an administrator's job: this says how, for a server or
// for someone's own machine, rather than offering a form that would send nothing
const ForgotPasswordPage = () => {
  // The same as the sign-in page: one of the home page's figures beside the card
  const [figure] = useState(() => JOURNEYS[Math.floor(Math.random() * JOURNEYS.length)]);
  const [server, setServer] = useState(null);

  useEffect(() => {
    getAuthConfig().then((config) => setServer(Boolean(config.server_mode))).catch(() => setServer(false));
  }, []);

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
        <h2>Forgot Password</h2>
        <p>
          Reset your Rowanholt account password.
        </p>
      </header>

      <div className="login-layout">
      <div className="journey-banner login-figure" aria-hidden="true">
        <img src={figure.image} alt="" style={{ '--drop': figure.drop }} />
        <span className="journey-banner__name">
          <span>{figure.name}</span>
          <span className="journey-banner__role">{figure.role}</span>
        </span>
      </div>
      <div className="card login-card">
        <h3>Reset Password</h3>

        {server === true && (
          <div data-testid="reset-server">
            <p style={{ marginBottom: '1rem' }}>
              Rowanholt doesn't send email, so an administrator sets a new password for you. Ask one to run
              this on the server, with your username:
            </p>
            <pre style={{ marginBottom: '1rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}><code>rowanholt server users password &lt;username&gt;</code></pre>
            <p style={{ marginBottom: '1.5rem', color: '#a09580', fontSize: '0.9rem' }}>
              Lost your authenticator and your backup codes as well? They can turn MFA off for you
              with <code>rowanholt server users mfa-reset &lt;username&gt;</code>.
            </p>
          </div>
        )}

        {server === false && (
          <div data-testid="reset-local">
            <p style={{ marginBottom: '1rem' }}>
              Rowanholt doesn't send email. On your own machine, set a new password from a terminal, with
              your username:
            </p>
            <pre style={{ marginBottom: '1.5rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}><code>docker exec -it rowanholt-backend python -m auth.manage_users password &lt;username&gt;</code></pre>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <Link to="/login" style={{ width: '100%' }}>
            <button type="button" style={{ width: '100%' }}>Back to Sign In</button>
          </Link>
        </div>
      </div>
      </div>
    </div>
  );
};

export default ForgotPasswordPage;
