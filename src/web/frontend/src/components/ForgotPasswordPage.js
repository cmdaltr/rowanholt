import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { forgotPassword } from '../api';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt.png`;

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await forgotPassword(email);
      setSuccess(true);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to send reset link. Please try again.');
    } finally {
      setLoading(false);
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
        <h2>Forgot Password</h2>
        <p>
          Reset your Rowanholt account password.
        </p>
      </header>

      <div className="card">
        {success ? (
          <>
            <div className="alert-success">
              Password reset instructions have been sent to your email address.
            </div>
            <p style={{ color: '#e5e0d0' }}>
              Please check your inbox and follow the instructions to reset your password.
            </p>
            <Link to="/login">
              <button style={{ marginTop: '1rem' }}>Return to Login</button>
            </Link>
          </>
        ) : (
          <>
            <h3>Reset Password</h3>
            <p style={{ color: '#e5e0d0', marginBottom: '1.5rem' }}>
              Enter your email address and we'll send you instructions to reset your password.
            </p>

            {error && (
              <div className="alert-error">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="email">Email Address</label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email address"
                  required
                  disabled={loading}
                />
              </div>

              <button type="submit" disabled={loading} style={{ width: '100%' }}>
                {loading ? 'Sending...' : 'Send Reset Link'}
              </button>
            </form>

            <div className="text-center" style={{ marginTop: '1.5rem' }}>
              Remember your password?{' '}
              <Link to="/login" className="text-link">
                Sign In
              </Link>
            </div>
          </>
        )}
      </div>

      <div className="card alert-info" style={{ marginTop: '2rem' }}>
        <h4 style={{ marginTop: 0, color: '#93c5fd' }}>Note</h4>
        <p style={{ fontSize: '0.9rem', marginBottom: 0 }}>
          Email functionality is currently under development. In production, the reset token will be sent to your email.
          For now, check the server logs for the reset token.
        </p>
      </div>
    </div>
  );
};

export default ForgotPasswordPage;
