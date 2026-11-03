import React, { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { resetPassword } from '../api';

const heroImage = `${process.env.PUBLIC_URL}/images/dernvale.png`;

const ResetPasswordPage = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';

  const [formData, setFormData] = useState({
    newPassword: '',
    confirmPassword: '',
  });
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Validate token
    if (!token) {
      setError('Invalid or missing reset token');
      return;
    }

    // Validate passwords match
    if (formData.newPassword !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Validate password strength
    if (formData.newPassword.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    setLoading(true);

    try {
      await resetPassword(token, formData.newPassword);
      setSuccess(true);
      // Redirect to login after 2 seconds
      setTimeout(() => {
        navigate('/login?reset=true');
      }, 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to reset password. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="journey-detail">
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Dernvale"
          className="hero-image"
          style={{
            transform: 'scale(0.2)',
            transformOrigin: 'center top'
          }}
        />
      </section>

      <header>
        <h2>Reset Password</h2>
        <p>
          Create a new password for your Dernvale account.
        </p>
      </header>

      <div className="card">
        {success ? (
          <>
            <div className="alert-success">
              Password reset successful! Redirecting to login...
            </div>
            <p style={{ color: '#e5e0d0' }}>
              Your password has been successfully reset. You can now log in with your new password.
            </p>
          </>
        ) : (
          <>
            <h3>Create New Password</h3>

            {error && (
              <div className="alert-error">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="newPassword">New Password</label>
                <input
                  type="password"
                  id="newPassword"
                  name="newPassword"
                  value={formData.newPassword}
                  onChange={handleChange}
                  placeholder="Enter new password (min 8 characters)"
                  required
                  disabled={loading}
                  minLength={8}
                />
              </div>

              <div className="form-group">
                <label htmlFor="confirmPassword">Confirm Password</label>
                <input
                  type="password"
                  id="confirmPassword"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  placeholder="Re-enter new password"
                  required
                  disabled={loading}
                  minLength={8}
                />
              </div>

              <button type="submit" disabled={loading} style={{ width: '100%' }}>
                {loading ? 'Resetting Password...' : 'Reset Password'}
              </button>
            </form>

            <div className="text-center" style={{ marginTop: '1.5rem' }}>
              <Link to="/login" className="text-link">
                Return to Login
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default ResetPasswordPage;
