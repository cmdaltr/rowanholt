import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router';
import { register } from '../api';
import { JOURNEYS } from './Home';

const heroImage = `/images/rowanholt-tm.webp`;

const RegisterPage = () => {
  const navigate = useNavigate();
  // The same as the sign-in page: one of the home page's figures beside the form
  const [figure] = useState(() => JOURNEYS[Math.floor(Math.random() * JOURNEYS.length)]);
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
    fullName: '',
  });
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

    // Validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Validate password strength
    if (formData.password.length < 12) {
      setError('Passwords need at least 12 characters');
      return;
    }

    setLoading(true);

    try {
      await register({
        email: formData.email,
        username: formData.username,
        password: formData.password,
        full_name: formData.fullName || null,
      });

      // Sign-in says the account was made, with its username filled in
      navigate('/login', { state: { registered: formData.username } });
    } catch (err) {
      const detail = err.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
      } else if (Array.isArray(detail)) {
        // Handle validation errors from FastAPI
        setError(detail.map(e => e.msg).join(', '));
      } else {
        setError('Registration failed. Please try again.');
      }
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
        <h2>Register</h2>
        <p>
          Create your Rowanholt DF Acceleration Suite account.
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
        <h3>Create Account</h3>

        {error && (
          <div className="alert-error">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Email *</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="Enter email address"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="username">Username *</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="Enter username (min 3 characters)"
              required
              disabled={loading}
              minLength={3}
            />
            <small>Alphanumeric characters and underscores only</small>
          </div>

          <div className="form-group">
            <label htmlFor="fullName">Full Name</label>
            <input
              type="text"
              id="fullName"
              name="fullName"
              value={formData.fullName}
              onChange={handleChange}
              placeholder="Enter full name (optional)"
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password *</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Enter password (min 12 characters)"
              required
              disabled={loading}
              minLength={12}
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password *</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              placeholder="Re-enter password"
              required
              disabled={loading}
              minLength={12}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <button type="submit" disabled={loading} style={{ width: '100%' }}>
              {loading ? 'Creating Account...' : 'Create Account'}
            </button>
          </div>
        </form>

        <div className="text-center" style={{ marginTop: '1.5rem' }}>
          Already have an account?{' '}
          <Link to="/login" className="text-link">
            Sign In
          </Link>
        </div>
      </div>
      </div>
    </div>
  );
};

export default RegisterPage;
