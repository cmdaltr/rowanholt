import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { completeSsoSignIn } from '../api';

// Where single sign-on lands: the backend has set the session cookie; swap it for the
// token and user the rest of the app keeps, then on to the jobs.
function SsoCallback() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [error, setError] = useState('');

  useEffect(() => {
    completeSsoSignIn()
      .then((data) => {
        login(data.user);
        navigate('/jobs', { replace: true });
      })
      .catch(() => setError('Single sign-on finished, but no session came back. Try signing in again.'));
    // Once: login() is a new function on every render of the auth context
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="journey-detail">
      <div className="card" style={{ width: '600px', maxWidth: '90%', margin: '3rem auto', textAlign: 'center' }}>
        {error ? <div className="alert-error">{error}</div> : <p>Signing you in…</p>}
      </div>
    </div>
  );
}

export default SsoCallback;
