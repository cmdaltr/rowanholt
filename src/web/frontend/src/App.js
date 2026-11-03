import React, { useCallback, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useNavigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Home from './components/Home';
import GandalfLanding from './components/GandalfLanding';
import ElrondLanding from './components/ElrondLanding';
import MordorTelemetry from './components/MordorTelemetry';
import LoginPage from './components/LoginPage';
import SsoCallback from './components/SsoCallback';
import RegisterPage from './components/RegisterPage';
import ForgotPasswordPage from './components/ForgotPasswordPage';
import ResetPasswordPage from './components/ResetPasswordPage';
import HelpPage from './components/HelpPage';
import AIAssistant from './components/AIAssistant';
import JobList from './components/JobList';
import JobDetails from './components/JobDetails';
import Archive from './components/Archive';
import AccountPage from './components/AccountPage';
import Aragorn from './components/Aragorn';
import ThreatIntel from './components/ThreatIntel';
import CaseBrowser from './components/CaseBrowser';
import StartOffer from './components/StartOffer';
import './App.css';

function Navigation({ onGuide, onWelcome }) {
  const navigate = useNavigate();
  const { user, logout, isAuthenticated } = useAuth();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <nav>
      <div className="nav-left">
        <Link to="/">Home</Link>
        <Link to="/gandalf">Gandalf</Link>
        <Link to="/elrond">Elrond</Link>
        <Link to="/mordor">Mordor</Link>
        <Link to="/pippin">Pippin</Link>
        {user?.role === 'admin' && <Link to="/aragorn">Aragorn</Link>}
      </div>
      <div className="nav-right">
        <Link to="/ai">Ask Eru</Link>
        <Link to="/jobs">Jobs</Link>
        <Link to="/help">About</Link>
        <button type="button" className="nav-guide" onClick={onGuide}>Guide</button>
        <Link to={isAuthenticated ? "/account" : "/login"}>Account</Link>
        <button
          onClick={isAuthenticated ? handleLogout : undefined}
          className={`logout-icon-btn ${!isAuthenticated ? 'disabled' : ''}`}
          title={isAuthenticated ? "Sign Out" : "Not signed in"}
          disabled={!isAuthenticated}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          <span>Log out</span>
        </button>
        <button type="button" className="nav-welcome" onClick={onWelcome} title="Welcome: the guide and a tip" aria-label="Show the welcome: the guide and a tip">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            {/* The Doors of Durin: speak, friend, and enter */}
            <path d="M5 22V11a7 7 0 0 1 14 0v11" />
            <path d="M3 22h18" />
            <path d="M12 14v8" />
            <path d="M12 6.5v3M10.5 8h3" />
          </svg>
        </button>
      </div>
    </nav>
  );
}

function AppContent() {
  const [scrollProgress, setScrollProgress] = useState(0);
  const [guideRequested, setGuideRequested] = useState(false);
  const [offerRequested, setOfferRequested] = useState(false);
  const closeOfferRequest = useCallback(() => setOfferRequested(false), []);
  const mapBackground = `${process.env.PUBLIC_URL}/images/middle_earth.png`;

  return (
    <div
      className="App"
      style={{
        backgroundImage: `url(${mapBackground})`,
        backgroundSize: 'cover',
        backgroundAttachment: 'fixed',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        backgroundColor: 'rgba(15, 15, 35, 0.72)',
        backgroundBlendMode: 'multiply',
      }}
    >
      <header className="App-header">
        <Navigation onGuide={() => setGuideRequested(true)} onWelcome={() => setOfferRequested(true)} />
      </header>

        <StartOffer guideRequested={guideRequested} onGuideClosed={() => setGuideRequested(false)}
          offerRequested={offerRequested} onOfferClosed={closeOfferRequest} />

        <main className="App-main">
          <Routes>
            <Route path="/" element={<Home onScrollProgress={setScrollProgress} />} />
            <Route path="/gandalf" element={<GandalfLanding />} />
            <Route path="/elrond" element={<ElrondLanding />} />
            <Route path="/mordor" element={<MordorTelemetry />} />
            <Route path="/mordor/datasets" element={<Navigate to="/mordor" replace />} />
            <Route path="/mordor/telemetry" element={<Navigate to="/mordor" replace />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/login/sso" element={<SsoCallback />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/help" element={<HelpPage />} />
            <Route path="/ai" element={<AIAssistant />} />
            <Route path="/pippin" element={<ThreatIntel />} />
            <Route path="/intel" element={<Navigate to="/pippin" replace />} />
            <Route path="/jobs" element={<JobList />} />
            <Route path="/jobs/:jobId" element={<JobDetails />} />
            <Route path="/jobs/:jobId/case" element={<CaseBrowser />} />
            <Route path="/archive" element={<Archive />} />
            <Route path="/account" element={<AccountPage />} />
            <Route path="/aragorn" element={<Aragorn />} />
            <Route path="/lab" element={<Navigate to="/aragorn#lab" replace />} />
          </Routes>
        </main>

        <footer className="App-footer">
          <p>
            Rivendell v1.0.0 - Digital Forensics Acceleration Suite
          </p>
          <p className="attribution">
            This project contains references to "The Lord of the Rings" by J.R.R. Tolkien. This code is not affiliated with or endorsed by the Tolkien Estate or Peter Jackson.<br />
            All trademarks and copyrights for that work belong to their respective owners.
          </p>
          <p style={{
            marginTop: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            fontSize: '0.9rem'
          }}>
            <a
              href="https://github.com/cmdaltr"
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                color: '#f0dba5',
                textDecoration: 'none',
                transition: 'opacity 0.3s ease'
              }}
              onMouseOver={(e) => e.currentTarget.style.opacity = '0.7'}
              onMouseOut={(e) => e.currentTarget.style.opacity = '1'}
            >
              <svg height="20" width="20" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
              </svg>
              @cmdaltr
            </a>
          </p>
        </footer>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}

export default App;
