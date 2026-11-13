import React, { useCallback, useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
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
import Licence, { LicenceNotice, managesLicence } from './components/Licence';
import Webhooks from './components/Webhooks';
import Branding from './components/Branding';
import { getAuthConfig } from './api';
import './App.css';

function Navigation({ onGuide, serverMode }) {
  const navigate = useNavigate();
  const { logout, isAuthenticated, user } = useAuth();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <nav>
      <div className="nav-left">
        <Link to="/gandalf">Gandalf</Link>
        <Link to="/elrond">Elrond</Link>
        <Link to="/pippin">Pippin</Link>
        {/* The licence and what it turns on, in a menu under Aragorn so the bar fits: a team
            server's admins, or the analyst in local mode */}
        <div className="nav-menu">
          <Link to="/aragorn">Aragorn</Link>
          {serverMode != null && managesLicence(user, serverMode) && (
            <div className="nav-menu__items nav-menu__items--list">
              <Link to="/licence">Licence</Link>
              <Link to="/branding">Branding</Link>
              <Link to="/webhooks">Webhooks</Link>
            </div>
          )}
        </div>
        <Link to="/ai">Smith</Link>
      </div>
      {/* Mordor opens the right: the datasets sit beside the jobs they feed */}
      <div className="nav-right">
        <Link to="/mordor">Mordor</Link>
        <Link to="/jobs">Jobs</Link>
        <div className="nav-menu">
          <Link to="/help">About</Link>
          <div className="nav-menu__items">
            <button type="button" className="nav-guide" onClick={onGuide} title="The guide and a tip">Guide</button>
            <Link to="/help#licence" title="The Elastic License 2.0 Rowanholt is under">Licence</Link>
          </div>
        </div>
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
      </div>
    </nav>
  );
}

// Every page's Rowanholt logo is the way home (the navigation has no Home link)
function useLogoGoesHome() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  return useCallback((event) => {
    const logo = event.target.closest?.('img.hero-image');
    if (logo && pathname !== '/') navigate('/');
  }, [navigate, pathname]);
}

function AppContent() {
  const goHome = useLogoGoesHome();
  const { pathname } = useLocation();
  const [scrollProgress, setScrollProgress] = useState(0);
  const [offerRequested, setOfferRequested] = useState(false);
  const closeOfferRequest = useCallback(() => setOfferRequested(false), []);
  // null until the auth config answers, so admin-only links and pages aren't guessed at
  const [serverMode, setServerMode] = useState(null);
  useEffect(() => {
    getAuthConfig().then((config) => setServerMode(!!config.server_mode)).catch(() => setServerMode(true));
  }, []);
  const mapBackground = `${process.env.PUBLIC_URL}/images/middle_earth.png`;

  return (
    <div
      className={pathname === '/' ? 'App App--home' : 'App'}
      onClick={goHome}
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
        <Navigation onGuide={() => setOfferRequested(true)} serverMode={serverMode} />
      </header>
      <LicenceNotice serverMode={serverMode} />

        <StartOffer offerRequested={offerRequested} onOfferClosed={closeOfferRequest} />

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
            <Route path="/licence" element={<Licence serverMode={serverMode} />} />
            <Route path="/branding" element={<Branding serverMode={serverMode} />} />
            <Route path="/webhooks" element={<Webhooks serverMode={serverMode} />} />
            <Route path="/lab" element={<Navigate to="/aragorn#lab" replace />} />
          </Routes>
        </main>

        <footer className="App-footer">
          <p>
            Rowanholt v2.1.0 - Digital Forensics Acceleration Suite
          </p>
          <p className="attribution">
            This project contains references to "The Lord of the Rings" by J.R.R. Tolkien. This code is not affiliated with or endorsed by the Tolkien Estate or Peter Jackson.<br />
            All trademarks and copyrights for that work belong to their respective owners.<br />
            Rowanholt™ and the Rowanholt logo are trademarks of cmdaltr. The licence covers the software; it does not grant any right to use the Rowanholt name or logo.
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
