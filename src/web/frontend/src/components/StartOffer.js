import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { markOffered, nextTip, offeredThisStart, setStartPref, startPrefs } from '../guide/prefs';
import Guide from './Guide';
import { randomQuote } from '../guide/quotes';

// Pages where nobody's settled in yet: the offer waits until they're past them
const NOT_YET = ['/login', '/register', '/forgot-password', '/reset-password'];

/**
 * At start-up: a quote, then the guide on offer and a tip side by side, each with its own "every start" tickbox.
 * The navigation's Guide link opens the guide directly (guideRequested); its Doors of Durin open this (offerRequested).
 */
function StartOffer({ guideRequested, onGuideClosed, offerRequested, onOfferClosed }) {
  const { user, loading } = useAuth();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [offer, setOffer] = useState(false);
  const [prefs, setPrefs] = useState(() => startPrefs(null));
  const [tip, setTip] = useState(null);
  const [guide, setGuide] = useState(false);
  const [quote] = useState(randomQuote);

  useEffect(() => {
    if (loading || offeredThisStart() || NOT_YET.some((p) => pathname.startsWith(p))) return;
    markOffered();
    const wanted = startPrefs(user);
    setPrefs(wanted);
    if (wanted.tips) setTip(nextTip(user));
    if (wanted.guide || wanted.tips) setOffer(true);
  }, [loading, pathname, user]);

  // The Doors of Durin in the navigation: the welcome, with a fresh tip, whatever the tickboxes say
  useEffect(() => {
    if (!offerRequested) return;
    setPrefs(startPrefs(user));
    setTip(nextTip(user));
    setOffer(true);
    onOfferClosed?.();
  }, [offerRequested, user, onOfferClosed]);

  useEffect(() => {
    if (guideRequested) {
      setOffer(false);
      setGuide(true);
    }
  }, [guideRequested]);

  const toggle = (which, value) => {
    setPrefs((p) => ({ ...p, [which]: value }));
    setStartPref(user, which, value);
  };

  const closeGuide = () => {
    setGuide(false);
    onGuideClosed?.();
  };

  if (guide) return <Guide onClose={closeGuide} />;
  if (!offer) return null;

  return (
    <div className="guide-backdrop" role="dialog" aria-modal="true" aria-label="Welcome to Rivendell"
         onClick={() => setOffer(false)}>
      <div className="start-offer tone-a" onClick={(e) => e.stopPropagation()}>
        <button type="button" className="guide-close" onClick={() => setOffer(false)} aria-label="Close">×</button>
        <div className="start-offer-head">
          <h2>Welcome to Rivendell</h2>
          <blockquote className="start-offer-quote">
            “{quote.text}”
            <cite>{quote.who}, {quote.where}</cite>
          </blockquote>
        </div>

        <div className="start-offer-columns">
        <section className="start-offer-part">
          <h3>The guide</h3>
          <p>Every page, section by section: what it's for, who uses it and when it helps most.</p>
          <button type="button" onClick={() => { setOffer(false); setGuide(true); }}>Take the guide</button>
          <label className="guide-check">
            <input type="checkbox" checked={prefs.guide} onChange={(e) => toggle('guide', e.target.checked)} />
            Offer the guide at every start
          </label>
        </section>

        <section className="start-offer-part">
          <h3>Tip</h3>
          {tip ? (
            <>
              <p className="start-offer-tip">{tip.text}</p>
              <div className="start-offer-actions">
                <button type="button" className="guide-secondary" onClick={() => setTip(nextTip(user, tip.id))}>
                  Another tip
                </button>
                {tip.to && tip.to !== pathname && (
                  <button type="button" className="guide-link" onClick={() => { setOffer(false); navigate(tip.to); }}>
                    Show me
                  </button>
                )}
              </div>
            </>
          ) : (
            <button type="button" className="guide-secondary" onClick={() => setTip(nextTip(user))}>Show a tip</button>
          )}
          <label className="guide-check">
            <input type="checkbox" checked={prefs.tips} onChange={(e) => toggle('tips', e.target.checked)} />
            Show a tip at every start
          </label>
        </section>
        </div>
      </div>
    </div>
  );
}

export default StartOffer;
