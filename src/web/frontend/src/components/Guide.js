import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { GUIDE_PAGES } from '../guide/content';
import { setStartPref, startPrefs } from '../guide/prefs';

const SHOTS = `${process.env.PUBLIC_URL}/guide`;

/**
 * The guide: a photograph of each page with its sections highlighted in turn, and what
 * each is for, who uses it and when. Positions come from boxes.json, written by
 * scripts/docs/guide/capture.py alongside the photographs.
 */
function Guide({ onClose, startPage }) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const pages = useMemo(
    () => GUIDE_PAGES.filter((page) => !page.admin || !user || user.role === 'admin'),
    [user],
  );
  const [pageIndex, setPageIndex] = useState(() => Math.max(0, pages.findIndex((p) => p.id === startPage)));
  const [sectionIndex, setSectionIndex] = useState(0);
  const [shots, setShots] = useState(null);
  const [atStart, setAtStart] = useState(() => startPrefs(user).guide);
  const shotRef = useRef(null);

  useEffect(() => {
    fetch(`${SHOTS}/boxes.json`)
      .then((r) => (r.ok ? r.json() : {}))
      .catch(() => ({}))
      .then(setShots);
  }, []);

  const page = pages[pageIndex];
  const shot = shots?.[page.id];
  // Sections the photograph shows (Access only exists on a team server, say), or all of
  // them when there's no photograph to go by
  const sections = shot ? page.sections.filter((s) => shot.boxes[s.id]) : page.sections;
  const section = sections[Math.min(sectionIndex, sections.length - 1)];

  // Keep the current section in view when the photograph is taller than its box
  useEffect(() => {
    const current = shotRef.current?.querySelector('.guide-box.is-current');
    current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [pageIndex, sectionIndex, shot]);

  const go = useCallback((delta) => {
    const next = sectionIndex + delta;
    if (next >= 0 && next < sections.length) {
      setSectionIndex(next);
    } else if (pageIndex + delta >= 0 && pageIndex + delta < pages.length) {
      const target = pages[pageIndex + delta];
      const targetShot = shots?.[target.id];
      const count = targetShot ? target.sections.filter((s) => targetShot.boxes[s.id]).length : target.sections.length;
      setPageIndex(pageIndex + delta);
      setSectionIndex(delta > 0 ? 0 : Math.max(0, count - 1));
    }
  }, [sectionIndex, sections.length, pageIndex, pages, shots]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowRight') go(1);
      if (e.key === 'ArrowLeft') go(-1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go, onClose]);

  const choosePage = (index) => {
    setPageIndex(index);
    setSectionIndex(0);
  };

  const toggleAtStart = (value) => {
    setAtStart(value);
    setStartPref(user, 'guide', value);
  };

  const box = (id) => {
    const b = shot?.boxes[id];
    if (!b) return null;
    const [x, y, w, h] = b;
    return { left: `${(x / shot.width) * 100}%`, top: `${(y / shot.height) * 100}%`,
             width: `${(w / shot.width) * 100}%`, height: `${(h / shot.height) * 100}%` };
  };

  const first = pageIndex === 0 && sectionIndex === 0;
  const last = pageIndex === pages.length - 1 && sectionIndex >= sections.length - 1;
  const route = page.route.includes(':') ? null : page.route;

  return (
    <div className="guide-backdrop" role="dialog" aria-modal="true" aria-label="Rivendell guide" onClick={onClose}>
      <div className="guide" onClick={(e) => e.stopPropagation()}>
        <div className="guide-head">
          <h2>The guide</h2>
          <select value={pageIndex} onChange={(e) => choosePage(Number(e.target.value))} aria-label="Page">
            {pages.map((p, i) => <option key={p.id} value={i}>{p.title}</option>)}
          </select>
          <button type="button" className="guide-close" onClick={onClose} aria-label="Close the guide">×</button>
        </div>

        <div className="guide-body">
          <div className="guide-shot" ref={shotRef}>
            {shot ? (
              <div className="guide-frame" style={{ aspectRatio: `${shot.width} / ${shot.height}` }}>
                <img src={`${SHOTS}/${shot.image}`} alt={`The ${page.title} page`} />
                {sections.map((s, i) => (
                  <button key={s.id} type="button" style={box(s.id)}
                          className={`guide-box${s.id === section?.id ? ' is-current' : ''}`}
                          onClick={() => setSectionIndex(i)} aria-label={s.title} />
                ))}
              </div>
            ) : (
              <div className="guide-noshot">
                <p>{page.title}</p>
                <p className="guide-dim">No photograph of this page yet: run scripts/docs/guide/capture.py.</p>
              </div>
            )}
          </div>

          <div className="guide-text">
            <p className="guide-intro">{page.intro}</p>
            {section && (
              <div className="guide-section" key={section.id}>
                <h3>{section.title}</h3>
                <p>{section.what}</p>
                <dl>
                  <dt>Who it's for</dt><dd>{section.who}</dd>
                  <dt>When it helps most</dt><dd>{section.when}</dd>
                </dl>
              </div>
            )}
            <div className="guide-dots" aria-hidden="true">
              {sections.map((s, i) => <span key={s.id} className={i === sectionIndex ? 'is-current' : ''} />)}
            </div>
            <div className="guide-nav">
              <button type="button" className="guide-secondary" onClick={() => go(-1)} disabled={first}>Back</button>
              {last
                ? <button type="button" onClick={onClose}>Done</button>
                : <button type="button" onClick={() => go(1)}>Next</button>}
            </div>
            {route && (
              <button type="button" className="guide-link" onClick={() => { onClose(); navigate(route); }}>
                Go to {page.title}
              </button>
            )}
          </div>
        </div>

        <label className="guide-check">
          <input type="checkbox" checked={atStart} onChange={(e) => toggleAtStart(e.target.checked)} />
          Offer the guide when Rivendell starts
        </label>
      </div>
    </div>
  );
}

export default Guide;
