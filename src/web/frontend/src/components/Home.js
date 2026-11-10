import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.png`;
const gandalfImage = `${process.env.PUBLIC_URL}/images/gandalf.png`;
const pippinImage = `${process.env.PUBLIC_URL}/images/pippin.png`;
const aragornImage = `${process.env.PUBLIC_URL}/images/aragorn.png`;
const elrondImage = `${process.env.PUBLIC_URL}/images/elrond.png`;
const auleImage = `${process.env.PUBLIC_URL}/images/aule.png`;
const mordorClosedImage = `${process.env.PUBLIC_URL}/images/mordor_closed.jpg`;
const mordorOpenImage = `${process.env.PUBLIC_URL}/images/mordor_open.jpg`;

// The banners, left to right (the Aragorn page itself is for admins). Insight is Aulë, the smith.
// drop lowers a figure in its frame; zoom closes in when it's open
const JOURNEYS = [
  { to: '/gandalf', image: gandalfImage, name: 'Gandalf', role: 'Acquisition',
    text: 'Collect evidence from live or remote systems with encrypted packaging.' },
  { to: '/elrond', image: elrondImage, name: 'Elrond', role: 'Analysis', drop: '12px', zoom: 1.1,
    text: 'Process timelines, memory and artifacts to map incidents to MITRE ATT&CK.' },
  { to: '/pippin', image: pippinImage, name: 'Pippin', role: 'Threat Intelligence', drop: '12px',
    text: 'Import indicators, match cases against them and see whose tradecraft the evidence resembles.' },
  { to: '/aragorn', image: aragornImage, name: 'Aragorn', role: 'Administration',
    text: "Keep the realm: Rowanholt's containers, users, settings and the test lab." },
  { to: '/ai', image: auleImage, name: 'Aulë', role: 'Insight',
    text: 'Ask about a case and get answers drawn from its own files, each citing the rows it came from.' },
];

const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

// One row of banners: the hovered or focused one opens to show its text, Gandalf when none is
const JourneyBanners = ({ offset }) => {
  const [open, setOpen] = useState(0);

  return (
    <section data-guide="home.journeys" className="journey-banners"
      style={{ transform: `translateY(${offset}px)` }}>
      {JOURNEYS.map((j, i) => (
        <Link key={j.to} to={j.to}
          className={`journey-banner${i === open ? ' is-open' : ''}`}
          onMouseEnter={() => setOpen(i)} onFocus={() => setOpen(i)}
          aria-label={`${j.name} ${j.role}`}>
          <img src={j.image} alt="" style={{ '--drop': j.drop, '--zoom': j.zoom }} />
          <span className="journey-banner__name">
            <span>{j.name}</span>
            <span className="journey-banner__role">{j.role}</span>
          </span>
          <div className="journey-banner__content">
            <h2>{j.name} <span>{j.role}</span></h2>
            <p>{j.text}</p>
          </div>
        </Link>
      ))}
    </section>
  );
};

const Home = ({ onScrollProgress }) => {
  const [progress, setProgress] = useState(0);
  const [locked, setLocked] = useState(true);
  const [mordorHovered, setMordorHovered] = useState(false);
  const progressRef = useRef(0);
  const targetRef = useRef(0);
  const frameRef = useRef(null);
  const lockedRef = useRef(true);

  useEffect(() => {
    lockedRef.current = locked;
  }, [locked]);

  useEffect(() => {
    if (onScrollProgress) {
      onScrollProgress(progress);
    }
  }, [progress, onScrollProgress]);

  useEffect(() => {
    const animate = () => {
      const current = progressRef.current;
      const target = targetRef.current;
      const diff = target - current;

      if (Math.abs(diff) < 0.0001) {
        progressRef.current = target;
        setProgress(target);
        frameRef.current = null;
        return;
      }

      const next = current + diff * 0.35; // Much faster interpolation for immediate response
      progressRef.current = next;
      setProgress(next);
      frameRef.current = requestAnimationFrame(animate);
    };

    const startAnimation = () => {
      if (!frameRef.current) {
        frameRef.current = requestAnimationFrame(animate);
      }
    };

    const handleWheel = (event) => {
      const delta = clamp(event.deltaY / 150, -1.0, 1.0);

      if (lockedRef.current) {
        // Scrolling while locked (initial state or re-locked)
        event.preventDefault();
        const nextTarget = clamp(targetRef.current + delta, 0, 1);
        targetRef.current = nextTarget;
        if (nextTarget >= 1) {
          lockedRef.current = false;
          setLocked(false);
        }
        startAnimation();
      } else {
        // Unlocked state - check if we need to re-engage the reverse animation
        // Find the scrollable container (.App has overflow-y: scroll)
        const appContainer = document.querySelector('.App');
        const scrollTop = appContainer ? appContainer.scrollTop : window.scrollY;
        const atTop = scrollTop <= 200; // Very forgiving threshold to start reverse animation much earlier
        const scrollingUp = delta < 0;
        const hasProgress = targetRef.current > 0.01;

        if (atTop && scrollingUp && hasProgress) {
          event.preventDefault();
          const nextTarget = clamp(targetRef.current + delta, 0, 1);
          targetRef.current = nextTarget;
          if (nextTarget <= 0.01) {
            lockedRef.current = true;
            setLocked(true);
            targetRef.current = 0;
          }
          startAnimation();
        }
        // Otherwise, allow normal browser scrolling (don't prevent default)
      }
    };

    window.addEventListener('wheel', handleWheel);
    return () => {
      window.removeEventListener('wheel', handleWheel);
      if (frameRef.current) {
        cancelAnimationFrame(frameRef.current);
      }
    };
  }, []);

  const heroScale = 1 - progress * 0.65; // shrink to 35% at max progress, slower than before
  // Cards move up slightly to follow hero, but limited to prevent overlap
  const cardOffset = -progress * 100;

  return (
    <div className="home">
      <section data-guide="home.hero" className="hero-section">
        <img
          src={heroImage}
          alt="Rowanholt"
          className="hero-image hero-image--home"
          style={{
            transform: `scale(${heroScale})`,
            transformOrigin: 'center top'
          }}
        />
      </section>

      <JourneyBanners offset={cardOffset} />

      <section data-guide="home.mordor"
        className="mordor-section"
        style={{ transform: `translateY(${cardOffset}px)` }}
      >
        <Link
          to="/mordor"
          className="journey-card journey-card--landscape"
          onMouseEnter={() => setMordorHovered(true)}
          onMouseLeave={() => setMordorHovered(false)}
        >
          <div className="journey-card__image">
            <img
              src={mordorHovered ? mordorOpenImage : mordorClosedImage}
              alt="Mordor Recordings"
            />
          </div>
          <div className="journey-card__content">
            <h2>Mordor Recordings</h2>
            <p>Access pre-recorded security event datasets for threat research, detection development, and testing.</p>
          </div>
        </Link>
      </section>
    </div>
  );
};

export default Home;
