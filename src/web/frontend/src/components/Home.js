import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

const heroImage = `${process.env.PUBLIC_URL}/images/rivendell.png`;
const gandalfImage = `${process.env.PUBLIC_URL}/images/gandalf.png`;
const elrondImage = `${process.env.PUBLIC_URL}/images/elrond.png`;
const pippinImage = `${process.env.PUBLIC_URL}/images/pippin.png`;
const aragornImage = `${process.env.PUBLIC_URL}/images/aragorn.png`;
const mordorClosedImage = `${process.env.PUBLIC_URL}/images/mordor_closed.jpg`;
const mordorOpenImage = `${process.env.PUBLIC_URL}/images/mordor_open.jpg`;

const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

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
          alt="Rivendell - The Last Homely House"
          className="hero-image"
          style={{
            transform: `scale(${heroScale})`,
            transformOrigin: 'center top'
          }}
        />
      </section>

      <section data-guide="home.journeys"
        className="journey-grid"
        style={{ transform: `translateY(${cardOffset}px)` }}
      >
        <Link to="/gandalf" className="journey-card">
          <div className="journey-card__image"><img src={gandalfImage} alt="Gandalf Acquisition" /></div>
          <div className="journey-card__content">
            <h2>Gandalf Acquisition</h2>
            <p>Collect evidence from live or remote systems with encrypted packaging.</p>
          </div>
        </Link>

        <Link to="/elrond" className="journey-card">
          <div className="journey-card__image"><img src={elrondImage} alt="Elrond Analysis" /></div>
          <div className="journey-card__content">
            <h2>Elrond Analysis</h2>
            <p>Process timelines, memory and artifacts to map incidents to MITRE ATT&CK.</p>
          </div>
        </Link>

        {/* Second row: Pippin under Gandalf, Aragorn under Elrond (the Aragorn page itself is for admins) */}
        <Link to="/pippin" className="journey-card">
          <div className="journey-card__image"><img src={pippinImage} alt="Pippin Threat Intelligence" /></div>
          <div className="journey-card__content">
            <h2>Pippin Threat Intelligence</h2>
            <p>Import indicators, match cases against them and see whose tradecraft the evidence resembles.</p>
          </div>
        </Link>

        <Link to="/aragorn" className="journey-card">
          <div className="journey-card__image"><img src={aragornImage} alt="Aragorn Administration" /></div>
          <div className="journey-card__content">
            <h2>Aragorn Administration</h2>
            <p>Keep the realm: Rivendell's containers, users, settings and the test lab.</p>
          </div>
        </Link>
      </section>

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
