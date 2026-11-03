import React from 'react';
import NewAnalysis from './NewAnalysis';

const heroImage = `${process.env.PUBLIC_URL}/images/dernvale.png`;

const ElrondLanding = () => {
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
        <h2>Elrond Automated Analysis</h2>
        <p>
          Launch artifact processing, analysis and ATT&CK mapping against evidence collected with Gandalf or other workflow.
        </p>
      </header>

      <NewAnalysis />
    </div>
  );
};

export default ElrondLanding;
