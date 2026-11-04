import React from 'react';
import NewAcquisition from './NewAcquisition';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt.png`;

const GandalfLanding = () => {
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
        <h2>Gandalf Remote Acquisition</h2>
        <p>
          Securely acquire artifacts from local or remote hosts using PowerShell, Python or Bash.
        </p>
      </header>

      <NewAcquisition />
    </div>
  );
};

export default GandalfLanding;
