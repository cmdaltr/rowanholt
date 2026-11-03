import React from 'react';

const heroImage = `${process.env.PUBLIC_URL}/images/dernvale.png`;

// The logo and title banner every Dernvale page opens with (as ElrondLanding and GandalfLanding)
function PageHero({ title, children }) {
  return (
    <>
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Dernvale"
          className="hero-image"
          style={{ transform: 'scale(0.2)', transformOrigin: 'center top' }}
        />
      </section>
      <header>
        <h2>{title}</h2>
        <p>{children}</p>
      </header>
    </>
  );
}

export default PageHero;
