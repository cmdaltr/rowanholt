import React from 'react';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.png`;

// The logo and title banner every Rowanholt page opens with (as ElrondLanding and GandalfLanding)
function PageHero({ title, children }) {
  return (
    <>
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Rowanholt"
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
