import React, { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  addBrand, chooseInstallationBrand, clearBrandLogo, deleteBrand, editBrand, getBrandLogo, getBrands, uploadBrandLogo,
} from '../api';
import { managesLicence } from './Licence';

// Report branding (docs/LICENSING_MODEL.md): brands for the Word report, each a primary and optional
// secondary colour and up to three logos. Pro uses the installation's brand; Services lets a case name
// its own (chosen in the case browser). Saving is open on every edition so nothing is lost when a
// licence changes; the page says what the current licence does with them.

const SLOTS = [
  ['cover', 'Cover', 'Above the title on the first page'],
  ['header', 'Header', 'Small, at the top of every page'],
  ['client', 'Client', 'Beside "Prepared for" on the cover'],
];

const errorText = (err) => {
  const detail = err.response?.data?.detail;
  if (!detail) return err.message;
  return typeof detail === 'string' ? detail : detail.message || JSON.stringify(detail);
};

function Logo({ brand, slot, label, hint, onChanged, onError }) {
  const [src, setSrc] = useState(null);
  const present = brand.logos?.[slot];
  const version = brand.updated;

  useEffect(() => {
    if (!present) { setSrc(null); return undefined; }
    let url = null;
    let cancelled = false;
    getBrandLogo(brand.id, slot).then((blob) => {
      if (cancelled) return;
      url = URL.createObjectURL(blob);
      setSrc(url);
    }).catch(() => {});
    return () => { cancelled = true; if (url) URL.revokeObjectURL(url); };
  }, [brand.id, slot, present, version]);

  const upload = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    try {
      onChanged(await uploadBrandLogo(brand.id, slot, file));
    } catch (err) {
      onError(errorText(err));
    }
  };

  return (
    <div style={{ flex: '1 1 12rem' }}>
      <strong>{label}</strong> <span style={{ color: '#888' }}>{hint}</span>
      <div style={{ height: '4rem', margin: '0.25rem 0' }}>
        {src ? <img src={src} alt={`${brand.name} ${label} logo`} style={{ maxHeight: '4rem', maxWidth: '100%', background: '#fff' }} />
          : <span style={{ color: '#888' }}>None</span>}
      </div>
      <label>
        <span className="secondary">Upload PNG or JPEG</span>{' '}
        <input type="file" accept="image/png,image/jpeg" aria-label={`${brand.name} ${label} logo`} onChange={upload} />
      </label>
      {present && <button className="secondary" onClick={async () => {
        try { onChanged(await clearBrandLogo(brand.id, slot)); } catch (err) { onError(errorText(err)); }
      }}>Remove</button>}
    </div>
  );
}

function Brand({ brand, installation, onChanged, onDeleted }) {
  const [fields, setFields] = useState({ name: brand.name, primary: brand.primary, secondary: brand.secondary || '',
    prepared_for: brand.prepared_for || '' });
  const [error, setError] = useState(null);
  const [confirming, setConfirming] = useState(false);
  const changed = Object.keys(fields).some((k) => fields[k] !== (brand[k] || ''));

  const set = (key) => (e) => setFields({ ...fields, [key]: e.target.value });
  const save = async () => {
    setError(null);
    try {
      onChanged(await editBrand(brand.id, fields));
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="card" data-testid={`brand-${brand.id}`}>
      <h3>{brand.name}{installation === brand.id && ' (the installation\'s)'}</h3>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'end' }}>
        <label>Name <input aria-label="Name" value={fields.name} onChange={set('name')} /></label>
        <label>Primary <input type="color" aria-label="Primary colour" value={fields.primary} onChange={set('primary')} /></label>
        <label>Secondary <input type="color" aria-label="Secondary colour" value={fields.secondary || '#ffffff'}
          onChange={set('secondary')} /></label>
        {fields.secondary && <button className="secondary" onClick={() => setFields({ ...fields, secondary: '' })}>No secondary</button>}
        <label>Prepared for <input aria-label="Prepared for" value={fields.prepared_for} onChange={set('prepared_for')} /></label>
        <button disabled={!changed} onClick={save}>Save</button>
      </div>
      {brand.notes?.map((note) => <p key={note} className="licence-notice">{note}</p>)}
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
        {SLOTS.map(([slot, label, hint]) => (
          <Logo key={slot} brand={brand} slot={slot} label={label} hint={hint} onChanged={onChanged} onError={setError} />
        ))}
      </div>
      {error && <div className="error">{error}</div>}
      <div style={{ marginTop: '0.5rem' }}>
        {confirming
          ? <><button onClick={async () => {
            try { await deleteBrand(brand.id); onDeleted(); } catch (err) { setError(errorText(err)); }
          }}>Delete it</button>{' '}<button className="secondary" onClick={() => setConfirming(false)}>Keep it</button>
            <span style={{ color: '#888' }}> Cases that named it fall back to the installation's brand.</span></>
          : <button className="secondary" onClick={() => setConfirming(true)}>Delete…</button>}
      </div>
    </div>
  );
}

function AddBrand({ onAdded }) {
  const [name, setName] = useState('');
  const [primary, setPrimary] = useState('#1f3a5f');
  const [error, setError] = useState(null);

  const add = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      onAdded(await addBrand({ name: name.trim(), primary }));
      setName('');
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <form className="card" onSubmit={add}>
      <h2>Add a brand</h2>
      <label>Name <input aria-label="New brand name" value={name} onChange={(e) => setName(e.target.value)} /></label>{' '}
      <label>Primary <input type="color" aria-label="New brand primary colour" value={primary}
        onChange={(e) => setPrimary(e.target.value)} /></label>{' '}
      <button type="submit" disabled={!name.trim()}>Add</button>
      {error && <div className="error">{error}</div>}
    </form>
  );
}

export default function Branding({ serverMode = true }) {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const isAdmin = managesLicence(user, serverMode);

  const load = useCallback(async () => {
    try {
      setData(await getBrands());
    } catch (err) {
      setError(errorText(err));
    }
  }, []);

  useEffect(() => { if (isAdmin && serverMode != null) load(); }, [isAdmin, serverMode, load]);

  if (serverMode == null) return <div className="loading">Loading the brands…</div>;
  if (!isAdmin) {
    return <div className="card"><h2>Branding</h2><p>Report branding is managed by Rowanholt administrators.</p></div>;
  }
  if (error && !data) return <div className="card"><div className="error">{error}</div></div>;
  if (!data) return <div className="loading">Loading the brands…</div>;

  const choose = async (e) => {
    setError(null);
    try {
      setData(await chooseInstallationBrand(e.target.value || null));
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="branding">
      <div className="card">
        <h2>Report branding</h2>
        <p>The Word report's colours and logos. Markdown reports, findings and the Navigator layer stay as they are.</p>
        <p className={data.report_branding ? '' : 'licence-notice'} role="status">{data.says}</p>
        <label>
          The installation's brand{' '}
          <select aria-label="The installation's brand" value={data.installation || ''} onChange={choose}>
            <option value="">Rowanholt's own style</option>
            {data.brands.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
          </select>
        </label>
        {error && <div className="error">{error}</div>}
      </div>
      {data.brands.map((brand) => (
        <Brand key={`${brand.id}-${brand.updated}`} brand={brand} installation={data.installation}
          onChanged={load} onDeleted={load} />
      ))}
      <AddBrand onAdded={load} />
    </div>
  );
}
