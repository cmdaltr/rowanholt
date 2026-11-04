/**
 * Vendor Logo Icons
 *
 * SVG icons for SIEM and threat intelligence vendors used throughout the Rowanholt application.
 * This component provides reusable vendor icons with proper gradients and styling.
 */

import React from 'react';

/**
 * Splunk Icon - Pink radial gradient with forward arrow
 */
export const SplunkIcon = ({ width = 32, height = 32, gradientId = 'splunkGradient' }) => (
  <svg width={width} height={height} viewBox="0 0 100 100" fill="none">
    <defs>
      <radialGradient id={gradientId} cx="30%" cy="30%">
        <stop offset="0%" style={{ stopColor: '#FF6B9D', stopOpacity: 1 }} />
        <stop offset="50%" style={{ stopColor: '#E91E8C', stopOpacity: 1 }} />
        <stop offset="100%" style={{ stopColor: '#C4166C', stopOpacity: 1 }} />
      </radialGradient>
    </defs>
    <circle cx="50" cy="50" r="48" fill={`url(#${gradientId})`}/>
    <path d="M45 35 L60 50 L45 65" stroke="white" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
  </svg>
);

/**
 * Elastic (Elasticsearch/Kibana) Icon - Tri-color horizontal bars
 */
export const ElasticIcon = ({ width = 32, height = 32, gradientIdPrefix = 'elastic' }) => (
  <svg width={width} height={height} viewBox="0 0 100 100" fill="none">
    <defs>
      <linearGradient id={`${gradientIdPrefix}Yellow`} x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style={{ stopColor: '#FED10A', stopOpacity: 1 }} />
        <stop offset="100%" style={{ stopColor: '#FDB42F', stopOpacity: 1 }} />
      </linearGradient>
      <linearGradient id={`${gradientIdPrefix}Teal`} x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style={{ stopColor: '#00BFB3', stopOpacity: 1 }} />
        <stop offset="100%" style={{ stopColor: '#00A9A5', stopOpacity: 1 }} />
      </linearGradient>
      <linearGradient id={`${gradientIdPrefix}Blue`} x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style={{ stopColor: '#24BBB1', stopOpacity: 1 }} />
        <stop offset="100%" style={{ stopColor: '#0077CC', stopOpacity: 1 }} />
      </linearGradient>
    </defs>
    <rect x="10" y="20" width="70" height="12" rx="6" fill={`url(#${gradientIdPrefix}Yellow)`}/>
    <rect x="15" y="44" width="70" height="12" rx="6" fill={`url(#${gradientIdPrefix}Teal)`}/>
    <rect x="20" y="68" width="70" height="12" rx="6" fill={`url(#${gradientIdPrefix}Blue)`}/>
  </svg>
);

/**
 * MITRE ATT&CK Navigator Icon - Yellow/gold shield with target crosshair
 */
export const NavigatorIcon = ({ width = 32, height = 32, gradientId = 'mitreGradient' }) => (
  <svg width={width} height={height} viewBox="0 0 100 100" fill="none">
    <defs>
      <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style={{ stopColor: '#FFD700', stopOpacity: 1 }} />
        <stop offset="50%" style={{ stopColor: '#FFC107', stopOpacity: 1 }} />
        <stop offset="100%" style={{ stopColor: '#FF9800', stopOpacity: 1 }} />
      </linearGradient>
    </defs>
    {/* Shield outline */}
    <path d="M50 10 L85 25 L85 50 Q85 75 50 90 Q15 75 15 50 L15 25 Z" fill={`url(#${gradientId})`}/>
    {/* Inner target circles */}
    <circle cx="50" cy="50" r="22" fill="none" stroke="white" strokeWidth="3"/>
    <circle cx="50" cy="50" r="14" fill="none" stroke="white" strokeWidth="3"/>
    <circle cx="50" cy="50" r="6" fill="white"/>
    {/* Crosshair */}
    <line x1="50" y1="28" x2="50" y2="38" stroke="white" strokeWidth="2"/>
    <line x1="50" y1="62" x2="50" y2="72" stroke="white" strokeWidth="2"/>
    <line x1="28" y1="50" x2="38" y2="50" stroke="white" strokeWidth="2"/>
    <line x1="62" y1="50" x2="72" y2="50" stroke="white" strokeWidth="2"/>
  </svg>
);

/**
 * Generic vendor icon component that selects the appropriate icon based on vendor name
 */
export const VendorIcon = ({ vendor, width = 32, height = 32, gradientId }) => {
  const vendorLower = vendor?.toLowerCase();

  if (vendorLower === 'splunk') {
    return <SplunkIcon width={width} height={height} gradientId={gradientId || 'splunkGradient'} />;
  } else if (vendorLower === 'elastic' || vendorLower === 'elasticsearch' || vendorLower === 'kibana') {
    return <ElasticIcon width={width} height={height} gradientIdPrefix={gradientId || 'elastic'} />;
  } else if (vendorLower === 'navigator' || vendorLower === 'mitre' || vendorLower === 'att&ck') {
    return <NavigatorIcon width={width} height={height} gradientId={gradientId || 'mitreGradient'} />;
  }

  return null;
};

export default VendorIcon;
