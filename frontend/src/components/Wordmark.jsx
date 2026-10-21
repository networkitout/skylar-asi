import React from 'react';

// Keep in sync with backend/branding.py; the backend renders the same lockup into exports.
export const TAGLINE = 'Attack surface intelligence';
export const TAGLINE_LONG = `${TAGLINE} for Cloudflare`;

// Orange SKY + blue LAR, equal weight (see docs/UI_CONVENTIONS.md).
const Wordmark = ({ size = 18 }) => (
  <span className={`wordmark wordmark-${size}`} aria-label="SKYLAR">
    <span className="wordmark-sky">SKY</span>
    <span className="wordmark-lar">LAR</span>
  </span>
);

export default Wordmark;
