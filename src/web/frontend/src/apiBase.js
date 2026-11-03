// Where the API is. The local stack sets REACT_APP_API_URL to http://localhost:5688; the
// server build sets it empty, so calls go to /api on the page's own origin through the
// reverse proxy. Unset (npm start outside Docker), it's the local default.
export const API_BASE_URL = process.env.REACT_APP_API_URL ?? 'http://localhost:5688';

// Splunk, Kibana and the ATT&CK Navigator, on their usual ports of whichever host serves
// this page: localhost on an analyst's machine, the server (behind its proxy) otherwise.
export const serviceUrl = (port, path = '') =>
  `${window.location.protocol}//${window.location.hostname}:${port}${path}`;
