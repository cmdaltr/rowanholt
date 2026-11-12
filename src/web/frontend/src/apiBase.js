// Where the API is. The local stack sets REACT_APP_API_URL to http://localhost:5688; the
// server build sets it empty, so calls go to /api on the page's own origin through the
// reverse proxy. Unset (npm start outside Docker), it's the local default.
export const API_BASE_URL = process.env.REACT_APP_API_URL ?? 'http://localhost:5688';

// Splunk, Kibana and the ATT&CK Navigator, on their usual ports of whichever host serves
// this page: localhost on an analyst's machine, the server (behind its proxy) otherwise.
export const serviceUrl = (port, path = '') =>
  `${window.location.protocol}//${window.location.hostname}:${port}${path}`;

// Sent with every request to the API: the backend refuses a state-changing request signed in by
// the session cookie without it (auth/access.py), so a page on another origin, which can't add a
// header without CORS allowing it, can't act as the person signed in.
export const CSRF_HEADERS = { 'X-Rowanholt': '1' };
