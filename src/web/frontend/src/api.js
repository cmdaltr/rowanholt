import axios from 'axios';
import { API_BASE_URL } from './apiBase';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Enable cookies for session management
});

// Add interceptor to include auth token from localStorage if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Add interceptor to handle 401 responses
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear auth data and redirect to login
      localStorage.removeItem('access_token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// File System API
export const browsePath = async (path = '/') => {
  const response = await api.get('/api/fs/browse', {
    params: { path },
  });
  return response.data;
};

// Jobs API
export const createJob = async (jobData) => {
  const response = await api.post('/api/jobs', jobData);
  return response.data;
};

export const listJobs = async (status = null, limit = 50, offset = 0) => {
  const response = await api.get('/api/jobs', {
    params: { status, limit, offset },
  });
  return response.data;
};

export const getJob = async (jobId) => {
  const response = await api.get(`/api/jobs/${jobId}`);
  return response.data;
};

export const updateJob = async (jobId, updateData) => {
  const response = await api.patch(`/api/jobs/${jobId}`, updateData);
  return response.data;
};

export const deleteJob = async (jobId) => {
  const response = await api.delete(`/api/jobs/${jobId}`);
  return response.data;
};

export const cancelJob = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/cancel`);
  return response.data;
};

export const pauseJob = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/pause`);
  return response.data;
};

export const resumeJob = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/resume`);
  return response.data;
};

// A job with findings answers 409 unless confirm is set: restarting rewrites the rows they point at
export const restartJob = async (jobId, confirm = false) => {
  const response = await api.post(`/api/jobs/${jobId}/restart`, null, { params: confirm ? { confirm: true } : {} });
  return response.data;
};

export const confirmSudo = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/confirm-sudo`);
  return response.data;
};

export const cancelSudo = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/cancel-sudo`);
  return response.data;
};

export const bulkCancelJobs = async (jobIds) => {
  const response = await api.post('/api/jobs/bulk/cancel', jobIds);
  return response.data;
};

export const bulkDeleteJobs = async (jobIds) => {
  const response = await api.post('/api/jobs/bulk/delete', jobIds);
  return response.data;
};

export const archiveJob = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/archive`);
  return response.data;
};

export const unarchiveJob = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/unarchive`);
  return response.data;
};

export const bulkArchiveJobs = async (jobIds) => {
  const response = await api.post('/api/jobs/bulk/archive', jobIds);
  return response.data;
};

export const bulkRestartJobs = async (jobIds, confirm = false) => {
  const response = await api.post('/api/jobs/bulk/restart', jobIds, { params: confirm ? { confirm: true } : {} });
  return response.data;
};

export const exportSiem = async (jobId) => {
  const response = await api.post(`/api/jobs/${jobId}/export-siem`);
  return response.data;
};

// Authentication API
export const register = async (userData) => {
  const response = await api.post('/api/auth/register', userData);
  return response.data;
};

export const login = async (username, password) => {
  // OAuth2 form data
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);

  const response = await api.post('/api/auth/login', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });

  // Store token and user data
  if (response.data.access_token) {
    localStorage.setItem('access_token', response.data.access_token);
    localStorage.setItem('user', JSON.stringify(response.data.user));
  }

  return response.data;
};

export const loginAsGuest = async () => {
  const response = await api.post('/api/auth/guest');

  // Store token and user data
  if (response.data.access_token) {
    localStorage.setItem('access_token', response.data.access_token);
    localStorage.setItem('user', JSON.stringify(response.data.user));
  }

  return response.data;
};

export const logout = async () => {
  try {
    await api.post('/api/auth/logout');
  } finally {
    // Clear local storage regardless of API response
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
  }
};

export const getAuthConfig = async () => {
  const response = await api.get('/api/auth/config');
  return response.data;
};

// A team server's licence (admins). Local mode needs none, and these answer 404 there.
export const getLicence = async () => (await api.get('/api/licence')).data;
export const getLicenceTerms = async () => (await api.get('/api/licence/terms')).data;
export const checkLicence = async (text) => (await api.post('/api/licence/check', { text })).data;
export const installLicence = async (text, termsVersion) =>
  (await api.put('/api/licence', { text, accept_terms: true, terms_version: termsVersion })).data;
export const removeLicence = async () => (await api.delete('/api/licence')).data;

// After single sign-on the session is a cookie; trade it for the bearer token the rest
// of the app keeps
export const completeSsoSignIn = async () => {
  const response = await api.post('/api/auth/session');
  localStorage.setItem('access_token', response.data.access_token);
  localStorage.setItem('user', JSON.stringify(response.data.user));
  return response.data;
};

// Long-lived, revocable tokens for scripts and ROWANHOLT_TOKEN (rowanholt mcp), made from a sign-in.
// The token itself comes back once, from createApiToken; the list has only its first characters
export const listApiTokens = async () => (await api.get('/api/auth/tokens')).data.tokens;
export const createApiToken = async (name, scope, days) =>
  (await api.post('/api/auth/tokens', { name, scope, days })).data;
export const revokeApiToken = async (id) => (await api.delete(`/api/auth/tokens/${id}`)).data;

export const getJobSharing = async (jobId) => {
  const response = await api.get(`/api/jobs/${jobId}/sharing`);
  return response.data;
};

export const setJobSharing = async (jobId, usernames) => {
  const response = await api.put(`/api/jobs/${jobId}/sharing`, { usernames });
  return response.data;
};

export const getUserDirectory = async () => {
  const response = await api.get('/api/auth/directory');
  return response.data;
};

export const getCurrentUser = async () => {
  const response = await api.get('/api/auth/me');
  return response.data;
};

export const forgotPassword = async (email) => {
  const response = await api.post('/api/auth/forgot-password', { email });
  return response.data;
};

export const resetPassword = async (token, newPassword) => {
  const response = await api.post('/api/auth/reset-password', {
    token,
    new_password: newPassword,
  });
  return response.data;
};

// Helper to check if user is authenticated
export const isAuthenticated = () => {
  return !!localStorage.getItem('access_token');
};

// Helper to get stored user
export const getStoredUser = () => {
  const userStr = localStorage.getItem('user');
  return userStr ? JSON.parse(userStr) : null;
};

// ============================================
// Mordor Datasets API
// ============================================

export const getMordorCatalog = async (params = {}) => {
  const response = await api.get('/api/mordor/catalog', { params });
  return response.data;
};

export const refreshMordorCatalog = async (force = false) => {
  const response = await api.post('/api/mordor/catalog/refresh', null, {
    params: { force }
  });
  return response.data;
};

export const getLocalMordorDatasets = async (params = {}) => {
  const response = await api.get('/api/mordor/datasets', { params });
  return response.data;
};

export const getMordorDataset = async (datasetId) => {
  const response = await api.get(`/api/mordor/datasets/${datasetId}`);
  return response.data;
};

export const downloadMordorDataset = async (datasetId, outputDir = null) => {
  const response = await api.post(`/api/mordor/datasets/${datasetId}/download`, {
    output_dir: outputDir
  });
  return response.data;
};

export const deleteMordorDataset = async (datasetId) => {
  const response = await api.delete(`/api/mordor/datasets/${datasetId}`);
  return response.data;
};

export const verifyMordorDataset = async (datasetId) => {
  const response = await api.get(`/api/mordor/datasets/${datasetId}/verify`);
  return response.data;
};

export const getMordorStats = async () => {
  const response = await api.get('/api/mordor/stats');
  return response.data;
};

// ============================================
// Anduril (Docker administration) API
// ============================================

export const getAndurilStatus = async () => (await api.get('/api/anduril/status')).data;

export const listAndurilContainers = async () => (await api.get('/api/anduril/containers')).data;

export const listAndurilImages = async () => (await api.get('/api/anduril/images')).data;

export const getAndurilLogs = async (name, tail = 200) =>
  (await api.get(`/api/anduril/containers/${encodeURIComponent(name)}/logs`, { params: { tail } })).data;

export const getAndurilStats = async (name) =>
  (await api.get(`/api/anduril/containers/${encodeURIComponent(name)}/stats`)).data;

export const andurilContainerAction = async (name, action, force = false) =>
  (await api.post(`/api/anduril/containers/${encodeURIComponent(name)}/${action}`, { force })).data;

export const andurilPullImage = async (ref) => (await api.post('/api/anduril/images/pull', { ref })).data;

export const andurilRemoveImage = async (id) => (await api.post('/api/anduril/images/remove', { id })).data;

export const andurilPruneImages = async () => (await api.post('/api/anduril/images/prune')).data;

export const getAndurilOp = async (opId) => (await api.get(`/api/anduril/ops/${opId}`)).data;

export const listAndurilOps = async () => (await api.get('/api/anduril/ops')).data;

export default api;

// Test lab API (proxied to the lab agent on the host)
export const getLabStatus = async () => (await api.get('/api/lab/status')).data;
export const getLabState = async () => (await api.get('/api/lab/state')).data;
export const saveLabConfig = async (settings) => (await api.put('/api/lab/config', { settings })).data;
export const setLabPassword = async (password) => (await api.put('/api/lab/password', { password })).data;
export const runLabCommand = async (command, args = []) => (await api.post('/api/lab/run', { command, args })).data;
export const listLabRuns = async () => (await api.get('/api/lab/runs')).data;
export const getLabRun = async (runId, offset = 0) =>
  (await api.get(`/api/lab/runs/${runId}`, { params: { offset } })).data;
export const cancelLabRun = async (runId) => (await api.post(`/api/lab/runs/${runId}/cancel`)).data;
// Lab VM consoles (lab_routes.lab_console_socket): the running VMs with a VNC server, one VM's
// (with the password noVNC answers with), and its websocket, which goes by the session cookie
export const listLabConsoles = async () => (await api.get('/api/lab/consoles')).data;
export const getLabConsole = async (engine, name) =>
  (await api.get(`/api/lab/consoles/${engine}/${encodeURIComponent(name)}`)).data;
export const labConsoleUrl = (engine, name) => {
  const base = new URL(API_BASE_URL || window.location.origin, window.location.href);
  return `${base.origin.replace(/^http/, 'ws')}/api/lab/consoles/${engine}/${encodeURIComponent(name)}/ws`;
};

// Mordor: recorded attack telemetry (src/mordor/telemetry) and the lab that records it
// (src/mordor/lab, through the host's lab agent; admin-only)
export const getTelemetryStatus = async () => (await api.get('/api/mordor/telemetry/status')).data;
export const getTelemetryTechniques = async (params = {}) =>
  (await api.get('/api/mordor/telemetry/techniques', { params })).data;
export const getTelemetryTechnique = async (tid, params = {}) =>
  (await api.get(`/api/mordor/telemetry/technique/${encodeURIComponent(tid)}`, { params })).data;
export const searchTelemetry = async (q) => (await api.get('/api/mordor/telemetry/search', { params: { q } })).data;
export const updateTelemetry = async () => (await api.post('/api/mordor/telemetry/build')).data;
export const getMordorLab = async () => (await api.get('/api/mordor/lab/overview')).data;
export const getMordorLabLogs = async (engine, name) =>
  (await api.get('/api/mordor/lab/logs', { params: { engine, name } })).data;
export const getMordorLabSteps = async (os) => (await api.get('/api/mordor/lab/provision-steps', { params: { os } })).data;
export const postMordorLab = async (verb, body) => (await api.post(`/api/mordor/lab/${verb}`, body)).data;

// Threat intelligence API
export const getThreatIntelSummary = async () => {
  const response = await api.get('/api/threat-intel');
  return response.data;
};

export const searchThreatIntel = async (params = {}) => {
  const response = await api.get('/api/threat-intel/indicators', { params });
  return response.data;
};

export const importThreatIntel = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await api.post('/api/threat-intel/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};

export const importTaxii = async (request) => {
  const response = await api.post('/api/threat-intel/taxii', request);
  return response.data;
};

export const deleteThreatIntelSource = async (source) => {
  const response = await api.delete(`/api/threat-intel/sources/${encodeURIComponent(source)}`);
  return response.data;
};

// validUntil: an ISO date, or null for no expiry (admins, on a team server)
export const setThreatIntelValidity = async (id, validUntil) =>
  (await api.put(`/api/threat-intel/indicators/${id}/validity`, { valid_until: validUntil })).data;

export const enrichValue = async (value) => {
  const response = await api.get('/api/threat-intel/enrich', { params: { value } });
  return response.data;
};

// Online lookups (VirusTotal), when .env turns them on: the value leaves Rowanholt
export const getLookupStatus = async () => (await api.get('/api/threat-intel/lookup')).data;

export const lookupValue = async (value) => (await api.post('/api/threat-intel/lookup', { value })).data;

// Case browser and collaboration API
const caseBase = (jobId) => `/api/jobs/${jobId}/case`;

export const getCase = async (jobId) => (await api.get(caseBase(jobId))).data;

export const getCaseRows = async (jobId, params) => (await api.get(`${caseBase(jobId)}/rows`, { params })).data;

// A table as CSV (the filter applied), for a spreadsheet: through the API client, so sign-in carries
export const getCaseRowsCsv = async (jobId, params) =>
  (await api.get(`${caseBase(jobId)}/rows.csv`, { params, responseType: 'blob' })).data;

export const getFindings = async (jobId, verify = false) =>
  (await api.get(`${caseBase(jobId)}/findings`, { params: { verify } })).data;

export const flagFinding = async (jobId, finding) => (await api.post(`${caseBase(jobId)}/findings`, finding)).data;

export const updateFinding = async (jobId, id, changes) =>
  (await api.patch(`${caseBase(jobId)}/findings/${id}`, changes)).data;

export const deleteFinding = async (jobId, id) => (await api.delete(`${caseBase(jobId)}/findings/${id}`)).data;

export const getCaseNotes = async (jobId) => (await api.get(`${caseBase(jobId)}/notes`)).data;

export const addCaseNote = async (jobId, body, findingId = null) =>
  (await api.post(`${caseBase(jobId)}/notes`, { body, finding_id: findingId })).data;

export const assignHost = async (jobId, host, changes) =>
  (await api.put(`${caseBase(jobId)}/hosts/${encodeURIComponent(host)}`, changes)).data;

export const getCaseActivity = async (jobId, since = 0) =>
  (await api.get(`${caseBase(jobId)}/activity`, { params: { since } })).data;

// The case's live socket (case_routes.live). Browsers can't put a header on a websocket, so it
// goes by the session cookie, never a token in the URL
export const caseLiveUrl = (jobId) => {
  const base = new URL(API_BASE_URL || window.location.origin, window.location.href);
  return `${base.origin.replace(/^http/, 'ws')}/api/jobs/${jobId}/case/live`; // https → wss
};

export const getCaseReport = async (jobId) =>
  (await api.get(`${caseBase(jobId)}/report`, { responseType: 'text' })).data;

// The case report (case_routes.full_report): confirmed findings first, then Elrond's report from the
// case. format is 'docx' or 'markdown'; a large case's first download reads all its tables
export const getCaseFullReport = async (jobId, format) =>
  (await api.get(`${caseBase(jobId)}/full-report`, { params: { format }, responseType: 'blob' })).data;

export const getConfirmedLayer = async (jobId) => (await api.get(`${caseBase(jobId)}/layer`)).data;

// How many findings a job's case has (0 when it has no output to flag yet): restarting rewrites the
// rows they point at, so the restart buttons warn first
export const countFindings = async (jobId) => {
  try {
    return (await getFindings(jobId)).length;
  } catch {
    return 0;
  }
};

// Volatility symbol tables for memory images (Aragorn's Settings; admin-only)
export const listSymbolTables = async () => (await api.get('/api/symbols')).data;

export const addSymbolTable = async (kind, file, extra = {}) => {
  const formData = new FormData();
  formData.append('kind', kind);
  formData.append('file', file);
  Object.entries(extra).forEach(([key, value]) => value && formData.append(key, value));
  return (await api.post('/api/symbols/add', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 0,
  })).data;
};

export const getSymbolTask = async (taskId) =>
  (await api.get(`/api/symbols/tasks/${encodeURIComponent(taskId)}`)).data;

// Sample data: public forensic images as ready cases (Aragorn's Settings; admin-only)
export const listSamples = async () => (await api.get('/api/samples')).data;

export const fetchSample = async (id) => (await api.post(`/api/samples/${encodeURIComponent(id)}/fetch`)).data;

export const getSampleTask = async (taskId) =>
  (await api.get(`/api/samples/tasks/${encodeURIComponent(taskId)}`)).data;

export const sampleJobRequest = async (id) => (await api.post(`/api/samples/${encodeURIComponent(id)}/import`)).data;
