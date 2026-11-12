// A completed job's manual SIEM export (POST/GET /api/jobs/{id}/export-siem): which jobs offer
// it, whether one is under way, and the sentence the job page shows for its record.

export const SIEM_OPTIONS = ['splunk', 'elastic', 'opensearch', 'timesketch', 'navigator'];

export const ACTIVE_STATES = ['queued', 'running'];

// What each target's count counts, as the backend reports it (siem_export.Progress)
const UNITS = { Elastic: 'documents', OpenSearch: 'records', Timesketch: 'events' };

export const offersSiemExport = (job) =>
  job?.status === 'completed' && SIEM_OPTIONS.some((option) => job.options?.[option]);

export const exportActive = (record) => ACTIVE_STATES.includes(record?.state);

const number = (n) => n.toLocaleString('en-GB');

const outcome = (name, result) => {
  if (!result.ok) return `${name}: ${result.error || 'failed'}`;
  if (typeof result.total === 'number') return `${name} ${number(result.total)} ${UNITS[name] || 'records'}`;
  if (typeof result.techniques === 'number') return `${name} ${result.techniques} techniques`;
  return result.note ? `${name} (${result.note})` : name;
};

// { kind, text } for the page's message styles (.info, .success, .error), or null with nothing to say
export const exportMessage = (record) => {
  if (!record || record.state === 'none') return null;
  const targets = (record.targets || []).join(', ');
  const results = Object.entries(record.results || {});
  switch (record.state) {
    case 'queued':
      return { kind: 'info', text: `SIEM export into ${targets} queued by ${record.requested_by}: waiting for the worker.` };
    case 'running': {
      const where = record.phase ? `${record.phase} (${record.step} of ${record.steps})` : 'starting';
      return { kind: 'info', text: `SIEM export running: ${where}. Its progress is in the job log.` };
    }
    case 'succeeded':
      return { kind: 'success', text: `SIEM export finished: ${results.map(([n, r]) => outcome(n, r)).join('; ')}.` };
    case 'failed':
      return {
        kind: 'error',
        text: `SIEM export failed: ${results.length ? results.map(([n, r]) => outcome(n, r)).join('; ') : record.error}.`,
      };
    default:
      return { kind: 'error', text: record.error || `SIEM export ${record.state}.` };
  }
};
