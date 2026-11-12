// What each job status is called on screen, and which statuses mean the job is being worked on.
// The backend's list is models/job.py's JobStatus.

const LABELS = {
  pending: 'Pending',
  running: 'Running',
  paused: 'Paused',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
  archived: 'Archived',
  awaiting_confirmation: 'Awaiting confirmation',
  // A confirmed retry of removing the old output, in the worker; the job runs once it's done
  removing: 'Removing old output',
};

// A job with one of these can't be deleted or archived (the backend refuses: main.BUSY_JOB_STATUSES)
export const BUSY_STATUSES = ['pending', 'running', 'paused', 'removing'];

// A job with one of these can be cancelled (a removal can't: it runs to the end, or fails)
export const STOPPABLE_STATUSES = ['pending', 'running', 'paused'];

export const statusLabel = (status) => LABELS[status] || String(status || '').replace(/_/g, ' ');

export const STATUS_FILTERS = ['pending', 'running', 'paused', 'awaiting_confirmation', 'removing',
  'completed', 'failed', 'cancelled'];
