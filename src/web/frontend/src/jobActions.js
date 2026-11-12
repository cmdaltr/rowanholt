// What the signed-in user may do to a job, so the web app offers only what the server allows.
// On a team server the people a job is shared with can see it, restart it into its output, export
// it and ask Smith; cancelling, pausing, deleting, archiving, a fresh restart, sharing and settling
// a failed removal are its owner's or an admin's (main._manager_refusal). The API says which per
// job (`can_manage`); hidden actions are still refused by the server, this only stops offering them.

import { BUSY_STATUSES, STOPPABLE_STATUSES } from './jobStatus';

// The server's own wording (main.NOT_THEIRS), for the skipped count in a bulk action
export const NOT_YOURS = "only the job's owner or an admin can";

const RESTARTABLE = ['failed', 'cancelled', 'completed'];

// Missing means local mode or a server from before the field: everything, as before
export const canManage = (job) => job?.can_manage !== false;

// A restart someone it's shared with makes keeps the output (fresh=false); undefined leaves the
// choice to the server's default (fresh for a completed job)
export const restartFresh = (job) => (canManage(job) ? undefined : false);

// The buttons the job page shows
export const jobPageActions = (job) => {
  const status = job?.status;
  const manage = canManage(job);
  return {
    pause: manage && status === 'running',
    resume: manage && status === 'paused',
    cancel: manage && STOPPABLE_STATUSES.includes(status),
    restart: RESTARTABLE.includes(status),
    delete: manage && RESTARTABLE.includes(status),
    settleRemoval: manage && status === 'awaiting_confirmation',
  };
};

const STATUS_RULES = {
  stop: (job) => STOPPABLE_STATUSES.includes(job.status),
  restart: (job) => RESTARTABLE.includes(job.status),
  archive: (job) => !BUSY_STATUSES.includes(job.status) && job.status !== 'archived',
  delete: (job) => !BUSY_STATUSES.includes(job.status),
  export: () => true,
};

// Restart and export are open to anyone who can see the job; the rest need its owner or an admin
const MANAGER_ONLY = ['stop', 'archive', 'delete'];

// How a bulk action splits the selection: `eligible` are the jobs it's sent for, `notYours` those
// skipped because someone else owns them, `wrongStatus` those it can't apply to at all. A restart
// sends the jobs the user doesn't manage separately, with fresh=false (`keepOutput`).
export const bulkPlan = (jobs, action) => {
  const managerOnly = MANAGER_ONLY.includes(action);
  const fits = STATUS_RULES[action];
  const plan = { eligible: [], notYours: [], wrongStatus: [], keepOutput: [] };
  jobs.forEach((job) => {
    if (managerOnly && !canManage(job)) plan.notYours.push(job);
    else if (!fits(job)) plan.wrongStatus.push(job);
    else {
      plan.eligible.push(job);
      if (action === 'restart' && !canManage(job)) plan.keepOutput.push(job);
    }
  });
  return plan;
};

// Whether the bulk button is offered at all: not when every selected job is someone else's and
// the action is the owner's
export const bulkOffered = (jobs, action) =>
  jobs.length > 0 && (!MANAGER_ONLY.includes(action) || jobs.some(canManage));

// The sentence a confirmation adds about jobs it leaves alone because they aren't the user's
export const skippedNote = (plan, verb) => {
  const n = plan.notYours.length;
  if (!n) return '';
  return ` ${n} selected job${n === 1 ? ' is' : 's are'} someone else's and will be skipped: ${NOT_YOURS} ${verb} it.`;
};
