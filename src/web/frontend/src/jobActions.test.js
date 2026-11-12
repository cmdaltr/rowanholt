// What a user is offered for a job: everything when it's theirs (or they're an admin, or local),
// only watching, a restart into the output and export when it's merely shared with them
import { bulkOffered, bulkPlan, canManage, jobPageActions, restartFresh, skippedNote } from './jobActions';

const job = (id, status, can_manage) => ({ id, status, can_manage });

test('a job without can_manage (local mode, an older server) is the user\'s to manage', () => {
  expect(canManage({ status: 'running' })).toBe(true);
  expect(canManage(job('a', 'running', true))).toBe(true);
  expect(canManage(job('a', 'running', false))).toBe(false);
});

test('the owner sees every action the status allows', () => {
  expect(jobPageActions(job('a', 'running', true))).toEqual({
    pause: true, resume: false, cancel: true, restart: false, delete: false, settleRemoval: false });
  expect(jobPageActions(job('a', 'paused', true))).toMatchObject({ resume: true, cancel: true });
  expect(jobPageActions(job('a', 'completed', true))).toMatchObject({ restart: true, delete: true });
  expect(jobPageActions(job('a', 'awaiting_confirmation', true)).settleRemoval).toBe(true);
});

test('someone it is shared with can only restart it, into its output', () => {
  for (const status of ['pending', 'running', 'paused', 'awaiting_confirmation']) {
    const offered = jobPageActions(job('a', status, false));
    expect(Object.values(offered).some(Boolean)).toBe(false);
  }
  expect(jobPageActions(job('a', 'completed', false))).toEqual({
    pause: false, resume: false, cancel: false, restart: true, delete: false, settleRemoval: false });
  expect(restartFresh(job('a', 'completed', false))).toBe(false);
  expect(restartFresh(job('a', 'completed', true))).toBeUndefined();
});

test('a bulk stop skips the jobs that are someone else\'s, and says how many', () => {
  const selection = [job('mine', 'running', true), job('theirs', 'running', false), job('done', 'completed', true)];
  const plan = bulkPlan(selection, 'stop');
  expect(plan.eligible.map((j) => j.id)).toEqual(['mine']);
  expect(plan.notYours.map((j) => j.id)).toEqual(['theirs']);
  expect(plan.wrongStatus.map((j) => j.id)).toEqual(['done']);
  expect(skippedNote(plan, 'stop')).toBe(
    " 1 selected job is someone else's and will be skipped: only the job's owner or an admin can stop it.");
  expect(skippedNote(bulkPlan([job('mine', 'running', true)], 'stop'), 'stop')).toBe('');
});

test('archive and delete follow the same rule; export and restart are open to everyone who sees it', () => {
  const selection = [job('mine', 'failed', true), job('theirs', 'completed', false)];
  expect(bulkPlan(selection, 'delete').eligible.map((j) => j.id)).toEqual(['mine']);
  expect(bulkPlan(selection, 'archive').notYours.map((j) => j.id)).toEqual(['theirs']);
  expect(bulkPlan(selection, 'export').eligible).toHaveLength(2);
  const restart = bulkPlan(selection, 'restart');
  expect(restart.eligible).toHaveLength(2);
  // Restarted with fresh=false: the server refuses them a fresh one
  expect(restart.keepOutput.map((j) => j.id)).toEqual(['theirs']);
});

test('restoring from the archive is the owner\'s, and only for archived jobs', () => {
  const plan = bulkPlan([job('mine', 'archived', true), job('theirs', 'archived', false),
                         job('live', 'completed', true)], 'restore');
  expect(plan.eligible.map((j) => j.id)).toEqual(['mine']);
  expect(plan.notYours.map((j) => j.id)).toEqual(['theirs']);
  expect(plan.wrongStatus.map((j) => j.id)).toEqual(['live']);
  expect(skippedNote(plan, 'restore')).toContain("only the job's owner or an admin can restore it");
});

test('an owner\'s bulk button is offered only when one of the selection is the user\'s', () => {
  const theirs = [job('t1', 'running', false), job('t2', 'completed', false)];
  for (const action of ['stop', 'archive', 'restore', 'delete']) {
    expect(bulkOffered(theirs, action)).toBe(false);
    expect(bulkOffered([...theirs, job('m', 'running', true)], action)).toBe(true);
  }
  expect(bulkOffered(theirs, 'restart')).toBe(true);
  expect(bulkOffered(theirs, 'export')).toBe(true);
  expect(bulkOffered([], 'export')).toBe(false);
});
