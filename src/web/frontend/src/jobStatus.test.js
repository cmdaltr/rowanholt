import { BUSY_STATUSES, STATUS_FILTERS, STOPPABLE_STATUSES, statusLabel } from './jobStatus';

test('a removal has a label of its own and holds the job like running', () => {
  expect(statusLabel('removing')).toBe('Removing old output');
  expect(statusLabel('awaiting_confirmation')).toBe('Awaiting confirmation');
  expect(BUSY_STATUSES).toContain('removing');
  expect(STOPPABLE_STATUSES).not.toContain('removing');
  expect(STATUS_FILTERS).toContain('removing');
});

test('an unknown status is shown as it is, underscores as spaces', () => {
  expect(statusLabel('some_new_status')).toBe('some new status');
});
