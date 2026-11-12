// The Archived Jobs page restores and deletes through the bulk routes, offers both only for jobs
// the user owns (or manages as an admin, or locally), and says what a delete leaves on disk
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import Archive from './Archive';
import * as api from '../api';

jest.mock('../api', () => ({
  listJobs: jest.fn(),
  bulkUnarchiveJobs: jest.fn(),
  bulkDeleteJobs: jest.fn(),
}));

const job = (id, extra = {}) => ({
  id, case_number: `CASE-${id}`, status: 'archived', source_paths: ['/e/a.E01'],
  destination_path: `/out/CASE-${id}`, created_at: '2026-11-12T09:00:00', ...extra,
});

const show = async (jobs) => {
  api.listJobs.mockResolvedValue({ jobs, total: jobs.length });
  render(<MemoryRouter><Archive /></MemoryRouter>);
  await screen.findByText('Archived Jobs');
};

beforeEach(() => {
  jest.resetAllMocks();
  window.confirm = jest.fn();
});

test("someone else's job can't be selected, so it's never offered restore or delete", async () => {
  await show([job('mine', { can_manage: true }), job('theirs', { can_manage: false })]);
  expect(screen.getByLabelText('Select CASE-mine')).toBeInTheDocument();
  expect(screen.queryByLabelText('Select CASE-theirs')).not.toBeInTheDocument();
  expect(screen.queryByText(/^Restore/)).not.toBeInTheDocument();

  fireEvent.click(screen.getByLabelText('Select all'));
  expect(screen.getByText('Restore (1)')).toBeInTheDocument();
  expect(screen.getByText('Delete Permanently (1)')).toBeInTheDocument();
});

test('nothing selectable when every archived job is someone else\'s', async () => {
  await show([job('theirs', { can_manage: false })]);
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});

test('without can_manage (local mode, an older server) every job can be selected', async () => {
  await show([job('a'), job('b')]);
  fireEvent.click(screen.getByLabelText('Select all'));
  expect(screen.getByText('Restore (2)')).toBeInTheDocument();
});

test('restore sends the selection to the bulk route and reloads the list', async () => {
  await show([job('a'), job('b')]);
  api.bulkUnarchiveJobs.mockResolvedValue({ results: [
    { job_id: 'a', success: true, status: 'completed' }] });
  api.listJobs.mockResolvedValue({ jobs: [job('b')], total: 1 });
  fireEvent.click(screen.getByLabelText('Select CASE-a'));
  fireEvent.click(screen.getByText('Restore (1)'));

  await waitFor(() => expect(api.bulkUnarchiveJobs).toHaveBeenCalledWith(['a']));
  expect(await screen.findByRole('status')).toHaveTextContent('Restored to Jobs: 1 job.');
  await waitFor(() => expect(screen.queryByText('CASE-a')).not.toBeInTheDocument());
  expect(api.listJobs).toHaveBeenCalledTimes(2);
  expect(api.listJobs).toHaveBeenLastCalledWith('archived');
  expect(window.confirm).not.toHaveBeenCalled();
});

test('a job the server refuses is named in the page, not an alert', async () => {
  await show([job('a'), job('b')]);
  window.alert = jest.fn();
  api.bulkUnarchiveJobs.mockResolvedValue({ results: [
    { job_id: 'a', success: true, status: 'failed' },
    { job_id: 'b', success: false, error: "Only the job's owner or an admin can restore it from the archive" }] });
  fireEvent.click(screen.getByLabelText('Select all'));
  fireEvent.click(screen.getByText('Restore (2)'));

  expect(await screen.findByRole('alert')).toHaveTextContent(
    "Couldn't restore 1 job: CASE-b (Only the job's owner or an admin can restore it from the archive)");
  expect(screen.getByRole('status')).toHaveTextContent('Restored to Jobs: 1 job.');
  expect(window.alert).not.toHaveBeenCalled();
});

test('a failed request shows the server\'s reason', async () => {
  await show([job('a')]);
  api.bulkDeleteJobs.mockRejectedValue({ response: { data: { detail: 'Database unavailable' } } });
  window.confirm.mockReturnValue(true);
  fireEvent.click(screen.getByLabelText('Select CASE-a'));
  fireEvent.click(screen.getByText('Delete Permanently (1)'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable');
});

test('the delete confirmation says the output stays on disk, and where', async () => {
  await show([job('a'), job('b', { destination_path: null, result: { output_directory: '/data/b' } })]);
  window.confirm.mockReturnValue(false);
  fireEvent.click(screen.getByLabelText('Select all'));
  fireEvent.click(screen.getByText('Delete Permanently (2)'));

  const asked = window.confirm.mock.calls[0][0];
  expect(asked).toMatch(/^Permanently delete 2 archived jobs\? This can't be undone\./);
  expect(asked).toContain("deletes each job's record (its settings, status, log, owner and sharing)");
  // The case's rows go with the job (storage.delete_job); they used to be left behind, and the
  // confirmation said so
  expect(asked).toContain("its case's findings, notes, host assignments and activity");
  expect(asked).not.toMatch(/stay in Rowanholt's database/);
  expect(asked).toContain('The security log keeps a record of the deletion.');
  expect(asked).toContain('Nothing on disk is removed.');
  expect(asked).toContain('CASE-a: /out/CASE-a');
  expect(asked).toContain('CASE-b: /data/b');
  // Declined: nothing sent
  expect(api.bulkDeleteJobs).not.toHaveBeenCalled();
});

test('a confirmed delete goes to the bulk route and the list is reloaded', async () => {
  await show([job('a')]);
  window.confirm.mockReturnValue(true);
  api.bulkDeleteJobs.mockResolvedValue({ results: [{ job_id: 'a', success: true }] });
  api.listJobs.mockResolvedValue({ jobs: [], total: 0 });
  fireEvent.click(screen.getByLabelText('Select CASE-a'));
  fireEvent.click(screen.getByText('Delete Permanently (1)'));

  await waitFor(() => expect(api.bulkDeleteJobs).toHaveBeenCalledWith(['a']));
  expect(await screen.findByRole('status')).toHaveTextContent('Deleted the records of 1 job.');
  expect(await screen.findByText('No archived jobs found.')).toBeInTheDocument();
});

test('the Archived column shows when each job was archived, as the Created column shows its dates', async () => {
  // archived_at comes from the job (jobs.archived_at, set by archive); a job archived before it
  // was kept has none
  const archivedAt = '2026-11-12T10:30:00';
  await show([job('a', { archived_at: archivedAt }), job('b')]);
  const cells = (caseNumber) => screen.getByText(caseNumber).closest('tr').querySelectorAll('td');
  expect(cells('CASE-a')[4]).toHaveTextContent(new Date(archivedAt).toLocaleString());
  expect(cells('CASE-a')[3]).toHaveTextContent(new Date('2026-11-12T09:00:00').toLocaleString());
  expect(cells('CASE-b')[4]).toHaveTextContent('N/A');
});
