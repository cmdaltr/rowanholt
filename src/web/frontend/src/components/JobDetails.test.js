// The job page offers its owner's buttons only to its owner (or an admin, or locally): someone a
// job is shared with sees why, and a restart that keeps the output
import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import JobDetails from './JobDetails';
import * as api from '../api';

jest.mock('../api', () => ({
  getJob: jest.fn(),
  cancelJob: jest.fn(),
  pauseJob: jest.fn(),
  resumeJob: jest.fn(),
  deleteJob: jest.fn(),
  restartJob: jest.fn(),
  exportSiem: jest.fn(),
  getSiemExport: jest.fn(),
  confirmRemoval: jest.fn(),
  cancelRemoval: jest.fn(),
  // JobSharing: local mode, so it draws nothing
  getAuthConfig: jest.fn(),
  getJobSharing: jest.fn(),
  setJobSharing: jest.fn(),
  getUserDirectory: jest.fn(),
}));

const JOB = {
  id: 'j1', case_number: 'CASE-1', status: 'running', progress: 40, source_paths: ['/e/a.E01'],
  destination_path: '/out/CASE-1', options: {}, log: [], created_at: '2026-11-12T09:00:00',
  started_at: '2026-11-12T09:00:00', completed_at: null, owner: 'alice', shared_with: ['bob'],
};

const show = async (job) => {
  api.getJob.mockResolvedValue(job);
  api.getAuthConfig.mockResolvedValue({ server_mode: false });
  render(
    <MemoryRouter initialEntries={['/jobs/j1']}>
      <Routes><Route path="/jobs/:jobId" element={<JobDetails />} /></Routes>
    </MemoryRouter>
  );
  await screen.findByText('Job Details');
};

beforeEach(() => jest.resetAllMocks());

test('the owner can pause and cancel a running job', async () => {
  await show({ ...JOB, can_manage: true });
  expect(screen.getByText('Pause Job')).toBeInTheDocument();
  expect(screen.getByText('Cancel Job')).toBeInTheDocument();
  expect(screen.queryByText(/shared with you/)).not.toBeInTheDocument();
});

test('someone it is shared with is not offered pause or cancel, and is told why', async () => {
  await show({ ...JOB, can_manage: false });
  expect(screen.queryByText('Pause Job')).not.toBeInTheDocument();
  expect(screen.queryByText('Cancel Job')).not.toBeInTheDocument();
  expect(screen.getByRole('note')).toHaveTextContent("alice's job, shared with you");
});

test('their restart keeps the output, and there is no delete', async () => {
  await show({ ...JOB, status: 'completed', can_manage: false });
  expect(screen.queryByText('Delete Job')).not.toBeInTheDocument();
  api.restartJob.mockResolvedValue({});
  fireEvent.click(screen.getByText('Restart Job'));
  await waitFor(() => expect(api.restartJob).toHaveBeenCalledWith('j1', false, false));
  // The page reloads the job afterwards: let it settle before the test ends
  await waitFor(() => expect(screen.getByText('Restart Job')).not.toBeDisabled());
});

test('a failed removal waits for the owner rather than asking them', async () => {
  const pending_action = { message: 'Could not remove it', target_path: '/out/CASE-1' };
  await show({ ...JOB, status: 'awaiting_confirmation', pending_action, can_manage: false });
  expect(screen.queryByText('Try Again')).not.toBeInTheDocument();
  expect(screen.getByText(/waits for its owner or an admin/)).toBeInTheDocument();
});

describe('the SIEM export', () => {
  const COMPLETED = { ...JOB, status: 'completed', progress: 100, can_manage: true, options: { splunk: true, elastic: true } };
  const QUEUED = { state: 'queued', task_id: 't1', targets: ['Splunk', 'Elastic'], requested_by: 'alice', results: {} };

  afterEach(() => jest.useRealTimers());

  test('is queued, polled while it runs, and its outcome shown', async () => {
    jest.useFakeTimers();
    api.getSiemExport.mockResolvedValue({ state: 'none' });
    await show(COMPLETED);
    await waitFor(() => expect(api.getSiemExport).toHaveBeenCalledWith('j1'));
    expect(screen.queryByRole('status')).not.toBeInTheDocument();

    api.exportSiem.mockResolvedValue(QUEUED);
    fireEvent.click(screen.getByText('Export to SIEM'));
    expect(await screen.findByText(/queued by alice: waiting for the worker/)).toBeInTheDocument();
    expect(api.exportSiem).toHaveBeenCalledWith('j1');
    expect(screen.getByText('Exporting to SIEM...')).toBeDisabled();

    api.getSiemExport.mockResolvedValue({ ...QUEUED, state: 'running', phase: 'Elastic', step: 2, steps: 2 });
    await act(async () => { jest.advanceTimersByTime(3000); });
    expect(await screen.findByText(/SIEM export running: Elastic \(2 of 2\)/)).toBeInTheDocument();

    api.getSiemExport.mockResolvedValue({
      ...QUEUED,
      state: 'succeeded',
      results: { Splunk: { ok: true, note: 'index=case-1' }, Elastic: { ok: true, total: 4242 } },
    });
    await act(async () => { jest.advanceTimersByTime(3000); });
    const done = await screen.findByText(/SIEM export finished/);
    expect(done).toHaveTextContent('Splunk (index=case-1); Elastic 4,242 documents');
    expect(done).toHaveClass('success');
    expect(screen.getByText('Export to SIEM')).not.toBeDisabled();

    // Finished: no more polling
    const calls = api.getSiemExport.mock.calls.length;
    await act(async () => { jest.advanceTimersByTime(9000); });
    expect(api.getSiemExport.mock.calls.length).toBe(calls);
  });

  test('a failed target is shown as an error, with why', async () => {
    api.getSiemExport.mockResolvedValue({
      ...QUEUED,
      state: 'failed',
      results: { Splunk: { ok: false, error: 'Splunk at splunk:8089 is unreachable' }, Elastic: { ok: true } },
    });
    await show(COMPLETED);
    const failed = await screen.findByText(/SIEM export failed/);
    expect(failed).toHaveTextContent('Splunk: Splunk at splunk:8089 is unreachable; Elastic');
    expect(failed).toHaveClass('error');
  });

  test('one already running answers 409, and that one is shown', async () => {
    api.getSiemExport.mockResolvedValueOnce({ state: 'none' })
      .mockResolvedValue({ ...QUEUED, state: 'running', phase: 'Splunk', step: 1, steps: 2 });
    await show(COMPLETED);
    api.exportSiem.mockRejectedValue({ response: { status: 409, data: { detail: 'A SIEM export is already queued or running for this job' } } });
    fireEvent.click(await screen.findByText('Export to SIEM'));
    expect(await screen.findByText('A SIEM export is already queued or running for this job')).toBeInTheDocument();
    expect(await screen.findByText(/SIEM export running: Splunk \(1 of 2\)/)).toBeInTheDocument();
  });

  test('is not offered for a job with no SIEM option, or one not completed', async () => {
    await show({ ...COMPLETED, options: {} });
    expect(screen.queryByText('Export to SIEM')).not.toBeInTheDocument();
    expect(api.getSiemExport).not.toHaveBeenCalled();
  });
});
