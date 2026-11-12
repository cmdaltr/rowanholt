// The job page offers its owner's buttons only to its owner (or an admin, or locally): someone a
// job is shared with sees why, and a restart that keeps the output
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
