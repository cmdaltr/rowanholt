// An admin's invitation, the reset page in invite mode: who it's for and a username suggested, then
// the username, name and password, then the authenticator (only now is the username checked by the
// server), and the account is made only by a code from it; the backup codes once, then into the app
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Routes, Route } from 'react-router';
import ResetAccessPage from './ResetAccessPage';
import * as api from '../api';

vi.mock('../api', () => ({
  startAccessReset: vi.fn(),
  completeAccessReset: vi.fn(),
  previewInvitation: vi.fn(),
  startInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}));

const mockLogin = vi.fn();
vi.mock('../context/AuthContext', () => ({ useAuth: () => ({ login: mockLogin }) }));

const PREVIEW = { email: 'ada@example.org', role: 'admin', full_name: 'Ada', username: 'ada', expires_in: 86000 };
const ENROLMENT = { username: 'ada-l', secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', qr_svg: 'data:image/svg+xml,qr' };
const PASSWORD = 'an-invited-password-1';

const visit = async () => {
  await act(async () => {
    render(
      <MemoryRouter initialEntries={['/accept-invite#inv123']}>
        <Routes>
          <Route path="/accept-invite" element={<ResetAccessPage mode="invite" />} />
          <Route path="/jobs" element={<div>jobs</div>} />
        </Routes>
      </MemoryRouter>,
    );
  });
};

const details = async (username = 'ada-l') => {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: username } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: PASSWORD } });
  fireEvent.change(screen.getByLabelText('Confirm Password'), { target: { value: PASSWORD } });
  await act(async () => { fireEvent.click(screen.getByText('Continue')); });
};

beforeEach(() => vi.resetAllMocks());

test('details, then the authenticator, then the codes once, and the account is made only at the end', async () => {
  api.previewInvitation.mockResolvedValue(PREVIEW);
  api.startInvitation.mockResolvedValue(ENROLMENT);
  api.acceptInvitation.mockResolvedValue({ access_token: 't', user: { username: 'ada-l', role: 'admin' }, backup_codes: ['ABCDE-FGHJK'] });
  await visit();
  expect(api.previewInvitation).toHaveBeenCalledWith('inv123');
  expect(api.startAccessReset).not.toHaveBeenCalled();
  expect(screen.getByTestId('accept-invite-email')).toHaveTextContent('ada@example.org');
  expect(screen.getByLabelText('Username')).toHaveValue('ada');
  expect(screen.getByLabelText('Full Name')).toHaveValue('Ada');
  await details();
  expect(api.startInvitation).toHaveBeenCalledWith('inv123', 'ada-l');
  expect(screen.getByAltText('QR code for your authenticator app')).toHaveAttribute('src', 'data:image/svg+xml,qr');
  expect(api.acceptInvitation).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Code from the app'), { target: { value: '123456' } });
  await act(async () => { fireEvent.click(screen.getByText('Create Account')); });
  expect(api.acceptInvitation).toHaveBeenCalledWith('inv123', 'ada-l', 'Ada', PASSWORD, '123456');
  expect(screen.getByTestId('backup-codes')).toHaveTextContent('ABCDE-FGHJK');
  const carryOn = screen.getByText('Continue');
  expect(carryOn).toBeDisabled();
  fireEvent.click(screen.getByLabelText("I've saved these codes"));
  fireEvent.click(carryOn);
  expect(mockLogin).toHaveBeenCalledWith({ username: 'ada-l', role: 'admin' });
  expect(screen.getByText('jobs')).toBeInTheDocument();
});

test('a username that is taken is said, and the details stay', async () => {
  api.previewInvitation.mockResolvedValue(PREVIEW);
  api.startInvitation.mockRejectedValue({ response: { status: 400, data: { detail: 'The username alice is taken: choose another' } } });
  await visit();
  await details('alice');
  expect(screen.getByRole('alert')).toHaveTextContent('is taken');
  expect(screen.getByLabelText('Username')).toHaveValue('alice');
  expect(screen.queryByAltText('QR code for your authenticator app')).not.toBeInTheDocument();
});

test('a used or expired invitation says so and offers no form', async () => {
  api.previewInvitation.mockRejectedValue({ response: { status: 410, data: { detail: 'This invitation has expired: ask an administrator for a new one' } } });
  await visit();
  expect(screen.getByRole('alert')).toHaveTextContent('This invitation has expired');
  expect(screen.queryByLabelText('Username')).not.toBeInTheDocument();
});
