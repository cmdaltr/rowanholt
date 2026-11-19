// An admin's reset link: the password first, then the new authenticator's QR code and key, and only a
// code from it finishes the reset; the new backup codes are shown once, and Continue waits for the
// tickbox. A link that's used, expired or cut short says so and offers nothing to fill in
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

const ENROLMENT = { username: 'alice', secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', qr_svg: 'data:image/svg+xml,qr' };
const CODES = ['ABCDE-FGHJK', 'MNPQR-STUVW'];
const PASSWORD = 'a-brand-new-password-2';

const visit = async (path) => {
  await act(async () => {
    render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/reset-access" element={<ResetAccessPage />} />
          <Route path="/jobs" element={<div>jobs</div>} />
        </Routes>
      </MemoryRouter>,
    );
  });
};

const choosePassword = (password = PASSWORD, confirm = PASSWORD) => {
  fireEvent.change(screen.getByLabelText('New Password'), { target: { value: password } });
  fireEvent.change(screen.getByLabelText('Confirm New Password'), { target: { value: confirm } });
  fireEvent.click(screen.getByText('Continue'));
};

beforeEach(() => vi.resetAllMocks());

test('password, then the authenticator, then the backup codes once, and into the app', async () => {
  api.startAccessReset.mockResolvedValue(ENROLMENT);
  api.completeAccessReset.mockResolvedValue({ access_token: 't', user: { username: 'alice', mfa_enabled: true }, backup_codes: CODES });
  await visit('/reset-access#tok123');
  expect(api.startAccessReset).toHaveBeenCalledWith('tok123');
  expect(screen.getByTestId('reset-access-username')).toHaveTextContent('alice');
  choosePassword();
  expect(screen.getByAltText('QR code for your authenticator app')).toHaveAttribute('src', 'data:image/svg+xml,qr');
  expect(screen.getByTestId('mfa-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP');
  const submit = screen.getByText('Reset Access', { selector: 'button' });
  expect(submit).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Code from the app'), { target: { value: '123456' } });
  await act(async () => { fireEvent.click(submit); });
  expect(api.completeAccessReset).toHaveBeenCalledWith('tok123', PASSWORD, '123456');
  expect(screen.getByTestId('backup-codes')).toHaveTextContent('ABCDE-FGHJK');
  expect(screen.getByText('Copy codes')).toBeInTheDocument();
  const carryOn = screen.getByText('Continue');
  expect(carryOn).toBeDisabled();
  fireEvent.click(screen.getByLabelText("I've saved these codes"));
  fireEvent.click(carryOn);
  expect(mockLogin).toHaveBeenCalledWith({ username: 'alice', mfa_enabled: true });
  expect(screen.getByText('jobs')).toBeInTheDocument();
});

test('passwords that differ or are short go no further', async () => {
  api.startAccessReset.mockResolvedValue(ENROLMENT);
  await visit('/reset-access#tok123');
  choosePassword(PASSWORD, 'something-else-entirely');
  expect(screen.getByRole('alert')).toHaveTextContent("The passwords don't match");
  choosePassword('short', 'short');
  expect(screen.getByRole('alert')).toHaveTextContent('at least 12 characters');
  expect(screen.queryByAltText('QR code for your authenticator app')).not.toBeInTheDocument();
});

test('a wrong code is said, and the codes are not shown', async () => {
  api.startAccessReset.mockResolvedValue(ENROLMENT);
  api.completeAccessReset.mockRejectedValue({ response: { status: 400, data: { detail: 'Incorrect code: check the app\'s clock and try the next one' } } });
  await visit('/reset-access#tok123');
  choosePassword();
  fireEvent.change(screen.getByLabelText('Code from the app'), { target: { value: '000000' } });
  await act(async () => { fireEvent.click(screen.getByText('Reset Access', { selector: 'button' })); });
  expect(screen.getByRole('alert')).toHaveTextContent(/Incorrect code/);
  expect(screen.queryByTestId('backup-codes')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Code from the app')).toHaveValue('');
});

test('a used or expired link says so and offers no form', async () => {
  api.startAccessReset.mockRejectedValue({ response: { status: 410, data: { detail: 'This link has expired: ask an administrator for a new one' } } });
  await visit('/reset-access#old');
  expect(screen.getByRole('alert')).toHaveTextContent('This link has expired');
  expect(screen.queryByLabelText('New Password')).not.toBeInTheDocument();
});

test('a link without its token says so without asking the server', async () => {
  await visit('/reset-access');
  expect(api.startAccessReset).not.toHaveBeenCalled();
  expect(screen.getByRole('alert')).toHaveTextContent('This link is incomplete');
});
