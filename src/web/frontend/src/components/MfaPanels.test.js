// The Account page's MFA and Backup Codes panels: enrolment shows the QR code and turns MFA on only
// with a code, the backup codes are shown once, regenerating and disabling ask for a code, and single
// sign-on accounts and a local stack are told where their MFA is instead of being offered it
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import MfaPanels from './MfaPanels';
import * as api from '../api';

jest.mock('../api', () => ({
  getMfaStatus: jest.fn(),
  startMfaSetup: jest.fn(),
  enableMfa: jest.fn(),
  disableMfa: jest.fn(),
  regenerateBackupCodes: jest.fn(),
}));

const OFF = { available: true, required: false, enabled: false, backup_codes_left: 0, backup_codes_total: 10 };
const ON = { ...OFF, enabled: true, backup_codes_left: 10 };
const CODES = ['ABCDE-FGHJK', 'MNPQR-STUVW'];

beforeEach(() => jest.resetAllMocks());

test('enrolment shows the QR code and key, and MFA goes on only with a code', async () => {
  api.getMfaStatus.mockResolvedValueOnce(OFF).mockResolvedValue({ ...ON, backup_codes_left: 2 });
  api.startMfaSetup.mockResolvedValue({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', qr_svg: 'data:image/svg+xml,qr' });
  api.enableMfa.mockResolvedValue({ ...ON, backup_codes: CODES });
  render(<MfaPanels />);
  const enable = await screen.findByText('Enable MFA');
  await act(async () => { fireEvent.click(enable); });
  expect(screen.getByAltText('QR code for your authenticator app')).toHaveAttribute('src', 'data:image/svg+xml,qr');
  expect(screen.getByTestId('mfa-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP');
  const turnOn = screen.getByText('Turn on MFA');
  expect(turnOn).toBeDisabled();
  expect(api.enableMfa).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Code from the app'), { target: { value: '123456' } });
  await act(async () => { fireEvent.click(turnOn); });
  expect(api.enableMfa).toHaveBeenCalledWith('123456');
  expect(screen.getByTestId('backup-codes')).toHaveTextContent('ABCDE-FGHJK');
  expect(screen.getByText('Enabled')).toBeInTheDocument();
  // Shown once: dismissed, they're gone
  fireEvent.click(screen.getByText("I've saved them"));
  expect(screen.queryByTestId('backup-codes')).not.toBeInTheDocument();
});

test('a wrong code is said and MFA stays off', async () => {
  api.getMfaStatus.mockResolvedValue(OFF);
  api.startMfaSetup.mockResolvedValue({ secret: 'S', otpauth_uri: 'u', qr_svg: 'data:image/svg+xml,qr' });
  api.enableMfa.mockRejectedValue({ response: { data: { detail: 'Incorrect code: check the app\'s clock and try the next one' } } });
  render(<MfaPanels />);
  const enable = await screen.findByText('Enable MFA');
  await act(async () => { fireEvent.click(enable); });
  fireEvent.change(screen.getByLabelText('Code from the app'), { target: { value: '000000' } });
  await act(async () => { fireEvent.click(screen.getByText('Turn on MFA')); });
  expect(screen.getByRole('alert')).toHaveTextContent(/Incorrect code/);
  expect(screen.getByText('Disabled')).toBeInTheDocument();
});

test('the backup codes panel shows how many are left and makes new ones for a code', async () => {
  api.getMfaStatus.mockResolvedValueOnce({ ...ON, backup_codes_left: 3 }).mockResolvedValue(ON);
  api.regenerateBackupCodes.mockResolvedValue({ ...ON, backup_codes: CODES });
  render(<MfaPanels />);
  expect(await screen.findByTestId('backup-codes-left')).toHaveTextContent('3 / 10');
  fireEvent.click(screen.getByText('Generate'));
  fireEvent.change(screen.getByLabelText('Code from your app'), { target: { value: '654321' } });
  await act(async () => { fireEvent.click(screen.getByText('Make new codes')); });
  expect(api.regenerateBackupCodes).toHaveBeenCalledWith('654321');
  expect(screen.getByTestId('backup-codes')).toHaveTextContent('MNPQR-STUVW');
  expect(screen.getByTestId('backup-codes-left')).toHaveTextContent('10 / 10');
});

test('generating is off until MFA is on', async () => {
  api.getMfaStatus.mockResolvedValue(OFF);
  render(<MfaPanels />);
  expect(await screen.findByText('Generate')).toBeDisabled();
});

test('disabling asks for the password and a code', async () => {
  api.getMfaStatus.mockResolvedValueOnce(ON).mockResolvedValue(OFF);
  api.disableMfa.mockResolvedValue(OFF);
  render(<MfaPanels />);
  fireEvent.click(await screen.findByText('Disable MFA'));
  const off = screen.getByText('Turn off MFA');
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'my-password-123' } });
  expect(off).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Code'), { target: { value: 'ABCDE-FGHJK' } });
  await act(async () => { fireEvent.click(off); });
  expect(api.disableMfa).toHaveBeenCalledWith('my-password-123', 'ABCDE-FGHJK');
  expect(screen.getByText('Disabled')).toBeInTheDocument();
});

test('a new authenticator needs a current code before the QR code', async () => {
  api.getMfaStatus.mockResolvedValue(ON);
  api.startMfaSetup.mockResolvedValue({ secret: 'NEW', otpauth_uri: 'u', qr_svg: 'data:image/svg+xml,new' });
  render(<MfaPanels />);
  fireEvent.click(await screen.findByText('New authenticator'));
  fireEvent.change(screen.getByLabelText('Current code'), { target: { value: '111222' } });
  await act(async () => { fireEvent.click(screen.getByText('Continue')); });
  expect(api.startMfaSetup).toHaveBeenCalledWith('111222');
  expect(screen.getByText('Use this authenticator')).toBeInTheDocument();
});

test('a server that requires MFA says so and offers no way to turn it off', async () => {
  api.getMfaStatus.mockResolvedValue({ ...OFF, required: true });
  render(<MfaPanels />);
  expect(await screen.findByTestId('mfa-required')).toHaveTextContent('This server requires MFA');
});

test('with MFA required and on, Disable is not offered', async () => {
  api.getMfaStatus.mockResolvedValue({ ...ON, required: true });
  render(<MfaPanels />);
  expect(await screen.findByText('New authenticator')).toBeInTheDocument();
  expect(screen.queryByText('Disable MFA')).not.toBeInTheDocument();
});

test('a single sign-on account is told its MFA is the identity provider\'s, with nothing to enrol', async () => {
  api.getMfaStatus.mockResolvedValue({
    available: false, reason: 'sso',
    message: "This account signs in with single sign-on: its MFA is your identity provider's",
  });
  render(<MfaPanels />);
  expect(await screen.findByTestId('mfa-unavailable')).toHaveTextContent('identity provider');
  expect(screen.queryByText('Enable MFA')).not.toBeInTheDocument();
  expect(screen.queryByText('Generate')).not.toBeInTheDocument();
});

test('a local stack shows the panels with a line saying MFA is for a team server', async () => {
  api.getMfaStatus.mockResolvedValue({
    available: false, reason: 'local',
    message: "MFA applies to a team server's sign-in: on your own machine Rowanholt has no sign-in for it to protect",
  });
  render(<MfaPanels />);
  expect(await screen.findByTestId('mfa-unavailable')).toHaveTextContent("team server's sign-in");
  expect(screen.getByText('Backup Codes')).toBeInTheDocument();
  expect(screen.queryByText('Enable MFA')).not.toBeInTheDocument();
});
