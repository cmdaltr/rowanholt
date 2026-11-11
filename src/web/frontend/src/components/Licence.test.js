// The Licence page: check, read the terms, tick, install; the "accepted by" line; local mode; the grace notice
import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';  // no src/setupTests.js: this suite brings its own matchers
import Licence, { LicenceNotice } from './Licence';
import * as api from '../api';

jest.mock('../api', () => ({
  getLicence: jest.fn(),
  getLicenceTerms: jest.fn(),
  checkLicence: jest.fn(),
  installLicence: jest.fn(),
  removeLicence: jest.fn(),
}));

let mockUser = { role: 'admin' };
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser }) }));

const FREE = {
  edition: 'free', state: 'free', licensee: '', licence_id: '', seats: 4, free_seats: 4, features: [],
  places_held: 3, not_before: null, expires: null, grace_ends: null, terms_version: '1.0', accepted: null,
};
const INSTALLED = {
  ...FREE, edition: 'pro', state: 'active', licensee: 'Northwind Ltd', licence_id: 'lic_1', seats: 25,
  expires: '2027-11-30', accepted: { by: 'Ada Admin <ada@example.org>', at: '2026-11-11T10:00:00+00:00', terms_version: '1.0' },
};
const PREVIEW = {
  licence_id: 'lic_1', licensee: 'Northwind Ltd', edition: 'pro', seats: 25, features: [],
  not_before: null, expires: '2027-11-30', state: 'active',
};

beforeEach(() => {
  jest.resetAllMocks();
  mockUser = { role: 'admin' };
});

test('a licence installs only once the terms for its licensee are ticked, and says who accepted them', async () => {
  api.getLicence.mockResolvedValue(FREE);
  api.checkLicence.mockResolvedValue(PREVIEW);
  api.getLicenceTerms.mockResolvedValue({ version: '1.0', text: '# Rowanholt Commercial Licence\n\n**Version 1.0**' });
  api.installLicence.mockResolvedValue(INSTALLED);
  render(<Licence />);

  expect(await screen.findByText('Free edition')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Licence'), { target: { value: 'rowanholt-licence-1.a.b' } });
  fireEvent.click(screen.getByText('Check'));

  const tick = await screen.findByLabelText(
    /I accept the Rowanholt Commercial Licence, version 1\.0, on behalf of Northwind Ltd, and I have authority to do so/);
  expect(screen.getByText(/Rowanholt Commercial Licence, version 1\.0$/)).toBeInTheDocument();
  const install = screen.getByText('Install');
  expect(install).toBeDisabled();
  fireEvent.click(tick);
  expect(install).not.toBeDisabled();
  await act(async () => { fireEvent.click(install); });

  expect(api.installLicence).toHaveBeenCalledWith('rowanholt-licence-1.a.b', '1.0');
  expect(await screen.findByText('Pro edition')).toBeInTheDocument();
  expect(screen.getByText(/Commercial licence v1\.0 accepted by Ada Admin <ada@example\.org> on 11 November 2026/)).toBeInTheDocument();
});

test('when the terms changed since they were shown, the new version must be ticked again', async () => {
  api.getLicence.mockResolvedValue(FREE);
  api.checkLicence.mockResolvedValue(PREVIEW);
  api.getLicenceTerms
    .mockResolvedValueOnce({ version: '1.0', text: 'old' })  // shown when the licence is checked
    .mockResolvedValue({ version: '1.1', text: 'new' });  // fetched again after the 409
  api.installLicence.mockRejectedValue({ response: { status: 409, data: { detail: 'The commercial licence terms are now version 1.1. Read them, then accept again.' } } });
  render(<Licence />);
  await screen.findByText('Free edition');
  fireEvent.change(screen.getByLabelText('Licence'), { target: { value: 'line' } });
  fireEvent.click(screen.getByText('Check'));
  fireEvent.click(await screen.findByLabelText(/version 1\.0, on behalf of Northwind Ltd/));
  await act(async () => { fireEvent.click(screen.getByText('Install')); });

  expect(await screen.findByText(/now version 1\.1/)).toBeInTheDocument();
  const again = await screen.findByLabelText(/version 1\.1, on behalf of Northwind Ltd/);
  expect(again).not.toBeChecked();
  expect(screen.getByText('Install')).toBeDisabled();
});

test('local mode needs no licence and shows no terms', async () => {
  api.getLicence.mockRejectedValue({ response: { status: 404 } });
  render(<Licence />);
  expect(await screen.findByText(/Local mode is one analyst and needs no licence/)).toBeInTheDocument();
  expect(screen.queryByText('Check')).not.toBeInTheDocument();
});

test('only admins manage the licence', () => {
  mockUser = { role: 'user' };
  render(<Licence />);
  expect(screen.getByText(/managed by Rowanholt administrators/)).toBeInTheDocument();
  expect(api.getLicence).not.toHaveBeenCalled();
});

test('admins see a warning on every page during grace, and nothing otherwise', async () => {
  api.getLicence.mockResolvedValue({ ...INSTALLED, state: 'grace', expires: '2026-11-01', grace_ends: '2026-12-01' });
  const { unmount } = render(<LicenceNotice serverMode />);
  expect(await screen.findByRole('alert')).toHaveTextContent(/ran out on 1 November 2026 and stops on 1 December 2026/);
  unmount();

  api.getLicence.mockResolvedValue(INSTALLED);
  render(<LicenceNotice serverMode />);
  await waitFor(() => expect(api.getLicence).toHaveBeenCalledTimes(2));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test('the notice asks nothing in local mode', () => {
  render(<LicenceNotice serverMode={false} />);
  expect(api.getLicence).not.toHaveBeenCalled();
});
