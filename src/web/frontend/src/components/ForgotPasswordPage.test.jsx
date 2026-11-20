// Forgot password: with email set up, the address goes to the API and the page says a link is on its
// way, whatever the answer was about; without email it says to ask an administrator, with the command
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router';
import ForgotPasswordPage from './ForgotPasswordPage';
import * as api from '../api';

vi.mock('../api', () => ({
  getAuthConfig: vi.fn(),
  requestResetLink: vi.fn(),
}));
vi.mock('./Home', () => ({ JOURNEYS: [{ image: '/x.webp', name: 'X', role: 'Y', drop: '0' }] }));

const open = async (config) => {
  api.getAuthConfig.mockResolvedValue(config);
  await act(async () => { render(<MemoryRouter><ForgotPasswordPage /></MemoryRouter>); });
};

beforeEach(() => vi.resetAllMocks());

test('with email, the address is sent and the page says a link is on its way', async () => {
  api.requestResetLink.mockResolvedValue({ message: 'If that address has an account, a link is on its way' });
  await open({ server_mode: true, forgot_password: true });
  fireEvent.change(screen.getByLabelText('Email or Username'), { target: { value: ' alice@example.org ' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Email Me a Link' })); });
  expect(api.requestResetLink).toHaveBeenCalledWith('alice@example.org');
  expect(screen.getByTestId('link-sent')).toHaveTextContent('If that address has an account, a link is on its way');
  expect(screen.queryByTestId('link-form')).not.toBeInTheDocument();
  // The emailed link is the only way offered: no backup-code form
  expect(screen.queryByTestId('reset-form')).not.toBeInTheDocument();
});

test('a refusal (too many requests) is shown and the form stays', async () => {
  api.requestResetLink.mockRejectedValue({ response: { status: 429, data: { detail: 'Too many requests for a link' } } });
  await open({ server_mode: false, forgot_password: true });
  fireEvent.change(screen.getByLabelText('Email or Username'), { target: { value: 'alice' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Email Me a Link' })); });
  expect(screen.getByText('Too many requests for a link')).toBeInTheDocument();
  expect(screen.getByTestId('link-form')).toBeInTheDocument();
});

test('without email, a server says to ask an administrator for a reset link', async () => {
  await open({ server_mode: true, forgot_password: false });
  expect(screen.getByTestId('ask-admin')).toHaveTextContent('rowanholt server users reset-access');
  expect(screen.queryByTestId('link-form')).not.toBeInTheDocument();
});

test('without email, a local stack gives the command for its own container, never a password command', async () => {
  await open({ server_mode: false, forgot_password: false });
  expect(screen.getByTestId('ask-admin')).toHaveTextContent('manage_users reset-access');
  expect(screen.queryByText(/manage_users password/)).not.toBeInTheDocument();
  expect(screen.queryByTestId('reset-form')).not.toBeInTheDocument();
});
