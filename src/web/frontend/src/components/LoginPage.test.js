// Sign-in's second step: a password that's right for an account with MFA asks for a code before
// anyone is signed in, a wrong code keeps the step, and an expired challenge goes back to the password
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import LoginPage from './LoginPage';
import * as api from '../api';

jest.mock('../api', () => ({
  login: jest.fn(),
  loginAsGuest: jest.fn(),
  getAuthConfig: jest.fn(),
  completeMfaSignIn: jest.fn(),
}));

const mockSetUser = jest.fn();
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ login: mockSetUser }) }));

const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockNavigate,
}));

const USER = { id: 'u1', username: 'alice', role: 'user' };

beforeEach(() => {
  jest.resetAllMocks();
  api.getAuthConfig.mockResolvedValue({ local_login: true, guest: false, register: false, sso: { enabled: false } });
});

const signIn = async () => {
  render(<MemoryRouter><LoginPage /></MemoryRouter>);
  fireEvent.change(screen.getByLabelText('Username or Email'), { target: { value: 'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'alice-password-123' } });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Sign In' })); });
};

test('without MFA the password signs in as before', async () => {
  api.login.mockResolvedValue({ access_token: 't', user: USER });
  await signIn();
  expect(mockSetUser).toHaveBeenCalledWith(USER);
  expect(mockNavigate).toHaveBeenCalledWith('/jobs');
});

test('with MFA the password step asks for a code, and only the code signs in', async () => {
  api.login.mockResolvedValue({ mfa_required: true, challenge: 'mfa_abc.def', expires_in: 300 });
  api.completeMfaSignIn.mockResolvedValue({ access_token: 't', user: USER });
  await signIn();
  expect(mockSetUser).not.toHaveBeenCalled();
  expect(screen.getByTestId('mfa-step')).toBeInTheDocument();
  expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } });
  await act(async () => { fireEvent.click(screen.getByText('Verify')); });
  expect(api.completeMfaSignIn).toHaveBeenCalledWith('mfa_abc.def', '123456');
  expect(mockSetUser).toHaveBeenCalledWith(USER);
  expect(mockNavigate).toHaveBeenCalledWith('/jobs');
});

test('a wrong code keeps the second step; an expired challenge goes back to the password', async () => {
  api.login.mockResolvedValue({ mfa_required: true, challenge: 'mfa_abc.def', expires_in: 300 });
  api.completeMfaSignIn.mockRejectedValueOnce({ response: { status: 401, data: { detail: 'Incorrect code' } } });
  await signIn();
  fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '000000' } });
  await act(async () => { fireEvent.click(screen.getByText('Verify')); });
  expect(screen.getByText('Incorrect code')).toBeInTheDocument();
  expect(screen.getByTestId('mfa-step')).toBeInTheDocument();
  api.completeMfaSignIn.mockRejectedValueOnce({ response: { status: 401, data: { detail: 'That sign-in has expired; start again' } } });
  fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '111111' } });
  await act(async () => { fireEvent.click(screen.getByText('Verify')); });
  expect(screen.getByText(/expired/)).toBeInTheDocument();
  expect(screen.queryByTestId('mfa-step')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Password')).toBeInTheDocument();
  expect(mockSetUser).not.toHaveBeenCalled();
});

test('a server that requires MFA sends someone without it to set it up', async () => {
  api.login.mockResolvedValue({ access_token: 't', user: USER, mfa_enrolment_required: true });
  await signIn();
  expect(mockNavigate).toHaveBeenCalledWith('/account', { state: { tab: 'security' } });
});
