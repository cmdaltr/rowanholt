// Pair with Ostraka: a link made and shown once with Copy, open codes listed and withdrawn, claimed ones
// listed apart, and what /pair says
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PairOstraka, { PairPage } from './PairOstraka';
import * as api from '../api';

vi.mock('../api', () => ({
  getPairingCodes: vi.fn(),
  makePairingLink: vi.fn(),
  withdrawPairingCode: vi.fn(),
}));

const soon = () => new Date(Date.now() + 10 * 60 * 1000).toISOString();
const OPEN = {
  id: 'p1', note: 'Ostraka on the homelab', created_by: 'admin', created_at: new Date().toISOString(),
  expires_at: soon(), claimed_at: null, claimed_by_name: null,
};
const CLAIMED = { ...OPEN, id: 'p2', note: 'Old one', claimed_at: new Date().toISOString(), claimed_by_name: 'Ostraka' };
const EXPIRED = { ...OPEN, id: 'p3', note: 'Expired one', expires_at: new Date(Date.now() - 1000).toISOString() };
const LINK = 'https://rowanholt.example.org/pair#pair_abc';

beforeEach(() => {
  vi.resetAllMocks();
});

test('making a link shows it once with a copy button', async () => {
  api.getPairingCodes.mockResolvedValue([]);
  api.makePairingLink.mockResolvedValue({ id: 'p1', link: LINK, expires_at: soon() });
  const writeText = vi.fn().mockResolvedValue();
  Object.assign(navigator, { clipboard: { writeText } });
  render(<PairOstraka />);
  fireEvent.change(screen.getByLabelText('Pairing note'), { target: { value: ' Homelab ' } });
  await act(async () => { fireEvent.click(screen.getByText('Make a pairing link')); });
  expect(api.makePairingLink).toHaveBeenCalledWith('Homelab');
  expect(screen.getByTestId('pairing-link')).toHaveTextContent(LINK);
  await act(async () => { fireEvent.click(screen.getByText('Copy')); });
  expect(writeText).toHaveBeenCalledWith(LINK);
  expect(screen.getByRole('status')).toHaveTextContent('Copied.');
  fireEvent.click(screen.getByText('Done'));
  expect(screen.queryByTestId('pairing-link')).not.toBeInTheDocument();
});

test('open codes are listed and can be withdrawn; claimed ones are listed apart; expired ones not at all', async () => {
  api.getPairingCodes.mockResolvedValueOnce([OPEN, CLAIMED, EXPIRED]).mockResolvedValue([CLAIMED]);
  api.withdrawPairingCode.mockResolvedValue();
  render(<PairOstraka />);
  expect(await screen.findByTestId('pairing-p1')).toHaveTextContent('Ostraka on the homelab');
  expect(screen.getByText('Old one')).toBeInTheDocument();
  expect(screen.queryByText('Expired one')).not.toBeInTheDocument();
  await act(async () => { fireEvent.click(screen.getByText('Withdraw')); });
  expect(api.withdrawPairingCode).toHaveBeenCalledWith('p1');
  expect(screen.queryByTestId('pairing-p1')).not.toBeInTheDocument();
});

test('a refusal says why', async () => {
  api.getPairingCodes.mockResolvedValue([]);
  api.makePairingLink.mockRejectedValue({ response: { status: 403, data: { detail: 'Admin privileges required' } } });
  render(<PairOstraka />);
  await act(async () => { fireEvent.click(screen.getByText('Make a pairing link')); });
  expect(screen.getByText('Admin privileges required')).toBeInTheDocument();
});

test('/pair says the link is for Ostraka', () => {
  render(<PairPage />);
  expect(screen.getByText(/paste the whole link into Ostraka/)).toBeInTheDocument();
});
