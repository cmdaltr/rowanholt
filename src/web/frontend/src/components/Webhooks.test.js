// The Webhooks page: why nothing is sent on Free, adding one and its secret shown once, the test
// delivery on Pro, deliveries listed, and admins only
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import Webhooks from './Webhooks';
import * as api from '../api';

jest.mock('../api', () => ({
  getWebhooks: jest.fn(),
  addWebhook: jest.fn(),
  editWebhook: jest.fn(),
  deleteWebhook: jest.fn(),
  testWebhook: jest.fn(),
}));

let mockUser = { role: 'admin' };
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser }) }));

const EVENTS = ['job.completed', 'job.failed', 'finding.confirmed', 'report.ready'];
const HOOK = {
  id: 'h1', url: 'https://soar.example.org/rowanholt', events: ['job.completed'], description: 'SOAR',
  enabled: true, has_secret: true, created: 1762855200, deliveries: [],
};
const FREE = {
  events: EVENTS, webhooks: [HOOK], sending: false,
  reason: "Webhooks are part of the Pro and Services editions; this is the Free edition. They're kept, and sent once a Pro or Services licence is installed.",
};

beforeEach(() => {
  jest.resetAllMocks();
  mockUser = { role: 'admin' };
});

test('on Free the webhook is listed, the page says why it is not sent, and no test can be sent', async () => {
  api.getWebhooks.mockResolvedValue(FREE);
  render(<Webhooks />);
  expect(await screen.findByText(HOOK.url)).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent(/part of the Pro and Services editions/);
  expect(screen.getByText('Send a test')).toBeDisabled();
});

test('adding a webhook shows its secret once', async () => {
  api.getWebhooks.mockResolvedValue({ ...FREE, webhooks: [] });
  api.addWebhook.mockResolvedValue({ ...HOOK, secret: 'shown-once' });
  render(<Webhooks />);
  fireEvent.change(await screen.findByLabelText('Webhook URL'), { target: { value: HOOK.url } });
  const add = screen.getByText('Add');
  expect(add).toBeDisabled(); // no events yet
  fireEvent.click(screen.getByLabelText(/report\.ready/));
  await act(async () => { fireEvent.click(add); });
  expect(api.addWebhook).toHaveBeenCalledWith({ url: HOOK.url, events: ['report.ready'], description: '' });
  expect(screen.getByTestId('webhook-secret')).toHaveTextContent('shown-once');
});

test('on Pro a test is sent and the deliveries are listed', async () => {
  const delivered = { event: 'job.completed', at: 1762855300, ok: true, status: 200, error: null, tries: 1 };
  api.getWebhooks
    .mockResolvedValueOnce({ ...FREE, sending: true, reason: '' })
    .mockResolvedValue({ ...FREE, sending: true, reason: '', webhooks: [{ ...HOOK, deliveries: [delivered] }] });
  api.testWebhook.mockResolvedValue(delivered);
  render(<Webhooks />);
  const test = await screen.findByText('Send a test');
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  await act(async () => { fireEvent.click(test); });
  expect(api.testWebhook).toHaveBeenCalledWith('h1');
  expect(await screen.findByText('HTTP 200')).toBeInTheDocument();
});

test('a refused URL says why', async () => {
  api.getWebhooks.mockResolvedValue({ ...FREE, webhooks: [] });
  api.addWebhook.mockRejectedValue({ response: { status: 422, data: { detail: 'The URL must be https://' } } });
  render(<Webhooks />);
  fireEvent.change(await screen.findByLabelText('Webhook URL'), { target: { value: 'http://example.org/h' } });
  fireEvent.click(screen.getByLabelText(/job\.failed/));
  await act(async () => { fireEvent.click(screen.getByText('Add')); });
  expect(screen.getByText('The URL must be https://')).toBeInTheDocument();
});

test('only admins manage webhooks; the local analyst is one', async () => {
  mockUser = { role: 'user' };
  const { unmount } = render(<Webhooks />);
  expect(screen.getByText(/managed by Rowanholt administrators/)).toBeInTheDocument();
  expect(api.getWebhooks).not.toHaveBeenCalled();
  unmount();

  mockUser = null;
  api.getWebhooks.mockResolvedValue(FREE);
  render(<Webhooks serverMode={false} />);
  expect(await screen.findByText(HOOK.url)).toBeInTheDocument();
});
