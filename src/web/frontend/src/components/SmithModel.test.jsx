// Steward's Smith tab: a saved API key kept back and kept unless replaced or removed, and a refused
// endpoint's reason shown
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import SmithModel from './SmithModel';
import * as api from '../api';

vi.mock('../api', () => ({
  getSmithModel: vi.fn(),
  testSmithModel: vi.fn(),
  saveSmithModel: vi.fn(),
  resetSmithModel: vi.fn(),
}));

const SAVED = { provider: 'openai', url: 'http://10.0.0.5:1234', model: 'qwen3-8b', has_api_key: true, saved: true, public_allowed: false };

test('a saved key is kept unless replaced or removed', async () => {
  api.getSmithModel.mockResolvedValue(SAVED);
  api.saveSmithModel.mockResolvedValue(SAVED);
  render(<SmithModel />);
  expect(await screen.findByDisplayValue('http://10.0.0.5:1234')).toBeInTheDocument();
  expect(screen.getByPlaceholderText('Saved: leave empty to keep it')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Save'));
  await waitFor(() => expect(api.saveSmithModel).toHaveBeenCalledWith(
    { provider: 'openai', url: 'http://10.0.0.5:1234', model: 'qwen3-8b', api_key: null }));
  await screen.findByText(/^Saved:/);
  fireEvent.click(screen.getByLabelText(/Remove the saved key/));
  fireEvent.click(screen.getByText('Save'));
  await waitFor(() => expect(api.saveSmithModel).toHaveBeenLastCalledWith(expect.objectContaining({ api_key: '' })));
});

test('a refused endpoint says why', async () => {
  api.getSmithModel.mockResolvedValue({ ...SAVED, has_api_key: false, saved: false, provider: 'ollama' });
  api.testSmithModel.mockResolvedValue({ ok: false, refused: true, models: [],
    reason: "llm.example.org resolves to 104.18.32.7, which isn't a private address." });
  render(<SmithModel />);
  fireEvent.click(await screen.findByText('Test'));
  expect(await screen.findByRole('status')).toHaveTextContent("isn't a private address");
  expect(screen.queryByLabelText('API key')).not.toBeInTheDocument();
});
