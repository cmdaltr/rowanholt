// The Branding page: what the licence does with brands, adding one, choosing the installation's,
// a logo upload, the derived-colour notes, and admins only
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import Branding from './Branding';
import * as api from '../api';

jest.mock('../api', () => ({
  getBrands: jest.fn(),
  addBrand: jest.fn(),
  editBrand: jest.fn(),
  deleteBrand: jest.fn(),
  chooseInstallationBrand: jest.fn(),
  uploadBrandLogo: jest.fn(),
  clearBrandLogo: jest.fn(),
  getBrandLogo: jest.fn(),
}));

let mockUser = { role: 'admin' };
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser }) }));

const HOUSE = {
  id: 'b1', name: 'House', primary: '#ffcc00', secondary: '', prepared_for: '', updated: 1,
  logos: { cover: false, header: false, client: false },
  notes: ['The primary colour is too light for headings on white, so they use a darker shade.'],
};
const FREE = {
  brands: [HOUSE], installation: null, cases: {}, report_branding: false, brand_library: false,
  says: "This is the Free edition: reports are in Rowanholt's own style. Brands saved here are kept, and used once a Pro or Services licence is installed.",
};

beforeEach(() => {
  jest.resetAllMocks();
  mockUser = { role: 'admin' };
});

test('on Free the page says reports are in Rowanholt style, and shows the colour notes', async () => {
  api.getBrands.mockResolvedValue(FREE);
  render(<Branding />);
  expect(await screen.findByRole('status')).toHaveTextContent(/Rowanholt's own style/);
  expect(screen.getByText(/too light for headings/)).toBeInTheDocument();
});

test('a brand is added and chosen for the installation', async () => {
  api.getBrands.mockResolvedValueOnce({ ...FREE, brands: [] }).mockResolvedValue(FREE); // reloaded after the add
  api.addBrand.mockResolvedValue(HOUSE);
  api.chooseInstallationBrand.mockResolvedValue({ ...FREE, installation: 'b1', report_branding: true, says: 'Reports use the installation\'s brand.' });
  render(<Branding />);
  fireEvent.change(await screen.findByLabelText('New brand name'), { target: { value: 'House' } });
  await act(async () => { fireEvent.click(screen.getByText('Add')); });
  expect(api.addBrand).toHaveBeenCalledWith({ name: 'House', primary: '#1f3a5f' });

  expect(await screen.findByTestId('brand-b1')).toBeInTheDocument();
  await act(async () => {
    fireEvent.change(screen.getByLabelText("The installation's brand"), { target: { value: 'b1' } });
  });
  expect(api.chooseInstallationBrand).toHaveBeenCalledWith('b1');
  expect(screen.getByRole('status')).toHaveTextContent(/installation's brand/);
});

test('a logo is uploaded to its slot and a refusal says why', async () => {
  api.getBrands.mockResolvedValue(FREE);
  api.uploadBrandLogo.mockRejectedValue({ response: { status: 422, data: { detail: 'Logos must be PNG or JPEG.' } } });
  render(<Branding />);
  const input = await screen.findByLabelText('House Cover logo');
  const file = new File(['<svg/>'], 'logo.svg', { type: 'image/svg+xml' });
  await act(async () => { fireEvent.change(input, { target: { files: [file] } }); });
  expect(api.uploadBrandLogo).toHaveBeenCalledWith('b1', 'cover', file);
  expect(screen.getByText('Logos must be PNG or JPEG.')).toBeInTheDocument();
});

test('only admins manage brands', () => {
  mockUser = { role: 'user' };
  render(<Branding />);
  expect(screen.getByText(/managed by Rowanholt administrators/)).toBeInTheDocument();
  expect(api.getBrands).not.toHaveBeenCalled();
});
