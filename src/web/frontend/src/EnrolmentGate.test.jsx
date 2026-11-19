// ROWANHOLT_REQUIRE_MFA: an account that must set MFA up first sees only Account (and sign-in);
// once it's on, or for anyone else, every page opens as before
import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router';
import { EnrolmentGate } from './App';

let mockUser = null;
vi.mock('./context/AuthContext', () => ({
  AuthProvider: ({ children }) => children,
  useAuth: () => ({ user: mockUser }),
}));

const Account = () => <div>account:{useLocation().state?.tab || 'none'}</div>;

const visit = (path) => render(
  <MemoryRouter initialEntries={[path]}>
    <EnrolmentGate>
      <Routes>
        <Route path="/account" element={<Account />} />
        <Route path="/login" element={<div>login</div>} />
        <Route path="/gandalf" element={<div>custodian</div>} />
        <Route path="/ai" element={<div>smith</div>} />
      </Routes>
    </EnrolmentGate>
  </MemoryRouter>,
);

test.each(['/gandalf', '/ai'])('MFA to set up: %s goes to Account, on Security', (path) => {
  mockUser = { username: 'alice', mfa_enrolment_required: true };
  visit(path);
  expect(screen.getByText('account:security')).toBeInTheDocument();
});

test('MFA to set up: Account and sign-in still open', () => {
  mockUser = { username: 'alice', mfa_enrolment_required: true };
  visit('/login');
  expect(screen.getByText('login')).toBeInTheDocument();
});

test.each([null, { username: 'alice' }, { username: 'alice', mfa_enrolment_required: false }])(
  'nothing to set up (%o): pages open', (user) => {
    mockUser = user;
    visit('/gandalf');
    expect(screen.getByText('custodian')).toBeInTheDocument();
  },
);
