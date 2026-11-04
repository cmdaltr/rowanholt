# Elrond Web Application - Test Suite

> **Legacy.** This describes the standalone Elrond stack in `src/analysis/web` and `src/analysis/docker` (ports 3000 and 8000), which Rowanholt no longer uses. Rowanholt runs from the repository's `docker-compose.yml` (web UI on :5687, API on :5688): start with [docs/QUICKSTART.md](../../../../docs/QUICKSTART.md) and the `rowanholt` command.

Comprehensive Playwright test suite for the Elrond Web Interface.

## 📋 Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Getting Started](#getting-started)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Writing Tests](#writing-tests)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

This test suite provides comprehensive end-to-end and API testing for the Elrond Web Application using Playwright. The tests cover:

- **UI/UX Testing**: User interface components and interactions
- **E2E Testing**: Complete user workflows from start to finish
- **API Testing**: Backend REST API endpoints
- **Cross-browser Testing**: Chrome, Firefox, Safari
- **Responsive Testing**: Desktop and mobile viewports
- **Accessibility Testing**: Keyboard navigation and ARIA labels

## Test Structure

```
tests/
├── playwright.config.js        # Playwright configuration
├── package.json               # Test dependencies
├── fixtures/                  # Test data and mocks
│   ├── test-data.js          # Mock data and constants
│   └── mock-api.js           # API mocking utilities
├── e2e/                      # End-to-end tests
│   ├── navigation.spec.js    # Navigation and layout
│   ├── file-browser.spec.js  # File browser component
│   ├── options-panel.spec.js # Options panel component
│   ├── new-analysis.spec.js  # New analysis workflow
│   ├── job-list.spec.js      # Job list and monitoring
│   └── job-details.spec.js   # Job details page
└── api/                      # API integration tests
    └── backend-api.spec.js   # Backend API endpoints
```

## Getting Started

### Prerequisites

- Node.js 18 or later
- npm or yarn
- Elrond web application running (frontend + backend)

### Installation

1. **Navigate to tests directory**:
   ```bash
   cd elrond/web/tests
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Install Playwright browsers**:
   ```bash
   npm run install
   ```

   Or directly:
   ```bash
   npx playwright install --with-deps
   ```

## Running Tests

### Quick Start

```bash
# Run all tests
npm test

# Run with UI mode (recommended for development)
npm run test:ui

# Run in headed mode (see browser)
npm run test:headed

# Run in debug mode
npm run test:debug
```

### Specific Test Suites

```bash
# Run only E2E tests
npm run test:e2e

# Run only API tests
npm run test:api

# Run specific test file
npx playwright test e2e/navigation.spec.js

# Run tests matching pattern
npx playwright test --grep "File Browser"
```

### Browser-Specific Tests

```bash
# Run in Chrome only
npm run test:chromium

# Run in Firefox only
npm run test:firefox

# Run in Safari only
npm run test:webkit

# Run mobile tests
npm run test:mobile
```

### Test Reports

```bash
# View HTML report
npm run report

# Generate and open report
npx playwright show-report test-results/html
```

## Test Coverage

### E2E Tests (150+ test cases)

#### Navigation Tests (12 tests)
- ✅ Application header and title
- ✅ Navigation links
- ✅ Page routing
- ✅ Footer display
- ✅ Dark theme styling
- ✅ Responsive design

#### File Browser Tests (25 tests)
- ✅ File and directory listing
- ✅ File icons and badges
- ✅ Directory navigation
- ✅ File selection (single/multiple)
- ✅ Disk image identification
- ✅ File size and date formatting
- ✅ Error handling
- ✅ Accessibility

#### Options Panel Tests (30 tests)
- ✅ Section tabs and switching
- ✅ Checkbox interactions
- ✅ Enable/Disable all buttons
- ✅ Option persistence
- ✅ All 30+ Elrond options
- ✅ Responsive design
- ✅ Accessibility

#### New Analysis Workflow Tests (30 tests)
- ✅ Form validation
- ✅ Case number input
- ✅ Image selection
- ✅ Option configuration
- ✅ Form submission
- ✅ Error handling
- ✅ Loading states
- ✅ Success navigation

#### Job List Tests (25 tests)
- ✅ Job table display
- ✅ Status badges
- ✅ Progress bars
- ✅ Filtering by status
- ✅ Auto-refresh (5s)
- ✅ Navigation to details
- ✅ Empty state
- ✅ Responsive design

#### Job Details Tests (28 tests)
- ✅ Job information display
- ✅ Real-time progress updates
- ✅ Log viewer
- ✅ Status tracking
- ✅ Cancel job action
- ✅ Delete job action
- ✅ Auto-refresh (3s)
- ✅ Error display
- ✅ Results display

### API Tests (40+ test cases)

- ✅ Health check endpoint
- ✅ File system browsing
- ✅ Job creation
- ✅ Job listing and filtering
- ✅ Job updates
- ✅ Job cancellation
- ✅ Job deletion
- ✅ Error handling
- ✅ CORS headers
- ✅ Performance benchmarks

## Writing Tests

### Test Structure

```javascript
const { test, expect } = require('@playwright/test');

test.describe('Feature Name', () => {
  test.beforeEach(async ({ page }) => {
    // Setup before each test
    await page.goto('/');
  });

  test('should do something', async ({ page }) => {
    // Test implementation
    await expect(page.locator('.selector')).toBeVisible();
  });
});
```

### Using Mock API

```javascript
const { setupMockAPI } = require('../fixtures/mock-api.js');

test.beforeEach(async ({ page }) => {
  await setupMockAPI(page);
  await page.goto('/');
});
```

### Common Patterns

#### Waiting for Elements
```javascript
await page.waitForSelector('.element');
await expect(page.locator('.element')).toBeVisible();
```

#### Clicking Elements
```javascript
await page.click('text=Button');
await page.locator('button', { hasText: 'Submit' }).click();
```

#### Filling Forms
```javascript
await page.fill('input[id="caseNumber"]', 'INC-2025-001');
await page.check('input[id="collect"]');
```

#### URL Navigation
```javascript
await page.goto('/jobs');
await expect(page).toHaveURL('/jobs');
```

#### Mocking API Responses
```javascript
await page.route('**/api/jobs', async (route) => {
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ jobs: [], total: 0 }),
  });
});
```

### Best Practices

1. **Use data-testid for stable selectors**:
   ```html
   <button data-testid="submit-button">Submit</button>
   ```
   ```javascript
   await page.click('[data-testid="submit-button"]');
   ```

2. **Wait for network to be idle**:
   ```javascript
   await page.goto('/', { waitUntil: 'networkidle' });
   ```

3. **Use explicit waits**:
   ```javascript
   await page.waitForTimeout(1000); // Last resort
   await page.waitForSelector('.element'); // Better
   await expect(page.locator('.element')).toBeVisible(); // Best
   ```

4. **Test user workflows, not implementation**:
   ```javascript
   // ❌ Bad - tests implementation
   await page.click('#submit-btn-123');

   // ✅ Good - tests user behavior
   await page.click('button:has-text("Start Analysis")');
   ```

5. **Use descriptive test names**:
   ```javascript
   // ❌ Bad
   test('test 1', async ({ page }) => { ... });

   // ✅ Good
   test('should validate case number is required', async ({ page }) => { ... });
   ```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Playwright Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: 18

      - name: Install dependencies
        run: |
          cd web/tests
          npm ci

      - name: Install Playwright browsers
        run: npx playwright install --with-deps

      - name: Run tests
        run: npm test
        env:
          CI: true

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: playwright-report
          path: web/tests/test-results/
```

### Docker Integration

```bash
# Run tests in Docker
docker run -it --rm \
  -v $(pwd):/work \
  -w /work/tests \
  mcr.microsoft.com/playwright:v1.40.0-focal \
  npm test
```

## Troubleshooting

### Common Issues

#### Tests Timing Out

**Problem**: Tests fail with timeout errors

**Solution**:
```javascript
// Increase timeout for specific test
test('slow test', async ({ page }) => {
  test.setTimeout(60000); // 60 seconds
  // ...
});
```

Or in config:
```javascript
// playwright.config.js
timeout: 60 * 1000,
```

#### Backend Not Running

**Problem**: API tests fail because backend isn't accessible

**Solution**:
```bash
# Ensure backend is running
cd ../backend
uvicorn main:app --port 8000

# Or use docker-compose
cd ..
docker-compose up -d
```

#### Browser Not Installed

**Problem**: `Error: browserType.launch: Executable doesn't exist`

**Solution**:
```bash
npx playwright install
# Or with system dependencies
npx playwright install --with-deps
```

#### Flaky Tests

**Problem**: Tests pass sometimes and fail other times

**Solutions**:
1. Add explicit waits:
   ```javascript
   await page.waitForLoadState('networkidle');
   ```

2. Retry flaky tests:
   ```javascript
   // playwright.config.js
   retries: 2,
   ```

3. Use auto-waiting:
   ```javascript
   await expect(page.locator('.element')).toBeVisible();
   ```

#### Port Already in Use

**Problem**: `Port 3000 is already in use`

**Solution**:
```bash
# Kill process on port
lsof -ti:3000 | xargs kill -9

# Or use different port
BASE_URL=http://localhost:3001 npm test
```

### Debug Mode

```bash
# Run single test in debug mode
npx playwright test e2e/navigation.spec.js --debug

# Debug specific test
npx playwright test --debug --grep "should display header"

# Use UI mode for visual debugging
npx playwright test --ui
```

### Screenshots and Videos

Tests automatically capture:
- **Screenshots**: On failure
- **Videos**: On failure
- **Traces**: On first retry

Located in `test-results/` directory.

View trace:
```bash
npx playwright show-trace test-results/trace.zip
```

## Test Metrics

### Current Coverage

- **Total Tests**: 190+
- **E2E Tests**: 150+
- **API Tests**: 40+
- **Test Files**: 7
- **Average Execution Time**: ~3-5 minutes (all tests)

### Performance Targets

- Health check: < 1s
- Job list load: < 3s
- Page navigation: < 2s
- Form submission: < 5s

## Contributing

### Adding New Tests

1. Create test file in appropriate directory
2. Follow naming convention: `feature-name.spec.js`
3. Include test description and use cases
4. Add mock data to `fixtures/test-data.js` if needed
5. Update this README with new test coverage

### Test Checklist

- [ ] Test has descriptive name
- [ ] Test is independent (no dependency on other tests)
- [ ] Test cleans up after itself
- [ ] Test uses mock API when appropriate
- [ ] Test handles both success and error cases
- [ ] Test is documented

## Additional Resources

- [Playwright Documentation](https://playwright.dev)
- [Best Practices Guide](https://playwright.dev/docs/best-practices)
- [Debugging Guide](https://playwright.dev/docs/debug)
- [CI Guide](https://playwright.dev/docs/ci)

## Support

For issues or questions:
- Check [Playwright Docs](https://playwright.dev)
- Review existing test examples
- Open an issue on GitHub

---

**Last Updated**: 2025-01-15
**Playwright Version**: 1.40.0
**Node Version**: 18+
