# Ledger Testing Guide

Comprehensive testing documentation for the Ledger digital forensics automation tool.

## Overview

Ledger has two complementary test suites:

1. **Python Backend Tests** - Unit and integration tests for the core forensics engine
2. **Web Application Tests** - End-to-end and API tests for the web interface

Both test suites work together to provide comprehensive coverage of the entire application.

## Quick Start

### Python Tests

```bash
# Install test dependencies
cd tests
pip install -r requirements.txt

# Run all Python tests
pytest

# Run with coverage
pytest --cov=elrond --cov-report=html

# Or use the convenience script
./run_tests.sh --all --coverage
```

### Web Tests

```bash
# Install test dependencies
cd web/tests
npm install
npx playwright install --with-deps

# Run all web tests
npm test

# Run with UI mode (recommended)
npm run test:ui

# Run specific test suite
npm run test:e2e
npm run test:api
```

## Test Coverage

### Python Backend Tests (100+ tests)

#### Core Engine Tests (20+ tests)
- ✅ Engine initialization and configuration
- ✅ Permission checking (sudo/root/admin)
- ✅ Dependency verification
- ✅ Image identification and mounting
- ✅ Unmounting and cleanup
- ✅ Context manager support
- ✅ Legacy bridge compatibility

#### Platform Adapter Tests (25+ tests)
- ✅ Linux platform adapter
- ✅ macOS platform adapter
- ✅ Windows platform adapter
- ✅ Image type identification (E01, RAW, VMDK, VHD, memory dumps)
- ✅ Mount/unmount operations
- ✅ Permission checks per platform
- ✅ Platform factory pattern

#### Tool Manager Tests (15+ tests)
- ✅ Tool verification and detection
- ✅ Dependency checking
- ✅ Installation suggestions
- ✅ Tool categorization
- ✅ Missing tool detection
- ✅ Platform-specific tool support

#### Utility Helper Tests (25+ tests)
- ✅ Time calculations and formatting
- ✅ File size formatting
- ✅ Path validation
- ✅ Directory structure creation
- ✅ Case ID sanitization
- ✅ Mount point generation
- ✅ User interaction prompts

#### Web API Tests (30+ tests)
- ✅ Health check endpoints
- ✅ File system browsing API
- ✅ Job creation and validation
- ✅ Job listing and pagination
- ✅ Job status filtering
- ✅ Job updates and progress tracking
- ✅ Job cancellation
- ✅ Job deletion
- ✅ CORS headers
- ✅ Performance benchmarks

#### Storage Tests (15+ tests)
- ✅ Job saving and retrieval
- ✅ Job listing with pagination
- ✅ Status filtering
- ✅ Job counting
- ✅ Job deletion
- ✅ Invalid file handling
- ✅ Ordering by modification time

#### Task Tests (20+ tests)
- ✅ Command building with various options
- ✅ Successful analysis execution
- ✅ Failed analysis handling
- ✅ Exception handling
- ✅ Log updates
- ✅ Progress tracking
- ✅ Output directory creation

### Web Application Tests (190+ tests)

#### Navigation Tests (12 tests)
- ✅ Application header and branding
- ✅ Navigation links and routing
- ✅ Footer display
- ✅ Dark theme styling
- ✅ Responsive design

#### File Browser Tests (25 tests)
- ✅ Directory listing and navigation
- ✅ File selection (single/multiple)
- ✅ Disk image identification
- ✅ File metadata display
- ✅ Error handling
- ✅ Accessibility features

#### Options Panel Tests (30 tests)
- ✅ All 30+ Ledger options
- ✅ Section tabs and switching
- ✅ Checkbox interactions
- ✅ Enable/disable all buttons
- ✅ Option persistence

#### New Analysis Workflow Tests (30 tests)
- ✅ Form validation
- ✅ Case number input
- ✅ Source selection
- ✅ Option configuration
- ✅ Form submission
- ✅ Error handling

#### Job List Tests (25 tests)
- ✅ Job table display
- ✅ Status badges and progress bars
- ✅ Filtering by status
- ✅ Auto-refresh functionality
- ✅ Navigation to details

#### Job Details Tests (28 tests)
- ✅ Job information display
- ✅ Real-time progress updates
- ✅ Log viewer
- ✅ Cancel/delete actions
- ✅ Results display

#### API Integration Tests (40 tests)
- ✅ All REST API endpoints
- ✅ Error handling
- ✅ CORS validation
- ✅ Performance benchmarks

## Test Organization

```
elrond/
├── tests/                      # Python backend tests
│   ├── conftest.py            # Shared fixtures
│   ├── pytest.ini             # Pytest configuration
│   ├── requirements.txt       # Test dependencies
│   ├── README.md              # Python test documentation
│   ├── run_tests.sh          # Test runner script
│   ├── unit/                 # Unit tests
│   │   ├── test_engine.py
│   │   ├── test_platform.py
│   │   ├── test_tool_manager.py
│   │   ├── test_storage.py
│   │   ├── test_tasks.py
│   │   └── test_helpers.py
│   └── integration/          # Integration tests
│       └── test_web_api.py
│
└── web/tests/                 # Web application tests
    ├── playwright.config.js   # Playwright configuration
    ├── package.json          # Test dependencies
    ├── README.md             # Web test documentation
    ├── fixtures/             # Test data and mocks
    │   ├── test-data.js
    │   └── mock-api.js
    ├── e2e/                  # End-to-end tests
    │   ├── navigation.spec.js
    │   ├── file-browser.spec.js
    │   ├── options-panel.spec.js
    │   ├── new-analysis.spec.js
    │   ├── job-list.spec.js
    │   └── job-details.spec.js
    └── api/                  # API integration tests
        └── backend-api.spec.js
```

## Running Tests in CI/CD

### GitHub Actions Example

```yaml
name: Elrond Tests

on: [push, pull_request]

jobs:
  python-tests:
    name: Python Backend Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          cd tests
          pip install -r requirements.txt

      - name: Run Python tests
        run: |
          cd tests
          pytest --cov=elrond --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  web-tests:
    name: Web Application Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: 18

      - name: Install dependencies
        run: |
          cd web/tests
          npm ci

      - name: Install Playwright
        run: npx playwright install --with-deps

      - name: Run web tests
        run: |
          cd web/tests
          npm test

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: playwright-report
          path: web/tests/test-results/
```

## Test Development Guidelines

### For Python Tests

1. **Follow the Arrange-Act-Assert pattern**:
   ```python
   def test_something(self):
       # Arrange
       engine = ElrondEngine("case-001", "/source")

       # Act
       result = engine.check_permissions()

       # Assert
       assert result is True
   ```

2. **Use descriptive test names**:
   ```python
   # Good
   def test_mount_image_returns_none_when_mount_point_unavailable(self):
       ...

   # Bad
   def test_mount(self):
       ...
   ```

3. **Mock external dependencies**:
   ```python
   @patch("subprocess.run")
   def test_something(self, mock_run):
       mock_run.return_value.returncode = 0
       ...
   ```

4. **Use fixtures for common setup**:
   ```python
   @pytest.fixture
   def mock_engine(mock_case_id, mock_source_dir):
       return ElrondEngine(mock_case_id, mock_source_dir)
   ```

### For Web Tests

1. **Test user workflows, not implementation**:
   ```javascript
   // Good
   await page.click('button:has-text("Start Analysis")');

   // Bad
   await page.click('#submit-btn-internal-id-123');
   ```

2. **Use proper waiting strategies**:
   ```javascript
   // Good
   await expect(page.locator('.job-status')).toBeVisible();

   // Bad
   await page.waitForTimeout(5000);
   ```

3. **Use mock API when possible**:
   ```javascript
   await setupMockAPI(page);
   await page.goto('/');
   ```

## Coverage Reports

### Python Coverage

```bash
# Generate HTML coverage report
cd tests
pytest --cov=elrond --cov-report=html

# View report
open htmlcov/index.html
```

### Web Coverage

Playwright provides built-in test reports:

```bash
cd web/tests

# Generate report
npm run report

# View report
npx playwright show-report
```

## Performance Benchmarks

### Python Tests
- Unit tests: < 5 minutes
- Integration tests: < 10 minutes
- Full suite: < 15 minutes
- Coverage generation: +2 minutes

### Web Tests
- E2E tests: ~3 minutes
- API tests: ~1 minute
- Full suite: ~5 minutes

## Troubleshooting

### Python Tests

**Import errors**:
```bash
export PYTHONPATH=$PYTHONPATH:/path/to/elrond
```

**Fixture not found**:
- Ensure `conftest.py` is present
- Check fixture name spelling

**Tests timeout**:
```python
@pytest.mark.timeout(60)
def test_slow_operation(self):
    ...
```

### Web Tests

**Browser not installed**:
```bash
npx playwright install --with-deps
```

**Backend not running**:
```bash
# Start backend first
cd web/backend
uvicorn main:app --port 8000
```

**Port conflicts**:
```bash
BASE_URL=http://localhost:3001 npm test
```

## Contributing

When adding new features:

1. ✅ Write tests FIRST (TDD approach)
2. ✅ Ensure all tests pass locally
3. ✅ Maintain > 80% code coverage
4. ✅ Add appropriate test markers/descriptions
5. ✅ Update test documentation

## Test Metrics

### Current Status

| Metric | Python | Web | Total |
|--------|--------|-----|-------|
| **Total Tests** | 100+ | 190+ | 290+ |
| **Test Files** | 7 | 7 | 14 |
| **Code Coverage** | ~85% | ~90% | ~87% |
| **Execution Time** | ~10 min | ~5 min | ~15 min |

### Coverage Targets

- Overall: > 80%
- Core Engine: > 90%
- Platform Adapters: > 85%
- Web API: > 85%
- Utilities: > 85%
- Web UI: > 90%

## Additional Resources

### Python Testing
- [Pytest Documentation](https://docs.pytest.org/)
- [unittest.mock Guide](https://docs.python.org/3/library/unittest.mock.html)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)

### Web Testing
- [Playwright Documentation](https://playwright.dev)
- [Playwright Best Practices](https://playwright.dev/docs/best-practices)
- [Debugging Guide](https://playwright.dev/docs/debug)

## Support

For questions or issues:

1. Check the appropriate README:
   - [tests/README.md](tests/README.md) - Python tests
   - [web/tests/README.md](web/tests/README.md) - Web tests

2. Review existing test examples

3. Consult official documentation

4. Open an issue on GitHub

---

**Maintained by**: Ledger Development Team
**Last Updated**: 2025-01-15
**Test Framework Versions**:
- Python: pytest 7.4+
- Web: Playwright 1.40+
