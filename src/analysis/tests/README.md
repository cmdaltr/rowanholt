# Elrond Test Suite

Comprehensive test suite for the Elrond digital forensics automation tool.

## Overview

This test suite provides extensive coverage for:
- **Core Engine**: Forensic analysis engine and workflow orchestration
- **Platform Adapters**: Linux, macOS, and Windows platform-specific functionality
- **Tool Management**: Forensic tool verification and installation
- **Web Backend**: FastAPI REST API endpoints
- **Job Management**: Analysis job storage and execution
- **Background Tasks**: Celery task processing
- **Utilities**: Helper functions and validators

## Directory Structure

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── pytest.ini              # Pytest configuration
├── requirements.txt        # Test dependencies
├── README.md              # This file
├── unit/                  # Unit tests
│   ├── test_engine.py     # Core engine tests
│   ├── test_platform.py   # Platform adapter tests
│   ├── test_tool_manager.py # Tool manager tests
│   ├── test_storage.py    # Storage tests
│   ├── test_tasks.py      # Celery task tests
│   └── test_helpers.py    # Utility helper tests
└── integration/           # Integration tests
    └── test_web_api.py    # Web API integration tests
```

## Installation

### 1. Install Test Dependencies

```bash
# From the elrond root directory
cd tests
pip install -r requirements.txt
```

### 2. Install Playwright (for web tests)

```bash
# Install Playwright browsers (in web/tests)
cd ../web/tests
npm install
npx playwright install --with-deps
```

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=elrond --cov-report=html

# Run in verbose mode
pytest -v

# Run with parallel execution (faster)
pytest -n auto
```

### Specific Test Categories

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only web API tests
pytest -m web

# Run platform-specific tests
pytest -m platform_specific
```

### Specific Test Files

```bash
# Run specific test file
pytest tests/unit/test_engine.py

# Run specific test class
pytest tests/unit/test_engine.py::TestElrondEngine

# Run specific test function
pytest tests/unit/test_engine.py::TestElrondEngine::test_init
```

### Test Selection

```bash
# Run tests matching pattern
pytest -k "test_mount"

# Run tests NOT matching pattern
pytest -k "not slow"

# Run tests with specific marker
pytest -m "not slow"
```

## Test Markers

Available test markers:

- `@pytest.mark.unit` - Unit tests for individual components
- `@pytest.mark.integration` - Integration tests requiring external services
- `@pytest.mark.web` - Web backend API tests
- `@pytest.mark.slow` - Tests that take a long time to run
- `@pytest.mark.platform_specific` - Tests that only run on specific platforms

## Coverage Reports

### Generate Coverage Report

```bash
# HTML report (recommended)
pytest --cov=elrond --cov-report=html
open htmlcov/index.html

# Terminal report
pytest --cov=elrond --cov-report=term-missing

# XML report (for CI/CD)
pytest --cov=elrond --cov-report=xml
```

### Coverage Targets

- **Overall Coverage**: > 80%
- **Core Engine**: > 90%
- **Web API**: > 85%
- **Utilities**: > 85%

## Writing Tests

### Test Structure

```python
import pytest
from unittest.mock import MagicMock, patch

@pytest.mark.unit
class TestYourComponent:
    """Test YourComponent class."""

    def test_something(self):
        """Test that something works."""
        # Arrange
        component = YourComponent()

        # Act
        result = component.do_something()

        # Assert
        assert result == expected_value
```

### Using Fixtures

```python
def test_with_fixtures(temp_dir, mock_logger):
    """Test using fixtures from conftest.py."""
    # temp_dir and mock_logger are automatically provided
    test_file = temp_dir / "test.txt"
    test_file.write_text("test")

    mock_logger.info("Test message")

    assert test_file.exists()
    mock_logger.info.assert_called_once()
```

### Mocking

```python
@patch("module.external_function")
def test_with_mock(mock_func):
    """Test with mocked external function."""
    mock_func.return_value = "mocked value"

    result = function_under_test()

    assert result == "expected"
    mock_func.assert_called_once()
```

## Best Practices

### 1. Test Independence

Each test should be independent and not rely on other tests:

```python
# Good
def test_something(self):
    data = create_test_data()
    result = process(data)
    assert result.is_valid()

# Bad - depends on test order
test_data = None

def test_create(self):
    global test_data
    test_data = create_test_data()

def test_process(self):
    result = process(test_data)  # Breaks if test_create doesn't run first
```

### 2. Clear Test Names

Use descriptive test names that explain what is being tested:

```python
# Good
def test_mount_image_returns_none_when_mount_fails(self):
    ...

# Bad
def test_mount(self):
    ...
```

### 3. Arrange-Act-Assert Pattern

```python
def test_example(self):
    # Arrange - Set up test data and conditions
    engine = ElrondEngine(case_id="TEST-001", source_dir="/test")

    # Act - Execute the function being tested
    result = engine.check_permissions()

    # Assert - Verify the expected outcome
    assert result is True
```

### 4. Use Fixtures for Common Setup

```python
@pytest.fixture
def test_engine(mock_case_id, mock_source_dir):
    """Create test engine instance."""
    return ElrondEngine(mock_case_id, mock_source_dir)

def test_something(test_engine):
    # Use the fixture
    result = test_engine.do_something()
    assert result is not None
```

### 5. Test Edge Cases

```python
def test_format_file_size_zero(self):
    """Test formatting zero bytes."""
    assert format_file_size(0) == "0 B"

def test_format_file_size_negative(self):
    """Test formatting negative size (edge case)."""
    with pytest.raises(ValueError):
        format_file_size(-100)

def test_format_file_size_very_large(self):
    """Test formatting very large size."""
    result = format_file_size(10**15)
    assert "PB" in result
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Run Tests

on: [push, pull_request]

jobs:
  test:
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

    - name: Run tests
      run: |
        pytest --cov=elrond --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage.xml
```

## Troubleshooting

### Tests Fail with Import Errors

**Solution**: Ensure elrond is in your Python path:

```bash
export PYTHONPATH=$PYTHONPATH:/path/to/elrond
```

Or run tests from the elrond root directory.

### Tests Hang or Timeout

**Solution**: Increase timeout or mark slow tests:

```python
@pytest.mark.timeout(60)  # 60 second timeout
def test_slow_operation(self):
    ...
```

### Fixtures Not Found

**Solution**: Ensure `conftest.py` is in the correct location and imported properly.

### Platform-Specific Test Failures

**Solution**: Use platform markers:

```python
@pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
def test_linux_specific(self):
    ...
```

## Test Metrics

### Current Coverage

- **Total Tests**: 100+
- **Unit Tests**: 80+
- **Integration Tests**: 20+
- **Code Coverage**: ~85%

### Performance Targets

- Unit tests: < 5 minutes
- Integration tests: < 10 minutes
- Full test suite: < 15 minutes

## Contributing

When adding new functionality:

1. Write tests FIRST (TDD approach)
2. Ensure tests pass locally
3. Maintain > 80% code coverage
4. Add appropriate test markers
5. Update this README if needed

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Python unittest.mock](https://docs.python.org/3/library/unittest.mock.html)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [FastAPI Testing Guide](https://fastapi.tiangolo.com/tutorial/testing/)

## Support

For issues or questions:
- Check existing tests for examples
- Review pytest documentation
- Open an issue on GitHub

---

**Last Updated**: 2025-01-15
**Python Version**: 3.10+
**Pytest Version**: 7.4+
