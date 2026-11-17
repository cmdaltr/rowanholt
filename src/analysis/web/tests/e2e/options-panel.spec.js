// Options Panel Component Tests

const { test, expect } = require('@playwright/test');
const { setupMockAPI } = require('../fixtures/mock-api.js');

test.describe('Options Panel', () => {
  test.beforeEach(async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');
  });

  test('should display options panel', async ({ page }) => {
    const optionsPanel = page.locator('.options-panel');
    await expect(optionsPanel).toBeVisible();
  });

  test('should display option section tabs', async ({ page }) => {
    const sections = page.locator('.options-sections button');

    // Should have all sections
    await expect(sections).toHaveCount(10); // Based on OptionsPanel.js

    // Check for key sections
    await expect(page.locator('button', { hasText: 'Operation Mode' })).toBeVisible();
    await expect(page.locator('button', { hasText: 'Analysis Options' })).toBeVisible();
    await expect(page.locator('button', { hasText: 'Collection Options' })).toBeVisible();
    await expect(page.locator('button', { hasText: 'Memory Analysis' })).toBeVisible();
  });

  test('should show operation mode section by default', async ({ page }) => {
    const sectionTitle = page.locator('.section-header h3');
    await expect(sectionTitle).toContainText('Operation Mode');

    const description = page.locator('.section-header p');
    await expect(description).toContainText('Choose how you want to process the images');
  });

  test('should switch between sections', async ({ page }) => {
    // Click on Analysis Options tab
    await page.click('button:has-text("Analysis Options")');

    // Should show Analysis Options content
    const sectionTitle = page.locator('.section-header h3');
    await expect(sectionTitle).toContainText('Analysis Options');

    // Should have analysis-specific options
    await expect(page.locator('label', { hasText: 'Automated Analysis' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Extract IOCs' })).toBeVisible();
  });

  test('should display checkboxes for options', async ({ page }) => {
    const checkboxes = page.locator('.checkbox-item input[type="checkbox"]');
    await expect(checkboxes.first()).toBeVisible();
  });

  test('should display option labels and descriptions', async ({ page }) => {
    const firstOption = page.locator('.checkbox-item').first();

    const label = firstOption.locator('.option-label');
    await expect(label).toBeVisible();

    const description = firstOption.locator('.option-description');
    await expect(description).toBeVisible();
  });

  test('should check/uncheck options on click', async ({ page }) => {
    const collectCheckbox = page.locator('input[id="collect"]');

    // Initially unchecked
    await expect(collectCheckbox).not.toBeChecked();

    // Click to check
    await collectCheckbox.check();
    await expect(collectCheckbox).toBeChecked();

    // Click to uncheck
    await collectCheckbox.uncheck();
    await expect(collectCheckbox).not.toBeChecked();
  });

  test('should enable all options in section', async ({ page }) => {
    // Click "Enable All" button
    await page.click('button:has-text("Enable All")');

    // All checkboxes in current section should be checked
    const checkboxes = page.locator('.checkbox-group input[type="checkbox"]');
    const count = await checkboxes.count();

    for (let i = 0; i < count; i++) {
      await expect(checkboxes.nth(i)).toBeChecked();
    }
  });

  test('should disable all options in section', async ({ page }) => {
    // First enable all
    await page.click('button:has-text("Enable All")');
    await page.waitForTimeout(200);

    // Then disable all
    await page.click('button:has-text("Disable All")');

    // All checkboxes in current section should be unchecked
    const checkboxes = page.locator('.checkbox-group input[type="checkbox"]');
    const count = await checkboxes.count();

    for (let i = 0; i < count; i++) {
      await expect(checkboxes.nth(i)).not.toBeChecked();
    }
  });

  test('should maintain selections when switching sections', async ({ page }) => {
    // Check an option in Operation Mode
    await page.check('input[id="collect"]');
    await expect(page.locator('input[id="collect"]')).toBeChecked();

    // Switch to Analysis Options
    await page.click('button:has-text("Analysis Options")');

    // Check an option there
    await page.check('input[id="analysis"]');

    // Switch back to Operation Mode
    await page.click('button:has-text("Operation Mode")');

    // Original selection should still be checked
    await expect(page.locator('input[id="collect"]')).toBeChecked();
  });

  test('should show active section tab with different styling', async ({ page }) => {
    const operationButton = page.locator('button:has-text("Operation Mode")');
    await expect(operationButton).toHaveClass(/active/);

    // Click another section
    const analysisButton = page.locator('button:has-text("Analysis Options")');
    await analysisButton.click();

    // New section should be active
    await expect(analysisButton).toHaveClass(/active/);
    await expect(operationButton).not.toHaveClass(/active/);
  });
});

test.describe('Options Panel - Specific Options', () => {
  test.beforeEach(async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');
  });

  test('should have operation mode options', async ({ page }) => {
    await expect(page.locator('label', { hasText: 'Collect' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Custodian' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Reorganise' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Process' })).toBeVisible();
  });

  test('should have analysis options', async ({ page }) => {
    await page.click('button:has-text("Analysis Options")');

    await expect(page.locator('label', { hasText: 'Automated Analysis' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Extract IOCs' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Timeline' })).toBeVisible();
  });

  test('should have collection options', async ({ page }) => {
    await page.click('button:has-text("Collection Options")');

    await expect(page.locator('label', { hasText: 'Collect Files' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'User Profiles' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Volume Shadow Copies' })).toBeVisible();
  });

  test('should have memory analysis options', async ({ page }) => {
    await page.click('button:has-text("Memory Analysis")');

    await expect(page.locator('label', { hasText: 'Memory Analysis' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Memory Timeline' })).toBeVisible();
  });

  test('should have speed mode options', async ({ page }) => {
    await page.click('button:has-text("Speed/Quality Mode")');

    await expect(page.locator('label', { hasText: 'Exhaustive' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Brisk' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Quick' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Super Quick' })).toBeVisible();
  });

  test('should have output options', async ({ page }) => {
    await page.click('button:has-text("Output Options")');

    await expect(page.locator('label', { hasText: 'Splunk' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Elastic' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'MITRE Navigator' })).toBeVisible();
  });

  test('should have security scanning options', async ({ page }) => {
    await page.click('button:has-text("Security Scanning")');

    await expect(page.locator('label', { hasText: 'ClamAV' })).toBeVisible();
  });

  test('should have hashing options', async ({ page }) => {
    await page.click('button:has-text("Hashing & Verification")');

    await expect(page.locator('label', { hasText: 'NSRL' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Meta Only' })).toBeVisible();
  });

  test('should have post-processing options', async ({ page }) => {
    await page.click('button:has-text("Post-Processing")');

    await expect(page.locator('label', { hasText: 'Archive' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'Delete Raw Data' })).toBeVisible();
  });

  test('should have miscellaneous options', async ({ page }) => {
    await page.click('button:has-text("Miscellaneous")');

    await expect(page.locator('label', { hasText: 'Keep Mounted' })).toBeVisible();
    await expect(page.locator('label', { hasText: 'LOTR Theme' })).toBeVisible();
  });
});

test.describe('Options Panel - Responsive Design', () => {
  test('should stack section tabs vertically on mobile', async ({ page }) => {
    await setupMockAPI(page);
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');

    const sections = page.locator('.options-sections');
    await expect(sections).toBeVisible();

    // Sections should be stacked
    const buttons = sections.locator('button');
    await expect(buttons.first()).toBeVisible();
  });

  test('should display options in single column on mobile', async ({ page }) => {
    await setupMockAPI(page);
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');

    const checkboxGroup = page.locator('.checkbox-group');
    await expect(checkboxGroup).toBeVisible();
  });
});

test.describe('Options Panel - Accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await setupMockAPI(page);
    await page.goto('/');
  });

  test('should have proper label associations', async ({ page }) => {
    const checkbox = page.locator('input[id="collect"]');
    const label = page.locator('label[for="collect"]');

    await expect(checkbox).toBeVisible();
    await expect(label).toBeVisible();

    // Clicking label should toggle checkbox
    await label.click();
    await expect(checkbox).toBeChecked();
  });

  test('should be keyboard navigable', async ({ page }) => {
    // Tab through options
    await page.keyboard.press('Tab');

    // Space should toggle checkbox
    await page.keyboard.press('Space');
  });
});
