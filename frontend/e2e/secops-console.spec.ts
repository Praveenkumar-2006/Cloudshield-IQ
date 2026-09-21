import { test, expect } from '@playwright/test';

test.describe('SecOps Remediation Console Drawer', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should open SecOps Console drawer when clicking the header button', async ({ page }) => {
    const consoleToggleBtn = page.locator('button:has-text("SecOps Console")').first();
    await consoleToggleBtn.click();

    // Verify drawer appears
    await expect(page.locator('text=Automated Remediation & SecOps Console')).toBeVisible();
    await expect(page.locator('.secops-console-panel')).toBeVisible();
  });

  test('should execute a remediation command and receive system response with code snippet', async ({ page }) => {
    // Open drawer
    await page.locator('button:has-text("SecOps Console")').first().click();

    // Type query into console input
    const input = page.locator('input[placeholder*="Enter remediation query"]');
    await input.fill('Remediate Root IAM access key');
    await input.press('Enter');

    // Verify user message appears
    await expect(page.locator('text=Remediate Root IAM access key')).toBeVisible();

    // Verify system response appears with CLI command
    await expect(page.locator('text=Threat Analysis: Root IAM Credentials Detected')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('code:has-text("aws iam delete-access-key")').first()).toBeVisible();
  });

  test('should close SecOps Console drawer when clicking close button', async ({ page }) => {
    // Open drawer
    await page.locator('button:has-text("SecOps Console")').first().click();
    await expect(page.locator('.secops-console-panel')).toBeVisible();

    // Click close button (X icon)
    const closeBtn = page.locator('button[aria-label="Close Console"]');
    await closeBtn.click();

    // Wait for drawer to close
    await expect(page.locator('.secops-console-panel')).not.toBeVisible();
  });
});
