import { test, expect } from '@playwright/test';

test.describe('Ingestion & Telemetry Pipeline Component', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.locator('nav.nav-tabs-desktop button:has-text("Ingestion")').click();
  });

  test('should render ingestion engine upload dropzone and controls', async ({ page }) => {
    await expect(page.locator('text=Multi-Cloud Data Ingestion Engine')).toBeVisible();
    await expect(page.locator('text=Select Configuration Audit File')).toBeVisible();
    await expect(page.locator('button:has-text("Upload & Analyze File")')).toBeVisible();
    await expect(page.locator('button:has-text("Simulate Ingestion Error")')).toBeVisible();
  });

  test('should simulate telemetry file upload workflow and display success state', async ({ page }) => {
    const uploadBtn = page.locator('button:has-text("Upload & Analyze File")');
    await expect(uploadBtn).toBeVisible();
    await uploadBtn.click();

    // Verify upload success message appears
    await expect(page.locator('text=Ingestion Successful')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=cloud-telemetry-dump-prod-01.json')).toBeVisible();

    // Verify reset button works
    const resetBtn = page.locator('button:has-text("Reset Ingestion")');
    await expect(resetBtn).toBeVisible();
    await resetBtn.click();
    await expect(page.locator('text=Ingestion Successful')).not.toBeVisible();
  });
});
