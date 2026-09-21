import { test, expect } from '@playwright/test';

test.describe('Navigation & View Routing', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should load the page with correct title and header', async ({ page }) => {
    await expect(page).toHaveTitle(/CloudShield IQ/);
    const logo = page.locator('.nav-logo-text');
    await expect(logo).toHaveText('CloudShield IQ');
  });

  test('should navigate through all main views via desktop nav tabs', async ({ page }) => {
    // 1. Initial view is Overview
    const overviewTab = page.locator('nav.nav-tabs-desktop button:has-text("Overview")');
    await expect(overviewTab).toHaveClass(/is-active/);
    await expect(page.locator('h1')).toHaveText('CloudShield IQ');

    // 2. Switch to Findings
    const findingsTab = page.locator('nav.nav-tabs-desktop button:has-text("Findings")');
    await findingsTab.click();
    await expect(findingsTab).toHaveClass(/is-active/);
    await expect(page.locator('input[placeholder*="Filter by title, ID, or ARN"]')).toBeVisible();

    // 3. Switch to Compliance
    const complianceTab = page.locator('nav.nav-tabs-desktop button:has-text("Compliance")');
    await complianceTab.click();
    await expect(complianceTab).toHaveClass(/is-active/);
    await expect(page.locator('text=Multi-Cloud Compliance Control Matrix')).toBeVisible();

    // 4. Switch to ML Engine
    const mlTab = page.locator('nav.nav-tabs-desktop button:has-text("ML Engine")');
    await mlTab.click();
    await expect(mlTab).toHaveClass(/is-active/);
    await expect(page.locator('text=Phase 5: Machine Learning Anomaly Detection')).toBeVisible();

    // 5. Switch to Ingestion
    const ingestionTab = page.locator('nav.nav-tabs-desktop button:has-text("Ingestion")');
    await ingestionTab.click();
    await expect(ingestionTab).toHaveClass(/is-active/);
    await expect(page.locator('text=Multi-Cloud Data Ingestion Engine')).toBeVisible();

    // 6. Switch to Architecture
    const archTab = page.locator('nav.nav-tabs-desktop button:has-text("Architecture")');
    await archTab.click();
    await expect(archTab).toHaveClass(/is-active/);
    await expect(page.locator('text=CloudShield IQ System Architecture')).toBeVisible();

    // 7. Return to Overview by clicking logo
    await page.locator('.nav-logo-group').click();
    await expect(overviewTab).toHaveClass(/is-active/);
    await expect(page.locator('h1')).toHaveText('CloudShield IQ');
  });

  test('should display backend health status indicator in header', async ({ page }) => {
    const healthButton = page.locator('button[aria-label="Refresh Backend"]');
    await expect(healthButton).toBeVisible();
    await expect(healthButton).toContainText(/API Online|API Standalone/);
  });
});
