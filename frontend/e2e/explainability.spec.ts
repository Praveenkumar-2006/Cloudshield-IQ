import { test, expect } from '@playwright/test';

test.describe('Phase 7: TreeSHAP Explainability & Risk Attribution', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should display TreeSHAP global feature attributions with domain impact chips in ML Engine', async ({ page }) => {
    // Navigate to ML Engine tab
    await page.locator('nav.nav-tabs-desktop button:has-text("ML Engine")').click();

    // Verify global attribution card header and phase tag
    await expect(page.locator('text=Top TreeSHAP Global Feature Attributions')).toBeVisible();
    await expect(page.locator('text=PHASE 7 (EXPLAINABILITY)')).toBeVisible();

    // Verify domain impact chips
    await expect(page.locator('text=Domain Impact:')).toBeVisible();
    await expect(page.locator('text=IAM:').first()).toBeVisible();

    // Verify top global features
    await expect(page.locator('text=Root Cloud Account Usage').first()).toBeVisible();
    await expect(page.locator('text=Missing Multi-Factor Auth').first()).toBeVisible();
  });

  test('should trigger TreeSHAP local waterfall attribution breakdown for an incident', async ({ page }) => {
    // Navigate to ML Engine tab
    await page.locator('nav.nav-tabs-desktop button:has-text("ML Engine")').click();

    // Initial placeholder state
    await expect(page.locator('text=Click "Deconstruct Sample Incident with TreeSHAP"')).toBeVisible();

    // Click explain button
    const deconstructBtn = page.locator('button:has-text("Deconstruct Sample Incident with TreeSHAP")');
    await expect(deconstructBtn).toBeVisible();
    await deconstructBtn.click();

    // Verify waterfall breakdown container appears
    await expect(page.locator('text=Explained Score:')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Base Risk:').first()).toBeVisible();

    // Verify top drivers and mitigators are displayed
    await expect(page.locator('text=Top Risk Drivers')).toBeVisible();
    await expect(page.locator('text=Root Account Usage')).toBeVisible();
    await expect(page.locator('text=+24.5 pts').first()).toBeVisible();
    await expect(page.locator('text=Protective Factors')).toBeVisible();
  });

  test('should navigate from Findings detail pane directly into TreeSHAP waterfall explainer', async ({ page }) => {
    // Switch to Findings tab
    await page.locator('nav.nav-tabs-desktop button:has-text("Findings")').click();

    // Locate the TreeSHAP jump button in the detail pane
    const explainFindingBtn = page.locator('button:has-text("Deconstruct in TreeSHAP Waterfall")').first();
    await expect(explainFindingBtn).toBeVisible();
    await explainFindingBtn.click();

    // Should route automatically to ML Engine tab
    const mlTab = page.locator('nav.nav-tabs-desktop button:has-text("ML Engine")');
    await expect(mlTab).toHaveClass(/is-active/);

    // TreeSHAP waterfall should be visible with the finding ID
    await expect(page.locator('text=TreeSHAP Local Incident Attribution Waterfall')).toBeVisible();
    await expect(page.locator('text=Incident: FND-AWS-1049').first()).toBeVisible();
    await expect(page.locator('text=Explained Score:').first()).toBeVisible();
  });
});
