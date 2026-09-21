import { test, expect } from '@playwright/test';

test.describe('ML Engine Components (Anomaly Detection & Supervised Risk Scoring)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.locator('nav.nav-tabs-desktop button:has-text("ML Engine")').click();
  });

  test('should display Isolation Forest anomaly detection engine with model specifications', async ({ page }) => {
    await expect(page.locator('text=Phase 5: Machine Learning Anomaly Detection')).toBeVisible();
    await expect(page.locator('.caption:text-is("Algorithm")').first()).toBeVisible();
    await expect(page.locator('.code-text:has-text("IsolationForest")').first()).toBeVisible();
  });

  test('should trigger Isolation Forest anomaly scan and render anomaly telemetry cards', async ({ page }) => {
    const scanBtn = page.locator('button:has-text("Run Live ML Inference Scan")');
    await expect(scanBtn).toBeVisible();
    await scanBtn.click();

    // Verify scan results appear
    await expect(page.locator('text=Live Inference Result').first()).toBeVisible({ timeout: 10000 });
  });

  test('should display Phase 6 Supervised Risk Classification Engine with dual-head architecture', async ({ page }) => {
    await expect(page.locator('text=Phase 6: Supervised Risk Classification Engine')).toBeVisible();
    await expect(page.locator('.caption:text-is("Dataset & Split")').first()).toBeVisible();
    await expect(page.locator('.code-text:has-text("XGBoost")').first()).toBeVisible();
  });

  test('should trigger live Supervised Risk Scan and render predicted severity and risk score', async ({ page }) => {
    const runRiskBtn = page.locator('button:has-text("Run Live Supervised Risk Scan")');
    await expect(runRiskBtn).toBeVisible();
    await runRiskBtn.click();

    // Wait for the risk predictions container
    await expect(page.locator('text=Live Supervised Inference').first()).toBeVisible({ timeout: 10000 });

    // Check that severity predictions and risk scores are displayed
    await expect(page.locator('text=Predicted Risk:').first()).toBeVisible();
    await expect(page.locator('text=Softmax Dist:').first()).toBeVisible();
  });

  test('should render simulation sliders and calculate simulated risk score', async ({ page }) => {
    await expect(page.locator('text=TreeSHAP Risk Sandbox Simulator')).toBeVisible();

    // Verify sliders exist
    const sliders = page.locator('input[type="range"]');
    await expect(sliders).toHaveCount(4);

    // Initial simulated score is rendered
    const scoreBadge = page.locator('text=/ 100').first();
    await expect(scoreBadge).toBeVisible();
  });
});
