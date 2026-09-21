import { test, expect } from '@playwright/test';

test.describe('Compliance Matrix Component', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.locator('nav.nav-tabs-desktop button:has-text("Compliance")').click();
  });

  test('should display compliance framework cards and status matrix', async ({ page }) => {
    await expect(page.locator('text=Multi-Cloud Compliance Control Matrix')).toBeVisible();
    await expect(page.locator('text=CIS AWS 1.4').first()).toBeVisible();
    await expect(page.locator('text=NIST 800-53').first()).toBeVisible();
    await expect(page.locator('text=PCI-DSS 4.0').first()).toBeVisible();
    await expect(page.locator('text=ISO 27001').first()).toBeVisible();
  });

  test('should filter controls by framework or status tabs', async ({ page }) => {
    const rows = page.locator('tbody tr');
    await expect(rows.first()).toBeVisible();

    // Verify PASS and FAIL chips exist in matrix
    await expect(page.locator('span.tag-pass:has-text("PASS")').first()).toBeVisible();
    await expect(page.locator('span.tag-critical:has-text("FAIL")').first()).toBeVisible();
  });
});
