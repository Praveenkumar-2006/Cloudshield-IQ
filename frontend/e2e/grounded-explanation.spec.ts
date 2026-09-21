import { test, expect } from '@playwright/test';

test.describe('Grounded LLM & Security Explanation Layer', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Switch to Findings tab
    await page.locator('nav.nav-tabs-desktop button:has-text("Findings")').click();
  });

  test('should render Grounded Security Explanation card with 100% evidence grounding badge', async ({ page }) => {
    const explanationCard = page.locator('#grounded-security-explanation');
    await expect(explanationCard).toBeVisible();

    // Verify Grounding badge
    await expect(explanationCard.locator('text=100% Grounded in Evidence')).toBeVisible();

    // Verify verified risk severity badge is displayed
    await expect(explanationCard.locator('text=VERIFIED RISK SEVERITY:')).toBeVisible();
    await expect(explanationCard.locator('text=Grounding Score: 100%')).toBeVisible();
  });

  test('should display structured factual sections derived from EvidencePack', async ({ page }) => {
    const explanationCard = page.locator('#grounded-security-explanation');

    // Section 1: What Happened
    await expect(explanationCard.locator('text=What Happened')).toBeVisible();

    // Section 2: Why It Matters
    await expect(explanationCard.locator('text=Why It Matters')).toBeVisible();

    // Section 3: Verified Pipeline Evidence
    await expect(explanationCard.locator('text=Verified Pipeline Evidence')).toBeVisible();

    // Section 4: Compliance Impact
    await expect(explanationCard.locator('text=Compliance Impact')).toBeVisible();

    // Section 5: Recommended Action
    await expect(explanationCard.locator('text=Recommended Non-Destructive Remediation')).toBeVisible();
  });

  test('should update explanation dynamically when selecting different findings', async ({ page }) => {
    // Select S3 bucket finding
    const s3Card = page.locator('.surface-card-interactive:has-text("FND-AWS-2081")').first();
    await s3Card.click();

    const explanationCard = page.locator('#grounded-security-explanation');
    await expect(explanationCard).toBeVisible();

    // S3 specific evidence or resource should appear in the explanation
    await expect(explanationCard).toContainText('cloudshield-prod-analytics-exports');
  });

  test('should trigger refresh button without crashing and maintain strict evidence bounds', async ({ page }) => {
    const refreshBtn = page.locator('.surface-card:has-text("Grounded Security Explanation") button:has-text("Refresh")');
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    // Card should still be visible and display verified severity
    const explanationCard = page.locator('#grounded-security-explanation');
    await expect(explanationCard).toBeVisible();
    await expect(explanationCard.locator('text=100% Grounded in Evidence')).toBeVisible();
  });
});
