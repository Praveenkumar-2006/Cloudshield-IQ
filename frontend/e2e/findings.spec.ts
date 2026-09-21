import { test, expect } from '@playwright/test';

test.describe('Findings Master-Detail & Filtering Component', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Switch to Findings tab
    await page.locator('nav.nav-tabs-desktop button:has-text("Findings")').click();
  });

  test('should render findings list and default selected finding detail', async ({ page }) => {
    const findingCards = page.locator('.surface-card-interactive');
    await expect(findingCards.first()).toBeVisible();

    // Check detail pane shows finding ID
    await expect(page.locator('.surface-card:has-text("Remediation Runbook")').or(page.locator('.surface-card:has-text("FND-AWS-1049")')).first()).toBeVisible();
  });

  test('should filter findings by search query', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Filter by title, ID, or ARN"]');
    await searchInput.fill('S3');

    // Should find S3 bucket finding
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-2081")').first()).toBeVisible();
    // Root user finding should be filtered out
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-1049")')).not.toBeVisible();

    // Clear search
    await searchInput.fill('');
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-1049")').first()).toBeVisible();
  });

  test('should filter findings by severity level', async ({ page }) => {
    // Click CRITICAL severity button in filter bar
    const criticalBtn = page.locator('button.btn:text-is("CRITICAL")').first();
    await criticalBtn.click();

    // Verify critical findings are visible in master list
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-1049")').first()).toBeVisible();

    // Reset to ALL
    await page.locator('button.btn:text-is("ALL")').last().click();
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-1049")').first()).toBeVisible();
  });

  test('should filter findings by cloud provider', async ({ page }) => {
    // Filter AWS
    const awsBtn = page.locator('button.btn:text-is("AWS")').first();
    await awsBtn.click();
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-1049")').first()).toBeVisible();

    // Filter Azure
    const azrBtn = page.locator('button.btn:text-is("Azure")').first();
    await azrBtn.click();
    await expect(page.locator('.surface-card-interactive:has-text("FND-AZR-3012")').first()).toBeVisible();
    await expect(page.locator('.surface-card-interactive:has-text("FND-AWS-1049")')).not.toBeVisible();

    // Filter GCP
    const gcpBtn = page.locator('button.btn:text-is("GCP")').first();
    await gcpBtn.click();
    await expect(page.locator('.surface-card-interactive:has-text("FND-GCP-4099")').first()).toBeVisible();
  });

  test('should switch selected finding when clicking another card and display code patches', async ({ page }) => {
    // Click S3 finding card
    const s3Card = page.locator('.surface-card-interactive:has-text("FND-AWS-2081")').first();
    await s3Card.click();

    // Detail panel should update to show FND-AWS-2081 title
    await expect(page.locator('h2:has-text("S3 Bucket with Sensitive Financial Artifacts")').first()).toBeVisible();

    // Verify CLI command and Terraform code are displayed
    await expect(page.locator('code:has-text("aws s3api put-public-access-block")').first()).toBeVisible();
    await expect(page.locator('code:has-text("aws_s3_bucket_public_access_block")').first()).toBeVisible();
  });
});
