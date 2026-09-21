import { test, expect } from '@playwright/test';

test.describe('Theme & Aesthetics Validation (Non-AI Dark Carbon Design)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should use dark carbon slate background color on body (#0a0d12 / rgb(10, 13, 18))', async ({ page }) => {
    const bodyBg = await page.evaluate(() => {
      return window.getComputedStyle(document.body).backgroundColor;
    });
    // Expected rgb(10, 13, 18) or close carbon slate dark
    expect(bodyBg).toBe('rgb(10, 13, 18)');
  });

  test('should not contain purple or blue gradient backgrounds in navigation or main cards', async ({ page }) => {
    const elementsWithGradient = await page.evaluate(() => {
      const all = Array.from(document.querySelectorAll('.nav-header, .secops-card, .btn-primary, .kpi-card'));
      const violations: string[] = [];

      for (const el of all) {
        const style = window.getComputedStyle(el);
        const bgImg = style.backgroundImage;
        if (bgImg && bgImg.includes('gradient')) {
          // Check if gradient has purple / blue / violet hues
          if (/rgb\((120|130|140|150|160|90|99|102|236|79|70),\s*(0|50|70|80|90|102),\s*(200|220|230|240|255)/i.test(bgImg) ||
              bgImg.includes('#6366f1') || bgImg.includes('#8b5cf6') || bgImg.includes('#a855f7')) {
            violations.push(`${el.className}: ${bgImg}`);
          }
        }
      }
      return violations;
    });

    expect(elementsWithGradient).toHaveLength(0);
  });

  test('should use tactical emerald accents for primary badges and highlights', async ({ page }) => {
    const emeraldBadge = page.locator('.badge-emerald, .text-emerald-400, .nav-logo-badge').first();
    await expect(emeraldBadge).toBeVisible();
  });
});
