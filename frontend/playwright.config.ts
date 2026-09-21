import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright Configuration for CloudShield IQ Frontend
 * Configured for both CLI and the Playwright VS Code / Antigravity IDE Extension.
 *
 * Web server connects to http://localhost:8000 (Vite dev server)
 * Reuses existing server if already running.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html', { open: 'never' }],
    ['list']
  ],
  use: {
    baseURL: 'http://localhost:8000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:8000',
    reuseExistingServer: true,
    timeout: 120 * 1000,
  },
});
