# CloudShield IQ — Playwright UI & Component Testing Guide

This project includes end-to-end (E2E) and component tests powered by **Playwright**.
You can run tests using the **Playwright VS Code / Antigravity IDE Extension** or directly from the terminal.

---

## 1. Using the Playwright Extension (VS Code / Antigravity IDE)

The workspace is pre-configured with `.vscode/settings.json` pointing to:
`cloudshield-iq-phase0-1/cloudshield-iq/frontend/playwright.config.ts`

### Steps to Run via Extension:
1. Ensure the **Playwright Test** extension (`ms-playwright.playwright`) is enabled.
2. Open the **Testing Explorer** from the Activity Bar (the flask/beaker icon on the left sidebar).
3. You will see all test suites listed hierarchically:
   - `navigation.spec.ts` — View routing, navigation bar active states, header badges
   - `theme-styles.spec.ts` — Verification of non-AI dark carbon theme (`#0A0D12`), zero purple/blue gradients, emerald accents
   - `findings.spec.ts` — Master-detail selection, search filter, severity/cloud filters, CLI and Terraform patch copying
   - `compliance.spec.ts` — Framework status matrix, passing/failing control chips
   - `ml-engine.spec.ts` — Isolation Forest Anomaly Scan and Supervised Risk Classifier (XGBoost) inference
   - `secops-console.spec.ts` — SecOps Remediation Console drawer, interactive commands, code snippets
   - `ingestion.spec.ts` — Real-time risk sliders and telemetry ingestion simulation
4. **Run any test or group**: Click the green **Play** button next to any test, group, or file.
5. **Debug any test**: Right-click any test and select **Debug Test** to step through execution with breakpoints.
6. **Watch / Show Browser**: Check the **"Show browser"** checkbox in the Testing sidebar to watch the browser execute live.

---

## 2. Running via Batch Script (Quickest)

From the project root:

```cmd
:: Run all tests in headless mode
test_ui.bat

:: Launch Playwright Interactive UI Mode (Visual Test Runner)
test_ui.bat --ui

:: View last HTML Test Execution Report
test_ui.bat --report
```

---

## 3. Running via NPM Scripts (frontend directory)

Navigate to `cloudshield-iq-phase0-1/cloudshield-iq/frontend`:

```bash
# Run all tests headlessly
npm run test:e2e

# Launch interactive UI mode (allows time-travel debugging, DOM inspection)
npm run test:e2e:ui

# View HTML report
npm run test:e2e:report

# Run a specific test file
npx playwright test e2e/navigation.spec.ts

# Run tests in headed mode (visible browser window)
npx playwright test --headed
```

---

## 4. Test Coverage Summary

| Test Spec | Target Area | What is Tested |
|---|---|---|
| `e2e/navigation.spec.ts` | Routing & Header | Tab transitions across all 6 views, page title, health badge |
| `e2e/theme-styles.spec.ts` | Design System | Validates strict dark carbon slate (`rgb(10, 13, 18)`), absence of purple/blue gradients |
| `e2e/findings.spec.ts` | Security Findings | Search filtering, AWS/Azure/GCP filters, severity badges, master-detail sync, CLI/Terraform code |
| `e2e/compliance.spec.ts` | Compliance Matrix | CIS AWS/Azure/GCP, NIST 800-53, ISO 27001, PCI-DSS controls & status chips |
| `e2e/ml-engine.spec.ts` | ML Pipelines | Phase 5 Isolation Forest anomaly scans & Phase 6 Supervised XGBoost risk classifier inference |
| `e2e/secops-console.spec.ts` | SecOps Console | Slide-over drawer, operator queries, system playbook generation |
| `e2e/ingestion.spec.ts` | Telemetry Pipeline | Real-time risk parameter sliders (0-100), telemetry batch simulation |
