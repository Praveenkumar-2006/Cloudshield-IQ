/**
 * CloudShield IQ — Frontend API Configuration
 * ============================================
 * Centralized API Base URL and request options.
 */

export const API_BASE: string = (
  import.meta.env.VITE_API_URL || 'http://localhost:8001/api/v1'
).replace(/\/$/, '');

export const DEFAULT_TIMEOUT_MS = 5000;
export const UPLOAD_TIMEOUT_MS = 30000;
