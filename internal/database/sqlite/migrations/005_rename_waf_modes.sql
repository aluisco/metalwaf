-- Migration 005: rename WAF site modes for clarity
--   "detect" → "monitor"  (inspect and log threats, never block)
--   "block"  → "protect"  (inspect, log, and block detected threats)
UPDATE sites SET waf_mode = 'monitor' WHERE waf_mode = 'detect';
UPDATE sites SET waf_mode = 'protect' WHERE waf_mode = 'block';
