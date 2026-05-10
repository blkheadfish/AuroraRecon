#!/bin/bash
# Check writable cron jobs and scheduled tasks
set -euo pipefail
echo "=== CRONTABS ===" && cat /etc/crontab 2>/dev/null
echo "=== CRON.D ===" && ls -la /etc/cron.d/ 2>/dev/null
echo "=== WRITABLE ===" && find /etc/cron* -writable -type f 2>/dev/null || true
echo "=== USER_CRON ===" && crontab -l 2>/dev/null || true
