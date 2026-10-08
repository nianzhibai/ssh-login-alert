#!/bin/bash
# Compatibility entry point; use the maintained implementation for all alerts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ssh-alert-enhanced.sh"
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
