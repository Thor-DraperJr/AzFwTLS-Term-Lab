#!/bin/bash
set -euo pipefail

echo "This legacy entry point no longer embeds certificate or VM credentials."
echo "Use scripts/enterprise-ca-automation.sh with secrets supplied at runtime."
echo "Review docs/enterprise-ca-complete-automation-guide.md before deployment."
exit 1
