#!/bin/bash
set -euo pipefail

echo "This legacy automation path was retired because it generated scripts with embedded certificate passwords."
echo "Use scripts/enterprise-ca-automation.sh with secrets supplied at runtime."
echo "Review docs/enterprise-ca-complete-automation-guide.md before deployment."
exit 1
