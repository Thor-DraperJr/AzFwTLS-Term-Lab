#!/bin/bash

# =============================================================================
# Azure Firewall TLS Inspection Lab - Quick Reference Script
# =============================================================================
# This script provides quick shortcuts to the most common operations
# using the master automation script.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MASTER_SCRIPT="$SCRIPT_DIR/master-automation.sh"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Azure Firewall TLS Inspection Lab - Quick Reference${NC}"
echo "============================================================"
echo ""

# Check if master script exists
if [ ! -f "$MASTER_SCRIPT" ]; then
    echo -e "${RED}❌ Master automation script not found at: $MASTER_SCRIPT${NC}"
    exit 1
fi

# Make sure it's executable
chmod +x "$MASTER_SCRIPT"

echo "Available quick actions:"
echo ""
echo -e "${GREEN}1.${NC} 🏗️  Deploy Complete Lab (Full automation)"
echo -e "${GREEN}2.${NC} 🧪 Test Existing Lab"
echo -e "${GREEN}3.${NC} 📊 Check Lab Status"
echo -e "${GREEN}4.${NC} ⚙️  Configure Existing Infrastructure"
echo -e "${GREEN}5.${NC} 🔍 Generate Status Report Only"
echo -e "${GREEN}6.${NC} 📈 Start Monitoring Mode"
echo -e "${GREEN}7.${NC} 🆘 Show Help"
echo -e "${GREEN}8.${NC} 🔧 Debug Mode Test"
echo ""

read -p "Enter your choice (1-8): " choice

case $choice in
    1)
        echo -e "${YELLOW}🏗️  Starting complete lab deployment...${NC}"
        echo "This will deploy, configure, and test everything."
        read -p "Continue? (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            "$MASTER_SCRIPT" full
        else
            echo "Cancelled."
        fi
        ;;
    2)
        echo -e "${YELLOW}🧪 Running comprehensive test suite...${NC}"
        "$MASTER_SCRIPT" test
        ;;
    3)
        echo -e "${YELLOW}📊 Checking lab status...${NC}"
        "$MASTER_SCRIPT" status
        ;;
    4)
        echo -e "${YELLOW}⚙️  Configuring existing infrastructure...${NC}"
        "$MASTER_SCRIPT" configure
        ;;
    5)
        echo -e "${YELLOW}🔍 Generating status report only...${NC}"
        "$MASTER_SCRIPT" status --report-only
        ;;
    6)
        echo -e "${YELLOW}📈 Starting monitoring mode (1 hour)...${NC}"
        echo "This will monitor the lab continuously for 1 hour."
        read -p "Continue? (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            "$MASTER_SCRIPT" monitor
        else
            echo "Cancelled."
        fi
        ;;
    7)
        echo -e "${YELLOW}🆘 Showing help...${NC}"
        "$MASTER_SCRIPT" help
        ;;
    8)
        echo -e "${YELLOW}🔧 Running test in debug mode...${NC}"
        "$MASTER_SCRIPT" test --debug
        ;;
    *)
        echo -e "${RED}❌ Invalid choice. Please run the script again.${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ Operation completed!${NC}"
echo ""
echo "📁 Check the following directories for outputs:"
echo "   • logs/ - Detailed execution logs"
echo "   • reports/ - HTML reports and JSON summaries"
echo ""
echo -e "${BLUE}💡 Tip: Use '$MASTER_SCRIPT help' for more options${NC}"
