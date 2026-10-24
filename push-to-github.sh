#!/usr/bin/env bash
# PHP2Shell Sentinel — GitHub repo setup & push
# Run this ONCE from inside /home/hoed/php2shell after: gh auth login
#
# Usage:
#   cd /home/hoed/php2shell
#   gh auth login          # follow prompts (browser or token)
#   bash push-to-github.sh [your-github-username]

set -euo pipefail

REPO_NAME="php2shell-sentinel"
DESCRIPTION="PHP Runtime Vulnerability Assessment Toolkit — CVE-2026-109618 & CVE-2026-109619"
USERNAME="${1:-}"

# ── Validate ──────────────────────────────────────────────────────────────────
if ! command -v gh &>/dev/null; then
    echo "ERROR: GitHub CLI (gh) not found. Install with: apt-get install gh"
    exit 1
fi

if ! gh auth status &>/dev/null; then
    echo "ERROR: Not logged into GitHub. Run: gh auth login"
    exit 1
fi

if [[ -z "$USERNAME" ]]; then
    USERNAME=$(gh api user --jq '.login')
    echo "Using GitHub username: $USERNAME"
fi

# ── Create repo ───────────────────────────────────────────────────────────────
echo ""
echo "Creating GitHub repository: $USERNAME/$REPO_NAME ..."

gh repo create "$REPO_NAME" \
    --public \
    --description "$DESCRIPTION" \
    --homepage "https://github.com/$USERNAME/$REPO_NAME" \
    2>&1 || {
        echo "Repository may already exist — continuing with push..."
    }

# ── Set remote & push ─────────────────────────────────────────────────────────
REMOTE_URL="https://github.com/$USERNAME/$REPO_NAME.git"

if git remote get-url origin &>/dev/null; then
    git remote set-url origin "$REMOTE_URL"
else
    git remote add origin "$REMOTE_URL"
fi

echo ""
echo "Pushing to $REMOTE_URL ..."
git push -u origin main

# ── Add topics / labels ───────────────────────────────────────────────────────
echo ""
echo "Adding repository topics..."
gh repo edit "$USERNAME/$REPO_NAME" \
    --add-topic security \
    --add-topic php \
    --add-topic vulnerability-assessment \
    --add-topic cve \
    --add-topic kali-linux \
    --add-topic defensive-security \
    2>/dev/null || true

# ── Create initial GitHub release ─────────────────────────────────────────────
echo ""
echo "Creating v1.0.0 release..."
gh release create v1.0.0 \
    --repo "$USERNAME/$REPO_NAME" \
    --title "v1.0.0 — Initial Release" \
    --notes "## PHP2Shell Sentinel v1.0.0

Assessment toolkit for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell).

### What's included
- Local PHP binary, php.ini, and PHP-FPM audit
- Remote HTTP header assessment with scope allowlist
- Deep passive fingerprinting (headers, error pages, cookies, timing)
- Patch matrix for PHP 8.2–8.5; EOL detection for 8.1 and older
- Terminal (Rich), JSON, and Markdown reports
- Isolated Docker lab (localhost-only)
- 71 unit + integration tests

### CVE References
- [CVE-2026-109618](https://github.com/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp)

### Install
\`\`\`bash
git clone https://github.com/$USERNAME/$REPO_NAME.git
cd $REPO_NAME
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
php2shell-sentinel --help
\`\`\`" \
    2>/dev/null || echo "Release may already exist — skipping."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=========================================="
echo " Done!"
echo " Repository: https://github.com/$USERNAME/$REPO_NAME"
echo " Actions:    https://github.com/$USERNAME/$REPO_NAME/actions"
echo " Releases:   https://github.com/$USERNAME/$REPO_NAME/releases"
echo "=========================================="
