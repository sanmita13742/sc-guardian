#!/usr/bin/env sh
# Installs Syft (Anchore) to ~/bin (user-level, no sudo). Official docs: https://oss.anchore.com/docs/installation/syft/
set -eu
mkdir -p "$HOME/bin"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/bin"
echo "Installed. Make sure \$HOME/bin is on PATH, or set SYFT_BIN in .env"
"$HOME/bin/syft" version
