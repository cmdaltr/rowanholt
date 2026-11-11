#!/usr/bin/env bash
# Issue a Rowanholt licence in one line (licensor only): a wrapper over sign_licence.py.
#
#   export ROWANHOLT_LICENCE_KEY=~/.config/rowanholt/licence-signing.key   # never commit it
#   ./scripts/admin/issue-licence.sh "Northwind Ltd" services 25
#   ./scripts/admin/issue-licence.sh "Northwind Ltd" pro unlimited ops@northwind.example 2027-12-31
#
# Arguments (the first three are required):
#   1 licensee   who it's for, as the Licence page shows it
#   2 edition    pro | services
#   3 seats      a number, or unlimited
#   4 email      contact, or - for none                       (default: none)
#   5 expires    YYYY-MM-DD, or perpetual                     (default: a year from today)
#   6 features   extra feature ids, comma-separated, or '*'   (default: the edition's own)
#
# With LICENCE_LEDGER_DIR set to the licensing repo, the licence and its ledger row go there (commit
# them). Without it, the licence goes to ./licences/ (git-ignored). Either way the line is printed.
set -euo pipefail

[[ $# -ge 3 ]] || { sed -n '2,15p' "$0"; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
py="$root/.venv/bin/python"
# The venv must have samarkand and cryptography (requirements/web.txt); else whichever python3 is on PATH
"$py" -c "import samarkand" 2>/dev/null || py="$(command -v python3)"

email="${4:--}"
[[ "$email" == "-" ]] && email=""
expires="${5:-$(date -v+1y +%F 2>/dev/null || date -d '+1 year' +%F)}"
# An empty array expands with ${out[@]+...}: macOS bash 3.2 calls a bare empty one unbound.
out=()
if [[ -z "${LICENCE_LEDGER_DIR:-}" ]]; then
  mkdir -p "$root/licences"
  out=(--out "$root/licences/$(date +%Y%m%d-%H%M%S)-$(echo "$1" | tr -cs 'A-Za-z0-9' '-' | sed 's/-$//').licence")
fi

"$py" "$here/sign_licence.py" sign --licensee "$1" --edition "$2" --seats "$3" \
  --email "$email" --expires "$expires" --features "${6:-}" ${out[@]+"${out[@]}"}
