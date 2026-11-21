#!/usr/bin/env bash
# Ставим бинарник и меню из одного коммита.
set -euo pipefail
export PATH="/usr/local/go/bin:$PATH"
branch=${1:-}
case "$branch" in dev|master) ;; *) echo 'Укажите dev или master' >&2; exit 2 ;; esac
[[ $EUID == 0 ]] || { echo 'Запустите через sudo' >&2; exit 1; }
work=$(mktemp -d)
binary=$(mktemp /usr/local/bin/.rkn-guard.XXXXXX)
manager=$(mktemp /opt/.rkn-guard-manager.XXXXXX)
wrapper=$(mktemp /usr/local/bin/.rkn.XXXXXX)
trap 'rm -rf -- "$work"; rm -f -- "$binary" "$manager" "$wrapper"' EXIT
if [[ ${RKN_PANEL_PROGRESS:-} == 1 ]]; then printf '%s\n' 'RKN_STAGE:clone'; fi
git clone -q --depth 1 --single-branch --branch "$branch" https://github.com/Flecksis/rkn-guard.git "$work/src"
cd "$work/src"
revision=$(git rev-parse --short HEAD)
if [[ ${RKN_PANEL_PROGRESS:-} == 1 ]]; then printf '%s\n' 'RKN_STAGE:build'; fi
GOTOOLCHAIN=auto go build -trimpath -ldflags="-X main.version=$revision -X main.branch=$branch" -o "$binary" ./cmd
bash -n install.sh
cp install.sh "$manager"
printf '%s\n' '#!/bin/bash' 'exec /opt/rkn-guard-manager.sh "$@"' > "$wrapper"
chmod 755 "$binary" "$manager" "$wrapper"
"$binary" build-info
if [[ $branch == master && -e /var/lib/rkn-guard-panel ]]; then
    /usr/local/bin/rkn-guard panel revoke
fi
if [[ ${RKN_PANEL_PROGRESS:-} == 1 ]]; then printf '%s\n' 'RKN_STAGE:install'; fi
mv -f "$binary" /usr/local/bin/rkn-guard
mv -f "$manager" /opt/rkn-guard-manager.sh
mv -f "$wrapper" /usr/local/bin/rkn
