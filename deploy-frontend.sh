#!/usr/bin/env bash
# deploy-frontend.sh — publish ONLY the ce-gov frontend (web/) to ce-net.com via ce-app.
#
# THE RULE: a CE app exposes ONLY its static frontend over HTTP. ce-gov's app STATE
# (proposals/arguments/votes/verdicts/policies) and device-to-device COMMS ride the MESH
# (content-addressed blobs + gov pubsub + request/reply to the gov/validator service — see
# src/mesh.js, src/mesh-service.js, docs/mesh-backend.md). This script ships the view layer
# only; it provisions NO backend compute (the hub has none) and keeps NO app state.
#
# It uses the `ce-app` CLI EXACTLY AS-IS (no edits to ce-app). `ce-app deploy` auto-detects
# the project: ce-gov's web/ is a plain static bundle (index.html + policy.* + the ES-module
# sources it imports from ../src), so ce-app uploads the files and enables SPA routing. The
# app goes live at:
#     https://<id>.ce-net.com/      (and https://ce-net.com/apps/<id>/)
# where <id> is this machine's ce-app public dev id (./.ce/app-id under the deploy dir).
#
# To get the friendly host gov-<nodeprefix>.ce-net.com, claim a human slug (optional, below).
#
# Usage:
#   ./deploy-frontend.sh            # deploy web/ to ce-net.com, print the URL
#   ./deploy-frontend.sh --dev      # live hot-reload upload instead of a one-shot deploy
#   CE_HUB=https://ce-net.com ./deploy-frontend.sh
#
# Prereqs:
#   * ce-app installed/reachable. From this monorepo:  node ~/ce-net/web/ce-app/bin/ce-app.mjs
#     (or `npm i -g ce-app`, or `npx ce-app`). Set CE_APP to override the invocation.
#   * The web/ data plane talks to the USER's LOCAL node (http://localhost:8844 by default,
#     or a browser-node bridge). Browser users reach the mesh via their own local node or a
#     gateway; the deployed static page never hardcodes a foreign node or an api token.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$HERE/web"

# How to invoke ce-app. Prefer an explicit $CE_APP; else a global `ce-app`; else the
# in-repo binary; else npx. (ce-app is used AS-IS — this script never modifies it.)
if [ -n "${CE_APP:-}" ]; then
  CEAPP=( $CE_APP )
elif command -v ce-app >/dev/null 2>&1; then
  CEAPP=( ce-app )
elif [ -f "$HERE/../web/ce-app/bin/ce-app.mjs" ]; then
  CEAPP=( node "$HERE/../web/ce-app/bin/ce-app.mjs" )
else
  CEAPP=( npx --yes ce-app )
fi

MODE="deploy"
if [ "${1:-}" = "--dev" ]; then MODE="dev"; fi

echo "ce-gov frontend deploy"
echo "  web dir : $WEB_DIR"
echo "  ce-app  : ${CEAPP[*]}"
echo "  hub     : ${CE_HUB:-https://ce-net.com}"
echo "  mode    : $MODE"
echo

# Resolve this machine's nodeprefix/id (no network) so we can suggest the slug + final host.
NODEPREFIX="$(${CEAPP[@]} whoami 2>/dev/null | awk '/nodeprefix/{print $NF; exit}')" || true
SLUG="gov${NODEPREFIX:+-$NODEPREFIX}"

echo "Step 1/2 — deploy the static frontend (state + comms stay on the mesh):"
echo "    (cd \"$WEB_DIR\" && ${CEAPP[*]} $MODE)"
( cd "$WEB_DIR" && "${CEAPP[@]}" "$MODE" )

cat <<EOF

Step 2/2 (optional) — claim a human-readable host so the app is reachable at
    https://${SLUG}.ce-net.com/
instead of the raw id host. ce-app slugs are first-class:

    (cd "$WEB_DIR" && ${CEAPP[*]} slug claim ${SLUG})
    (cd "$WEB_DIR" && ${CEAPP[*]} slug status)

Done. The frontend is the ONLY HTTP surface. Everything the app DOES — proposals, votes,
verdicts, policy resolution, validator queries — flows over the mesh via each visitor's
LOCAL node (see docs/mesh-backend.md). No hub /db, no hub /rt, no app backend.
EOF
