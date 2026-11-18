#!/bin/sh
# Infisical SDK test bootstrap (GRO-1369). POSIX sh + curl only (image curlimages/curl:8.23.0).
#
# 1. waits for GET /api/status,
# 2. claims the instance admin exactly like the platform `infisical-bootstrap` job
#    (POST /api/v1/admin/bootstrap, then requires POST /api/v3/auth/login with the same
#    credentials to return 200),
# 3. prepares the SDK test data with the bootstrap's "Instance Admin Identity" token
#    (org admin, non-expiring token auth): project `sdk-test`, extra environment `test`,
#    folders, a seed secret, machine identities (Universal Auth admin, Token Auth viewer,
#    Token Auth without project access), a legacy service token and a user JWT,
# 4. writes KEY=value lines to $BOOTSTRAP_ENV_FILE (default /bootstrap/env, mode 0644).
#
# Idempotent: every created id/credential is cached in $STATE_DIR/state (mode 0600); a re-run
# reuses cached values and only performs the missing steps; a complete env file short-circuits.
# Never prints tokens, secrets or passwords (only HTTP codes and the server's error message).
set -eu

API="${INFISICAL_URL:-http://infisical:8080}/api"
ENV_FILE="${BOOTSTRAP_ENV_FILE:-/bootstrap/env}"
STATE_DIR="$(dirname "$ENV_FILE")/.infisical-bootstrap"
STATE="$STATE_DIR/state"
ADMIN_EMAIL="${INFISICAL_ADMIN_EMAIL:-admin@sdk-test.invalid}"
ORG_NAME="${INFISICAL_ORG_NAME:-SDK Test}"
PROJECT_SLUG="${INFISICAL_PROJECT_SLUG:-sdk-test}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '[infisical-bootstrap] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

if [ -f "$ENV_FILE" ] && grep -q '^INFISICAL_BOOTSTRAP_COMPLETE=1$' "$ENV_FILE"; then
  log "already bootstrapped ($ENV_FILE complete)"; exit 0
fi

mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$STATE"; chmod 600 "$STATE"

# --- tiny state store -------------------------------------------------------------------------
sget() { sed -n "s/^$1=//p" "$STATE" | tail -n 1; }
sput() { printf '%s=%s\n' "$1" "$2" >> "$STATE"; }

# --- JSON helpers (flat string fields only; values never contain quotes here) -----------------
# jstr KEY [FILE]          -> first "KEY":"value"
# jobj OBJ KEY [FILE]      -> "OBJ":{... "KEY":"value"  (first KEY inside OBJ's first-level prefix)
jstr() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "${2:-$TMP/body}" | head -n 1; }
jobjid() { sed -n "s/.*\"$1\":{\"id\":\"\([^\"]*\)\".*/\1/p" "${2:-$TMP/body}" | head -n 1; }
errmsg() { sed -n 's/.*"message":"\([^"]*\)".*/\1/p' "$TMP/body" | head -n 1 | cut -c1-200; }

# api METHOD PATH TOKEN|- [JSON]  -> sets CODE, body in $TMP/body. TOKEN "-" = no Authorization
# header (Infisical rejects login/renew/revoke calls that carry an unrelated bearer token).
api() {
  _m=$1; _p=$2; _t=$3; _b=${4:-}
  set -- -sS -o "$TMP/body" -w '%{http_code}' --max-time 60 -X "$_m" -H 'Accept: application/json' \
    -A 'grow-codes-infisical-bootstrap/1'
  [ "$_t" != "-" ] && set -- "$@" -H "Authorization: Bearer $_t"
  [ -n "$_b" ] && set -- "$@" -H 'Content-Type: application/json' --data-binary "$_b"
  CODE=$(curl "$@" "$API$_p") || CODE=000
}
expect() { # expect "200 400" "what"
  case " $1 " in *" $CODE "*) return 0 ;; esac
  die "$2: HTTP $CODE $(errmsg)"
}

# --- 1. wait for the API ----------------------------------------------------------------------
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API/status" || true)" = 200 ]; do
  i=$((i + 1)); [ "$i" -gt 150 ] && die "GET /api/status not 200 after 300 s"
  sleep 2
done
log "API is up"

# --- 2. claim the instance admin (platform infisical-bootstrap pattern) ------------------------
ADMIN_PASSWORD=$(sget ADMIN_PASSWORD)
if [ -z "$ADMIN_PASSWORD" ]; then
  # policy: >= 14 chars, a letter, a number or special char, no 4 repeated chars
  ADMIN_PASSWORD="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)-9aZ"
  sput ADMIN_PASSWORD "$ADMIN_PASSWORD"
fi
ADMIN_TOKEN=$(sget ADMIN_TOKEN)
if [ -z "$ADMIN_TOKEN" ]; then
  api POST /v1/admin/bootstrap - "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"organization\":\"$ORG_NAME\"}"
  expect 200 "POST /api/v1/admin/bootstrap (instance already initialised by someone else?)"
  ADMIN_TOKEN=$(jstr token); ORG_ID=$(jobjid organization); ORG_SLUG=$(jstr slug)
  [ -n "$ADMIN_TOKEN" ] && [ -n "$ORG_ID" ] && [ -n "$ORG_SLUG" ] || die "unexpected bootstrap response"
  sput ADMIN_TOKEN "$ADMIN_TOKEN"; sput ORG_ID "$ORG_ID"; sput ORG_SLUG "$ORG_SLUG"
  log "instance admin claimed (organization $ORG_SLUG)"
fi
ORG_ID=$(sget ORG_ID); ORG_SLUG=$(sget ORG_SLUG)

# the generated credentials must log in (same check as the platform job)
api POST /v3/auth/login - "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}"
expect 200 "admin login (POST /api/v3/auth/login)"
LOGIN_TOKEN=$(jstr accessToken)
api POST /v3/auth/select-organization "$LOGIN_TOKEN" "{\"organizationId\":\"$ORG_ID\"}"
expect 200 "POST /api/v3/auth/select-organization"
USER_TOKEN=$(jstr token)   # org-scoped user JWT (default lifetime 10 days)
[ -n "$USER_TOKEN" ] || die "no user token"
log "admin login verified"

# --- 3. project, environments, folders, seed secret -------------------------------------------
PROJECT_ID=$(sget PROJECT_ID)
if [ -z "$PROJECT_ID" ]; then
  api GET "/v1/projects/slug/$PROJECT_SLUG" "$ADMIN_TOKEN"
  if [ "$CODE" = 200 ]; then
    PROJECT_ID=$(jstr id)
  else
    api POST /v1/projects "$ADMIN_TOKEN" "{\"projectName\":\"SDK Test\",\"projectDescription\":\"grow-codes-packages/infisical integration tests\",\"slug\":\"$PROJECT_SLUG\"}"
    expect 200 "create project"
    PROJECT_ID=$(jobjid project)
  fi
  [ -n "$PROJECT_ID" ] || die "no project id"
  sput PROJECT_ID "$PROJECT_ID"
fi
log "project $PROJECT_SLUG ready"

# admin user joins the project (personal secrets + secret-version listing need a user JWT)
if [ -z "$(sget USER_MEMBER)" ]; then
  api POST "/v1/projects/$PROJECT_ID/memberships" "$ADMIN_TOKEN" "{\"emails\":[\"$ADMIN_EMAIL\"],\"usernames\":[],\"roleSlugs\":[\"admin\"]}"
  expect "200 400" "add admin user to project"
  sput USER_MEMBER 1
fi

# default environments dev/staging/prod exist; add `test`
api POST "/v1/projects/$PROJECT_ID/environments" "$ADMIN_TOKEN" '{"name":"Test","slug":"test"}'
expect "200 400" "create environment test"

mkfolder() { # env parentPath name
  api POST /v2/folders "$ADMIN_TOKEN" "{\"projectId\":\"$PROJECT_ID\",\"environment\":\"$1\",\"path\":\"$2\",\"name\":\"$3\"}"
  expect "200 400" "create folder $1:$2/$3"
}
mkfolder dev / app
mkfolder dev /app nested
mkfolder staging / common

mksecret() { # env path key value
  api POST "/v4/secrets/$3" "$ADMIN_TOKEN" "{\"projectId\":\"$PROJECT_ID\",\"environment\":\"$1\",\"secretPath\":\"$2\",\"secretValue\":\"$4\",\"secretComment\":\"seeded by bootstrap\"}"
  expect "200 400" "seed secret $1:$2/$3"
}
mksecret dev / SDK_SEED seed-value-1
mksecret staging /common SDK_COMMON common-value-1

# --- 4. machine identities --------------------------------------------------------------------
mkidentity() { # name -> echoes id (cached)
  _id=$(sget "IDENTITY_$1")
  if [ -z "$_id" ]; then
    api POST /v1/identities "$ADMIN_TOKEN" "{\"name\":\"$1\",\"organizationId\":\"$ORG_ID\",\"role\":\"member\"}"
    expect 200 "create identity $1"
    _id=$(jobjid identity); [ -n "$_id" ] || die "no identity id for $1"
    sput "IDENTITY_$1" "$_id"
  fi
  printf '%s' "$_id"
}
add_to_project() { # identityId role
  api POST "/v1/projects/$PROJECT_ID/memberships/identities/$1" "$ADMIN_TOKEN" "{\"role\":\"$2\"}"
  expect "200 400" "add identity to project as $2"
}
token_auth_token() { # identityId cacheKey -> echoes token
  _tok=$(sget "$2")
  if [ -z "$_tok" ]; then
    api POST "/v1/auth/token-auth/identities/$1" "$ADMIN_TOKEN" '{"accessTokenTTL":2592000,"accessTokenMaxTTL":2592000}'
    expect "200 400" "attach token auth"
    api POST "/v1/auth/token-auth/identities/$1/tokens" "$ADMIN_TOKEN" '{"name":"sdk-tests"}'
    expect 200 "create token-auth token"
    _tok=$(jstr accessToken); [ -n "$_tok" ] || die "no token-auth token"
    sput "$2" "$_tok"
  fi
  printf '%s' "$_tok"
}

# 4a. Universal Auth identity, project admin (CRUD incl. environments). Lockout disabled so
#     wrong-secret tests (401) cannot lock the identity out (default: 3 failures -> 300 s lock).
UA_ID=$(mkidentity sdk-universal-auth)
CLIENT_ID=$(sget CLIENT_ID)
if [ -z "$CLIENT_ID" ]; then
  api POST "/v1/auth/universal-auth/identities/$UA_ID" "$ADMIN_TOKEN" '{"accessTokenTTL":300,"accessTokenMaxTTL":3600,"lockoutEnabled":false}'
  expect 200 "attach universal auth"
  CLIENT_ID=$(jstr clientId); [ -n "$CLIENT_ID" ] || die "no clientId"
  sput CLIENT_ID "$CLIENT_ID"
fi
CLIENT_SECRET=$(sget CLIENT_SECRET)
if [ -z "$CLIENT_SECRET" ]; then
  api POST "/v1/auth/universal-auth/identities/$UA_ID/client-secrets" "$ADMIN_TOKEN" '{"description":"sdk-tests"}'
  expect 200 "create client secret"
  CLIENT_SECRET=$(jstr clientSecret); [ -n "$CLIENT_SECRET" ] || die "no clientSecret"
  sput CLIENT_SECRET "$CLIENT_SECRET"
fi
add_to_project "$UA_ID" admin

# 4b. Token Auth identity with project role viewer (read OK, writes -> 403 PermissionDenied)
VIEWER_ID=$(mkidentity sdk-viewer)
VIEWER_TOKEN=$(token_auth_token "$VIEWER_ID" VIEWER_TOKEN)
add_to_project "$VIEWER_ID" viewer

# 4c. Token Auth identity without project membership (-> 403 ProjectMembershipNotFound);
#     also the target for Kubernetes/AWS login negative tests (auth method not configured -> 404)
NOACCESS_ID=$(mkidentity sdk-no-access)
NOACCESS_TOKEN=$(token_auth_token "$NOACCESS_ID" NOACCESS_TOKEN)

# --- 5. legacy service token (st.<id>.<secret>), read/write on dev:/ ---------------------------
SERVICE_TOKEN=$(sget SERVICE_TOKEN)
if [ -z "$SERVICE_TOKEN" ]; then
  api POST /v2/service-token "$USER_TOKEN" "{\"name\":\"sdk-tests\",\"workspaceId\":\"$PROJECT_ID\",\"scopes\":[{\"environment\":\"dev\",\"secretPath\":\"/\"}],\"encryptedKey\":\"unused\",\"iv\":\"unused\",\"tag\":\"unused\",\"expiresIn\":null,\"permissions\":[\"read\",\"write\"]}"
  expect 200 "create service token"
  SERVICE_TOKEN=$(jstr serviceToken); [ -n "$SERVICE_TOKEN" ] || die "no service token"
  sput SERVICE_TOKEN "$SERVICE_TOKEN"
fi

# --- 6. env file ------------------------------------------------------------------------------
umask 022
{
  echo "# written by docker/bootstrap/bootstrap.sh - disposable test credentials"
  echo "INFISICAL_API_URL=${INFISICAL_URL:-http://infisical:8080}"
  echo "INFISICAL_ORG_ID=$ORG_ID"
  echo "INFISICAL_ORG_SLUG=$ORG_SLUG"
  echo "INFISICAL_PROJECT_ID=$PROJECT_ID"
  echo "INFISICAL_PROJECT_SLUG=$PROJECT_SLUG"
  echo "INFISICAL_ENVIRONMENT=dev"
  echo "INFISICAL_ENVIRONMENT_STAGING=staging"
  echo "INFISICAL_ENVIRONMENT_EXTRA=test"
  echo "INFISICAL_CLIENT_ID=$CLIENT_ID"
  echo "INFISICAL_CLIENT_SECRET=$CLIENT_SECRET"
  echo "INFISICAL_IDENTITY_ID=$UA_ID"
  echo "INFISICAL_VIEWER_IDENTITY_ID=$VIEWER_ID"
  echo "INFISICAL_VIEWER_TOKEN=$VIEWER_TOKEN"
  echo "INFISICAL_NOACCESS_IDENTITY_ID=$NOACCESS_ID"
  echo "INFISICAL_NOACCESS_TOKEN=$NOACCESS_TOKEN"
  echo "INFISICAL_SERVICE_TOKEN=$SERVICE_TOKEN"
  echo "INFISICAL_USER_TOKEN=$USER_TOKEN"
  echo "INFISICAL_USER_EMAIL=$ADMIN_EMAIL"
  echo "INFISICAL_ADMIN_TOKEN=$ADMIN_TOKEN"
  echo "INFISICAL_SEED_SECRET_NAME=SDK_SEED"
  echo "INFISICAL_SEED_SECRET_VALUE=seed-value-1"
  echo "INFISICAL_EXPECTED_SERVER_VERSION=v0.167.10"
  echo "INFISICAL_BOOTSTRAP_COMPLETE=1"
} > "$ENV_FILE.tmp"
chmod 0644 "$ENV_FILE.tmp"
mv "$ENV_FILE.tmp" "$ENV_FILE"
log "wrote $ENV_FILE ($(grep -c '=' "$ENV_FILE") keys)"
