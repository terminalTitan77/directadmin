#!/bin/bash
# DirectAdmin-only read-only server audit, version 1.0.0, 2026-10-05.
# Bash 4+ and existing Linux utilities only. No installs, upgrades, config/service changes or scans.
# Output is stdout in the same [ITEM]/[STATUS]/[ISSUE]/[RECOMMENDATION] format the Bob_Portal extension reads.
# Every item (including ACTIVE/GOOD/Configured ones) carries an ISSUE that says WHY the status was
# chosen and WHAT data was read, plus a RECOMMENDATION written from what was found on this server.
# Not tested on a live DirectAdmin host by the author: DirectAdmin file formats were taken from DirectAdmin
# documentation/forums. Treat UNVERIFIED/NA items as "check by hand".

if (( BASH_VERSINFO[0] < 4 )); then printf 'ERROR: Bash 4 or newer is required.\n' >&2; exit 2; fi
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -o pipefail
shopt -s nullglob

usage() {
cat <<'HELP'
DIRECTADMIN READ-ONLY SERVER AUDIT 1.0.0

Run: sudo bash directadmin_audit_readonly.sh [options]

  --offline                  No DNS or HTTPS lookups (panel/IP-reputation/rDNS/version checks become NA)
  --no-package-check         Skip yum/dnf/apt update-availability queries
  --ip IPv4                  Public/mail IPv4 to audit (use for NAT/multiple IPs)
  --http-url URL              Optional HTTP(S) HEAD check; repeatable
  --webroot /abs/path         CMS discovery root; repeatable (default /home)
  --backup-dir /abs/path      Extra backup artifact root; repeatable
  --expected-backup-bytes N   Minimum acceptable size of the latest backup
  --report /abs/path          Existing scan report (default /root/scripts/malware-scan-report.txt)
  --max-report-days N         Maximum scan-report age, default 20
  --backup-max-days N         Recent-backup threshold, default 2
  --cpu-max N  --ram-max N  --disk-max N   Percent thresholds, default 85
  --queue-max N               Mail queue threshold, default 100
  --force                     Run even if /usr/local/directadmin/directadmin is missing
  --help

DirectAdmin data read (read-only): `directadmin v`, `da config-get update_channel|autoupdate`,
DNS TXT <channel>-version.directadmin.com (latest version), custombuild/options.conf,
`custombuild/build versions` (installed vs latest software, if present), conf/directadmin.conf
(only brute_force_* keys), data/admin/backup_crons.list (schedule fields only; FTP user/password are
never read into output), /etc/cron.d/directadmin_cron and the diradmin crontab (to confirm a backup
job is really scheduled), data/users/*/domains/*.conf (php=ON and php1_select, to find which PHP
versions sites actually use), /usr/local/php*/lib/php.ini + php.conf.d + php-fpm pool overrides.

Exit 0: audit completed (may include UNVERIFIED/NA items). Exit 2: invalid options/not root/not DirectAdmin.
HELP
}

OFFLINE=0; NO_PACKAGE_CHECK=0; TARGET_IP=''; SCAN_REPORT=/root/scripts/malware-scan-report.txt
MAX_REPORT_DAYS=20; BACKUP_MAX_DAYS=2; CPU_MAX=85; RAM_MAX=85; DISK_MAX=85
QUEUE_MAX=100; EXPECTED_BACKUP_BYTES=0; FORCE=0
WEBROOTS=(); BACKUP_DIRS=(); HTTP_URLS=()
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
need_value() { (( $# >= 2 )) && [[ -n $2 ]] || die "Missing value for $1"; }
uint() { [[ $1 =~ ^[0-9]{1,12}$ ]] && [[ $1 == 0 || $1 != 0* ]]; }
while (( $# )); do
    case "$1" in
        --help|-h) usage; exit 0;;
        --offline) OFFLINE=1; shift;;
        --no-package-check) NO_PACKAGE_CHECK=1; shift;;
        --force) FORCE=1; shift;;
        --ip) need_value "$@"; TARGET_IP=$2; shift 2;;
        --http-url) need_value "$@"; [[ $2 =~ ^https?://[^[:space:]]+$ ]] || die 'Invalid HTTP URL'; HTTP_URLS+=("$2"); shift 2;;
        --webroot) need_value "$@"; [[ $2 == /* && -d $2 && ! -L $2 ]] || die 'Webroot must be an existing absolute non-symlink directory'; WEBROOTS+=("$2"); shift 2;;
        --backup-dir) need_value "$@"; [[ $2 == /* && -d $2 && ! -L $2 ]] || die 'Backup root must be an existing absolute non-symlink directory'; BACKUP_DIRS+=("$2"); shift 2;;
        --report) need_value "$@"; [[ $2 == /* ]] || die 'Report path must be absolute'; SCAN_REPORT=$2; shift 2;;
        --max-report-days|--backup-max-days|--cpu-max|--ram-max|--disk-max|--queue-max|--expected-backup-bytes)
            need_value "$@"; uint "$2" || die "Invalid integer for $1"
            case "$1" in
                --max-report-days) MAX_REPORT_DAYS=$2;; --backup-max-days) BACKUP_MAX_DAYS=$2;;
                --cpu-max) CPU_MAX=$2;; --ram-max) RAM_MAX=$2;; --disk-max) DISK_MAX=$2;;
                --queue-max) QUEUE_MAX=$2;; --expected-backup-bytes) EXPECTED_BACKUP_BYTES=$2;;
            esac; shift 2;;
        *) die "Unknown option: $1 (use --help)";;
    esac
done
(( EUID == 0 )) || die 'Run as root.'
DA_DIR=/usr/local/directadmin
[[ -x $DA_DIR/directadmin ]] || (( FORCE )) || die 'DirectAdmin not found at /usr/local/directadmin. This script is DirectAdmin-only (use server_audit_readonly.sh for other servers, or --force).'
for dep in awk sed grep find stat date timeout sort head tail tr cut cat sleep; do
    command -v "$dep" >/dev/null 2>&1 || die "Required utility missing: $dep"
done
for pct in "$CPU_MAX" "$RAM_MAX" "$DISK_MAX"; do (( pct > 0 && pct <= 100 )) || die 'Percent thresholds must be 1..100'; done
(( ${#WEBROOTS[@]} )) || WEBROOTS=(/home)
BACKUP_DIRS+=(/home/admin/admin_backups /backup /backups /var/backups)
NOW=$(date +%s); TODAY=$(date -u +%F)

have() { command -v "$1" >/dev/null 2>&1; }
run() { timeout -k 2s 15s "$@" 2>/dev/null; }
flat() { tr '\n\r\t' '   ' | tr -cd '\40-\176' | tr -s ' ' | cut -c 1-6000; }
emit() {
    printf '[ITEM] : %s\n[STATUS] : %s\n[ISSUE] : %s\n[RECOMMENDATION] : %s\n\n' \
        "$1" "$2" "$(printf '%s' "$3" | flat)" "$(printf '%s' "$4" | flat)"
}
section() { printf '\nSECTION %s\n%s\n\n' "$1" '============================================================'; }
active() {
    local n
    for n in "$@"; do
        if have systemctl && [[ -d /run/systemd/system ]] && run systemctl is-active --quiet "$n"; then return 0; fi
        if have pgrep && run pgrep -x "$n" >/dev/null; then return 0; fi
    done
    return 1
}
version_le() {
    [[ $1 =~ ^[0-9]+(\.[0-9]+){1,3}$ && $2 =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || return 2
    [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1) == "$1" ]]
}
first_ver() { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' | head -n 1; }
os_value() { awk -F= -v k="$1" '$1==k {v=substr($0,index($0,"=")+1); gsub(/^"|"$/,"",v); print v; exit}' /etc/os-release 2>/dev/null; }
cbopt() { awk -F= -v k="$1" '$1==k {v=$2; gsub(/[[:space:]\r"]/,"",v); print v; exit}' "$DA_DIR/custombuild/options.conf" 2>/dev/null; }
dacfg() { awk -F= -v k="$1" '$1==k {v=$2; gsub(/[[:space:]\r"]/,"",v); print v; exit}' "$DA_DIR/conf/directadmin.conf" 2>/dev/null; }

OS_ID=$(os_value ID); OS_VERSION=$(os_value VERSION_ID); OS_NAME=$(os_value PRETTY_NAME)
[[ -n $OS_NAME ]] || OS_NAME=$(head -c 300 /etc/redhat-release 2>/dev/null)
KERNEL=$(run uname -r); HOST=$(run hostname)

# ---------------------------------------------------------------- DirectAdmin facts
da_raw=$(run "$DA_DIR/directadmin" v)
DA_VER=$(printf '%s\n' "$da_raw" | sed -nE 's/.*[Vv]ersion[: ]+v?([0-9][0-9.]*).*/\1/p' | head -n 1)
[[ -n $DA_VER ]] || DA_VER=$(printf '%s\n' "$da_raw" | first_ver)
DA_CHANNEL=''; DA_AUTOUPDATE=''
if have da; then
    DA_CHANNEL=$(run da config-get update_channel | sed -E 's/.*[= ]//' | tr -cd 'a-z')
    DA_AUTOUPDATE=$(run da config-get autoupdate | sed -E 's/.*[= ]//' | tr -cd '0-9')
fi
[[ -n $DA_CHANNEL ]] || DA_CHANNEL=stable
CB_WEBSERVER=$(cbopt webserver); CB_MODSEC=$(cbopt modsecurity); CB_RULESET=$(cbopt modsecurity_ruleset); CB_CLAMAV=$(cbopt clamav)

# ---------------------------------------------------------------- package inventory
PKGS=''; PKG_KIND=unknown; PKG_QUERY_OK=0
if have rpm; then
    raw=$(timeout -k 2s 60s rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null)
    PKGS=$(printf '%s\n' "$raw" | awk -F '\t' 'NF==3 && $1 ~ /^[A-Za-z0-9_+.-]+$/ {e=$2;if(e=="(none)")e=0;print $1 "\t" e ":" $3}')
    [[ -n $PKGS ]] && { PKG_KIND=rpm; PKG_QUERY_OK=1; }
fi
if [[ $PKG_QUERY_OK == 0 ]] && have dpkg-query; then
    raw=$(timeout -k 2s 60s dpkg-query -W '-f=${db:Status-Status}\t${binary:Package}\t${Version}\n' 2>/dev/null)
    PKGS=$(printf '%s\n' "$raw" | awk -F '\t' '$1=="installed" {print $2 "\t" $3}')
    [[ -n $PKGS ]] && { PKG_KIND=deb; PKG_QUERY_OK=1; }
fi
pkgmatch() { printf '%s\n' "$PKGS" | awk -F '\t' -v re="$1" '$1 ~ re {print}'; }

# ---------------------------------------------------------------- network helpers
fetch_metadata() {
    (( OFFLINE )) && return 1
    have curl || return 1
    timeout -k 2s 22s curl -q -f -sS --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 20 --max-filesize 2097152 -- "$1" 2>/dev/null
}
json_version() { grep -oE '"'"$1"'"[[:space:]]*:[[:space:]]*"[0-9]+(\.[0-9]+){1,3}"' | head -n 1 | sed -E 's/.*:[[:space:]]*"([0-9.]+)"/\1/'; }
dns_query() { run dig +time=3 +tries=1 +noall +comments +answer "$@"; }
dns_code() { sed -nE 's/.*status: ([A-Z]+),.*/\1/p' | head -n 1; }
dns_a() { awk '$4=="A" {print $5}'; }

public_v4() {
    local a b c d tail
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d tail <<< "$1"
    a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))
    (( a<=255 && b<=255 && c<=255 && d<=255 )) || return 1
    (( a>0 && a<224 && a!=10 && a!=127 )) || return 1
    (( a==169 && b==254 || a==172 && b>=16 && b<=31 || a==192 && b==168 || a==100 && b>=64 && b<=127 )) && return 1
    (( a==192 && b==0 || a==198 && (b==18 || b==19 || b==51) || a==203 && b==0 && c==113 )) && return 1
    return 0
}
if [[ -n $TARGET_IP ]]; then public_v4 "$TARGET_IP" || die '--ip must be a public IPv4 address'; fi
ips=()
if have ip; then
    while read -r v; do public_v4 "$v" && ips+=("$v"); done < <(run ip -o -4 addr show scope global | awk '{split($4,a,"/");print a[1]}' | sort -u)
fi
IP_NOTE='Explicit --ip supplied.'; IP_MISMATCH=0
if [[ -n $TARGET_IP ]] && ! printf '%s\n' "${ips[@]}" | grep -Fxq "$TARGET_IP"; then
    IP_NOTE='WARNING: --ip is not assigned to a detected public interface (NAT?).'; IP_MISMATCH=1
fi
if [[ -z $TARGET_IP ]]; then
    da_ip=$(awk -F= '$1=="ip" {print $2; exit}' "$DA_DIR/scripts/setup.txt" 2>/dev/null | tr -cd '0-9.')
    if [[ -n $da_ip ]] && public_v4 "$da_ip" && printf '%s\n' "${ips[@]}" | grep -Fxq "$da_ip"; then
        TARGET_IP=$da_ip; IP_NOTE='Main IP read from DirectAdmin setup.txt (ip= key only) and matched to a local interface.'
    elif (( ${#ips[@]} == 1 )); then TARGET_IP=${ips[0]}; IP_NOTE='Single public interface IP selected.'
    else IP_NOTE="UNVERIFIED: ${#ips[@]} public IPv4 addresses found; use --ip for the main/mail IP."; fi
fi

# ---------------------------------------------------------------- scan report (malware / rootkit)
REPORT_TEXT=''; REPORT_FRESH=0; REPORT_INFO='Scan report missing, unreadable or a symlink.'
MALWARE_RESULT=unknown; ROOTKIT_RESULT=unknown
if [[ -f $SCAN_REPORT && -r $SCAN_REPORT && ! -L $SCAN_REPORT ]]; then
    mtime=$(stat -c %Y -- "$SCAN_REPORT" 2>/dev/null); rsize=$(stat -c %s -- "$SCAN_REPORT" 2>/dev/null)
    if [[ $mtime =~ ^[0-9]+$ && $rsize =~ ^[0-9]+$ ]]; then
        age=$((NOW-mtime)); REPORT_INFO="Scan report $SCAN_REPORT age=$((age/86400)) days; bytes=$rsize."
        if (( age >= 0 && age <= MAX_REPORT_DAYS*86400 && rsize > 0 && rsize <= 20971520 )); then
            REPORT_TEXT=$(run cat -- "$SCAN_REPORT"); REPORT_FRESH=1
        else REPORT_INFO+=' Rejected: stale/future/empty/over 20 MiB.'; fi
    fi
fi
summary_num() { printf '%s\n' "$2" | awk -v re="$1" 'BEGIN{re=tolower(re);n=-1} tolower($0) ~ re {v=$0;sub(/^[^:]*:[[:space:]]*/,"",v);sub(/[[:space:]]*$/,"",v);if(v ~ /^[0-9]+$/ && v+0>n)n=v+0} END{if(n>=0)print n}'; }
text_has() { printf '%s\n' "$2" | grep -Eiq -- "$1"; }
if (( REPORT_FRESH )); then
    if text_has '^[[:space:]]*Rootkit Scan Report' "$REPORT_TEXT"; then
        MALWARE_TEXT=$(printf '%s\n' "$REPORT_TEXT" | awk 'tolower($0) ~ /^[[:space:]]*rootkit scan report/ {exit} {print}')
        ROOTKIT_TEXT=$(printf '%s\n' "$REPORT_TEXT" | awk 'f || tolower($0) ~ /^[[:space:]]*rootkit scan report/ {f=1; print}')
    else MALWARE_TEXT=$REPORT_TEXT; ROOTKIT_TEXT=$REPORT_TEXT; fi
    mi=$(summary_num '^[[:space:]]*(Infected files|MALWARE_INFECTED_FILES)[[:space:]]*:' "$MALWARE_TEXT")
    mc=$(summary_num '^[[:space:]]*(Scanned files|MALWARE_FILES_SCANNED)[[:space:]]*:' "$MALWARE_TEXT")
    ri=$(summary_num '^[[:space:]]*(Possible rootkits|ROOTKIT_FOUND)[[:space:]]*:' "$ROOTKIT_TEXT")
    rc=$(summary_num '^[[:space:]]*(Files checked|Rootkits checked|ROOTKIT_CHECKS_PERFORMED)[[:space:]]*:' "$ROOTKIT_TEXT")
    merr=0; rerr=0
    text_has '(^|[[:space:]])(ERROR|FAILED|ABORTED|WARNING)(:|[[:space:]]|$)' "$MALWARE_TEXT" && merr=1
    text_has '(^|[[:space:]])(ERROR|FAILED|ABORTED|WARNING)(:|[[:space:]]|$)' "$ROOTKIT_TEXT" && rerr=1
    if [[ $mi =~ ^[0-9]+$ ]] && (( mi > 0 )); then MALWARE_RESULT=found
    elif [[ $mi == 0 && $mc =~ ^[0-9]+$ ]] && (( mc > 0 && merr == 0 )) &&
         text_has 'SCAN SUMMARY|^MALWARE_SCAN_COMPLETED:[[:space:]]*YES' "$MALWARE_TEXT"; then MALWARE_RESULT=clean; fi
    if [[ $ri =~ ^[0-9]+$ ]] && (( ri > 0 )); then ROOTKIT_RESULT=found
    elif [[ $ri == 0 && $rc =~ ^[0-9]+$ ]] && (( rc > 0 && rerr == 0 )) &&
         text_has 'System checks summary|^ROOTKIT_SCAN_COMPLETED:[[:space:]]*YES|^[[:space:]]*Rootkits checked[[:space:]]*:' "$ROOTKIT_TEXT"; then ROOTKIT_RESULT=clean; fi
    text_has '^[[:space:]]*Checking.*INFECTED' "$ROOTKIT_TEXT" && ROOTKIT_RESULT=found
    text_has '^/[^:]+: .+ FOUND[[:space:]]*$' "$MALWARE_TEXT" && MALWARE_RESULT=found
fi

# ---------------------------------------------------------------- CMS discovery (DirectAdmin layout /home/USER/domains/DOMAIN/public_html)
CMS_LIST=''; CMS_PARTIAL=0
for root in "${WEBROOTS[@]}"; do
    [[ -d $root ]] || continue
    files=$(timeout -k 2s 45s find "$root" -xdev -maxdepth 12 \
        \( -type d \( -name node_modules -o -name .git -o -name cache -o -name vendor -o -name backups -o -name admin_backups -o -name .trash \) -prune \) -o \
        \( -type f \( -path '*/wp-includes/version.php' -o -path '*/core/lib/Drupal.php' -o -path '*/administrator/manifests/files/joomla.xml' -o -name version.php \) -print \) 2>/dev/null)
    (( $? == 0 )) || CMS_PARTIAL=1
    while IFS= read -r file; do
        [[ -n $file ]] || continue
        ver=''; product=''
        case "$file" in
            */wp-includes/version.php) product=wordpress; ver=$(sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */core/lib/Drupal.php) product=drupal; ver=$(sed -nE "s/.*const VERSION[[:space:]]*=[[:space:]]*['\"]([0-9.]+)['\"].*/\1/p" "$file" | head -n 1);;
            */administrator/manifests/files/joomla.xml) product=joomla; ver=$(sed -nE 's/.*<version>([0-9.]+)<\/version>.*/\1/p' "$file" | head -n 1);;
            */version.php) [[ -f ${file%/*}/lib/moodlelib.php ]] && { product=moodle; ver=$(sed -nE "s/^[[:space:]]*\\\$release[[:space:]]*=[[:space:]]*['\"]([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p" "$file" | head -n 1); };;
        esac
        [[ -n $product && -n $ver ]] && CMS_LIST+="$product"$'\t'"$ver"$'\t'"$file"$'\n'
    done <<< "$files"
done
CMS_LIST=$(printf '%s' "$CMS_LIST" | sort -u)
site_of() { printf '%s' "$1" | sed -nE 's#.*/domains/([^/]+)/.*#\1#p'; }

# ---------------------------------------------------------------- PHP installed by CustomBuild + which are in use
declare -A PHP_REL_DIR PHP_REL_MODE
PHP_LIST=''
for i in 1 2 3 4; do
    rel=$(cbopt "php${i}_release"); [[ $rel =~ ^[0-9]+\.[0-9]+$ ]] || continue
    dir=/usr/local/php${rel//./}; PHP_REL_DIR[$i]=$dir; PHP_REL_MODE[$i]=$(cbopt "php${i}_mode")
    if [[ -x $dir/bin/php ]]; then
        pv=$(run "$dir/bin/php" -n -v | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1)
        [[ -n $pv ]] && PHP_LIST+="$pv"$'\t'"$dir/bin/php"$'\t'"$i"$'\n'
    fi
done
if [[ -z $PHP_LIST ]]; then
    for bin in /usr/local/php[0-9]*/bin/php; do
        pv=$(run "$bin" -n -v | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1)
        [[ -n $pv ]] && PHP_LIST+="$pv"$'\t'"$bin"$'\t'"?"$'\n'
    done
fi
PHP_LIST=$(printf '%s' "$PHP_LIST" | sort -u)
PHP_DOMAIN_MAP=''; PHP_INUSE_IDX=''
for f in "$DA_DIR"/data/users/*/domains/*.conf; do
    [[ -f $f ]] || continue
    grep -qiE '^php=ON' "$f" || continue
    sel=$(sed -nE 's/^php1_select=([0-9]+).*/\1/p' "$f" | head -n 1); sel=${sel:-1}
    PHP_DOMAIN_MAP+="$(basename "$f" .conf)"$'\t'"$sel"$'\n'
done
PHP_INUSE_IDX=$(printf '%s' "$PHP_DOMAIN_MAP" | cut -f2 | sort -u)
php_eol() {
    local branch=${1%.*} end=''
    case "$branch" in
        5.*|7.*|8.0|8.1) printf 'End Of Life Period'; return;;
        8.2) end=2026-12-31;; 8.3) end=2027-12-31;; 8.4) end=2028-12-31;; 8.5) end=2029-12-31;;
        *) printf NA; return;;
    esac
    if [[ $TODAY > $end ]]; then printf 'End Of Life Period'; else printf 'Support Period Active'; fi
}

# ---------------------------------------------------------------- CustomBuild installed-vs-latest
CB_ROWS=''; CB_NOTE='CustomBuild versions check not run.'
if (( ! OFFLINE && ! NO_PACKAGE_CHECK )) && [[ -x $DA_DIR/custombuild/build ]]; then
    cb_out=$(cd "$DA_DIR/custombuild" && timeout -k 5s 120s ./build versions 2>&1); cb_rc=$?
    CB_ROWS=$(printf '%s\n' "$cb_out" | awk '
        /^[Ii]nstalled version of /{s=$0;sub(/^[Ii]nstalled version of /,"",s);i=index(s,": ");if(i){n=substr(s,1,i-1);inst[n]=substr(s,i+2)}}
        /^[Ll]atest version of /{s=$0;sub(/^[Ll]atest version of /,"",s);i=index(s,": ");if(i){n=substr(s,1,i-1);lat[n]=substr(s,i+2)}}
        END{for(n in lat)print n "\t" inst[n] "\t" lat[n]; for(n in inst) if(!(n in lat)) print n "\t" inst[n] "\t"}')
    CB_NOTE="CustomBuild 'build versions' exit=$cb_rc; rows parsed=$(printf '%s\n' "$CB_ROWS" | awk 'NF{n++}END{print n+0}')."
    unset cb_out
elif (( OFFLINE || NO_PACKAGE_CHECK )); then CB_NOTE='CustomBuild versions check skipped (--offline/--no-package-check).'
else CB_NOTE='custombuild/build not found (newer DirectAdmin or non-CustomBuild install); CustomBuild comparison unavailable.'; fi
# group status: pending / equal / unknown counts for rows whose name matches a regex
cb_group() {
    CBG_PEND=0; CBG_EQ=0; CBG_UNK=0; CBG_EV=''
    local n i l
    while IFS=$'\t' read -r n i l; do
        [[ -n $n ]] || continue
        printf '%s' "$n" | grep -Eiq "$1" || continue
        [[ -z $i || $i =~ ^([Nn]o|none|-|not.*)$ ]] && continue
        if [[ -n $l && $i == "$l" ]]; then ((CBG_EQ++)); CBG_EV+="$n installed=$i (latest); "
        elif [[ -n $l ]]; then ((CBG_PEND++)); CBG_EV+="$n installed=$i latest=$l; "
        else ((CBG_UNK++)); CBG_EV+="$n installed=$i latest=unknown; "; fi
    done <<< "$CB_ROWS"
}

# ---------------------------------------------------------------- OS package update query (query only)
RPM_UPDATES=''; RPM_CHECK_OK=0; RPM_CHECK_NOTE='Package update query not run.'; RPM_MANAGER=''
if [[ $PKG_KIND == rpm && $NO_PACKAGE_CHECK == 0 ]]; then
    have dnf && RPM_MANAGER=dnf; [[ -n $RPM_MANAGER ]] || { have yum && RPM_MANAGER=yum; }
    if [[ -n $RPM_MANAGER ]]; then
        opts=(--setopt=history_record=false --setopt=skip_if_unavailable=false)
        (( OFFLINE )) && opts=(-C --noplugins "${opts[@]}")
        [[ $RPM_MANAGER == yum ]] && opts+=(--setopt=logfile=/dev/null)
        update_raw=$(timeout -k 2s 90s "$RPM_MANAGER" "${opts[@]}" -q check-update 2>&1); urc=$?
        if (( urc==0 || urc==100 )); then
            RPM_UPDATES=$(printf '%s\n' "$update_raw" | awk '$1 ~ /\.(x86_64|i[3-6]86|noarch|aarch64)$/ && NF>=3 && $2 ~ /^[0-9]/ {n=$1;sub(/\.[^.]+$/,"",n);print n "\t" $2}')
            RPM_CHECK_OK=1
            RPM_CHECK_NOTE="$RPM_MANAGER check-update ok (exit=$urc), update candidates=$(printf '%s\n' "$RPM_UPDATES" | awk 'NF{n++}END{print n+0}')."
        else RPM_CHECK_NOTE="UNVERIFIED: $RPM_MANAGER check-update failed (exit=$urc)."; fi
        unset update_raw
    fi
fi
APT_PENDING=''; APT_OK=0; APT_NOTE=''
if [[ $PKG_KIND == deb && $NO_PACKAGE_CHECK == 0 ]] && have apt-get; then
    sim=$(timeout -k 2s 60s apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null); src=$?
    if (( src==0 )); then
        APT_PENDING=$(printf '%s\n' "$sim" | awk '/^Inst /{print $2 "\t" $3}'); APT_OK=1
        APT_NOTE="apt-get -s upgrade simulation ok; upgradable packages=$(printf '%s\n' "$APT_PENDING" | awk 'NF{n++}END{print n+0}') (based on last apt update)."
    else APT_NOTE='UNVERIFIED: apt-get -s upgrade failed.'; fi
fi
pending_match() { # regex -> matching package names with pending update
    if [[ $PKG_KIND == rpm ]]; then printf '%s\n' "$RPM_UPDATES" | awk -F '\t' -v re="$1" '$1 ~ re {print $1}'
    elif [[ $PKG_KIND == deb ]]; then printf '%s\n' "$APT_PENDING" | awk -F '\t' -v re="$1" '$1 ~ re {print $1}'; fi
}
pkg_check_ok() { [[ $PKG_KIND == rpm && $RPM_CHECK_OK == 1 ]] || [[ $PKG_KIND == deb && $APT_OK == 1 ]]; }

# KernelCare
kcare=0
if have kcarectl && run kcarectl --info | grep -q 'kpatch-state: patch is applied'; then kcare=1; fi

# OS standard-support flag
OS_STANDARD_EOL=0
case "$OS_ID:$OS_VERSION" in
    cloudlinux:7|cloudlinux:7.*|centos:7|centos:7.*) [[ $TODAY > 2024-06-30 ]] && OS_STANDARD_EOL=1;;
    centos:8|centos:8.*) [[ $OS_NAME != *Stream* ]] && OS_STANDARD_EOL=1;;
    almalinux:7*|rocky:7*|rhel:7*|ol:7*) OS_STANDARD_EOL=1;;
    ubuntu:14.04|ubuntu:16.04|ubuntu:18.04|ubuntu:20.04) OS_STANDARD_EOL=1;;
    debian:9|debian:9.*|debian:10|debian:10.*) OS_STANDARD_EOL=1;;
    debian:11|debian:11.*) [[ $TODAY > 2026-08-31 ]] && OS_STANDARD_EOL=1;;
esac

# ---------------------------------------------------------------- header
printf 'DIRECTADMIN READ-ONLY SERVER AUDIT 1.0.0 | %s UTC\n' "$(date -u '+%F %T')"
printf 'Host: %s | OS: %s | Kernel: %s | Panel: directadmin %s\n' "$HOST" "$OS_NAME" "$KERNEL" "${DA_VER:-unknown}"
printf 'Target IPv4: %s | %s\n' "${TARGET_IP:-unverified}" "$IP_NOTE"
printf 'Update channel: %s | %s | %s\n' "$DA_CHANNEL" "$CB_NOTE" "$RPM_CHECK_NOTE $APT_NOTE"
printf 'Read-only: nothing installed, changed, scanned or restarted. Package/CustomBuild query tools may write their own cache/log files.\n'

OFFPEAK='Please share your preferred date and time (with time zone) for an off-peak maintenance window; we will take a fresh backup first, apply the changes, and validate sites afterwards.'

# ================================================================ A
section 'A : Threat Protection'

ipt_out=''; ipt_ok=0
if have iptables; then ipt_out=$(run iptables -S); (( $? == 0 )) && ipt_ok=1; fi
restrict_rules=$(printf '%s\n' "$ipt_out" | grep -Ec -- '^-P INPUT (DROP|REJECT)|^-A [A-Za-z0-9_-]+ .*-j (DROP|REJECT)')
nft_restrict=0
if have nft; then nft_restrict=$(run nft list ruleset | grep -Ec 'policy drop|[[:space:];](drop|reject)([[:space:];]|$)'); fi

fw_enf=''; fw_other=''
if [[ -d /etc/csf ]] || have csf; then
    csf_t=0; [[ -r /etc/csf/csf.conf ]] && grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"?1' /etc/csf/csf.conf && csf_t=1
    csf_chain=0; printf '%s\n' "$ipt_out" | grep -Eq '^-N (LOCALINPUT|ALLOWIN|DENYIN)' && csf_chain=1
    if [[ ! -e /etc/csf/csf.disable ]] && (( csf_t==0 )) && { (( csf_chain )) || { (( ! ipt_ok )) && active lfd; }; }; then
        fw_enf+="CSF (installed, not disabled, TESTING off, CSF chains loaded=$csf_chain, LFD running=$(active lfd && echo yes || echo no)); "
    else fw_other+="CSF installed but not enforcing (disabled marker=$([[ -e /etc/csf/csf.disable ]] && echo yes || echo no), TESTING=$csf_t, chains loaded=$csf_chain); "; fi
fi
if [[ -d /etc/apf ]] || have apf; then
    if [[ -r /etc/apf/conf.apf ]] && grep -Eq '^DEVEL_MODE="?0' /etc/apf/conf.apf && printf '%s\n' "$ipt_out" | grep -Eq 'TALLOW|TDENY|GALLOW|GDENY|PROHIBIT|IN_SANITY'; then
        fw_enf+='APF (DEVEL_MODE=0 and APF chains loaded); '
    else fw_other+='APF installed but not confirmed enforcing; '; fi
fi
if have firewall-cmd && active firewalld; then fw_enf+="firewalld (running, state=$(run firewall-cmd --state)); "; fi
if have ufw && run ufw status | grep -qi '^Status: active'; then fw_enf+='UFW (status active); '; fi
if [[ -z $fw_enf ]] && { (( restrict_rules > 0 )) || (( nft_restrict > 0 )); }; then
    fw_enf+="iptables/nftables ruleset with restrictive rules (iptables DROP/REJECT entries=$restrict_rules, nft entries=$nft_restrict); "
fi
if [[ -n $fw_enf ]]; then
    fw_status=ACTIVE
    fw_issue="Status basis: an enforcing firewall was confirmed - ${fw_enf}Data fetched: installed tools, csf.conf TESTING flag, csf.disable marker, loaded iptables chains/rules (iptables -S), nft ruleset, firewalld/ufw state. ${fw_other}Note: a loaded rule set shows a firewall is present; it does not prove every port is correctly restricted."
    fw_rec='A firewall is protecting the server. Please confirm the list of public services and trusted admin IPs (DirectAdmin 2222, SSH, web, mail) so we can review the rule set, keep admin IPs allow-listed, and confirm it survives reboot. Any rule change is made only with your approval.'
else
    fw_status=INACTIVE
    fw_issue="Status basis: no enforcing firewall was found (CSF, APF, UFW, firewalld or restrictive iptables/nft rules). ${fw_other}Data fetched: /etc/csf, /etc/apf, csf.conf TESTING flag, iptables -S, nft ruleset, firewalld and ufw state. Without a firewall every listening service, including DirectAdmin (2222), SSH, FTP and database ports, is reachable from the internet."
    fw_rec='A firewall is not installed or not active on the server. We recommend installing and enabling CSF/LFD (or firewalld) allowing only the ports the server needs and allow-listing your admin IPs. Kindly let us know if we can enable it.'
fi
emit 'SYSTEM FIREWALL' "$fw_status" "$fw_issue" "$fw_rec"

# Malware scanner
ms_found=''; ms_active=''
have clamscan && ms_found+='clamscan '; have clamdscan && ms_found+='clamdscan '; have maldet && ms_found+='Linux-Malware-Detect '
have imunify360-agent && ms_found+='Imunify360 '; have imunify-antivirus && ms_found+='ImunifyAV '
[[ $CB_CLAMAV == yes ]] && ms_found+='(CustomBuild clamav=yes) '
active clamd clamd@scan clamav-daemon && ms_active+='clamd running; '
active imunify360 imunify-360 && ms_active+='Imunify360 service running; '
active imunify-antivirus imunify-av imunify-antivirus-user && ms_active+='ImunifyAV service running; '
sig_age='none'
for f in /var/lib/clamav/daily.c[vl]d /var/clamav/daily.c[vl]d /usr/local/directadmin/custombuild/clamav/daily.c[vl]d; do
    [[ -f $f ]] || continue; t=$(stat -c %Y "$f" 2>/dev/null); [[ $t =~ ^[0-9]+$ ]] && sig_age=$(((NOW-t)/86400))
done
ms_ok=0
[[ -n $ms_active ]] && ms_ok=1
[[ -z $ms_active ]] && have maldet && ms_ok=1 && ms_active='LMD installed; '
[[ -z $ms_active ]] && have clamscan && [[ $sig_age =~ ^[0-9]+$ ]] && (( sig_age <= 14 )) && ms_ok=1 && ms_active="clamscan with signatures ${sig_age} days old; "
if (( ms_ok )); then
    emit 'MALWARE SCANNER' ACTIVE "Status basis: ${ms_active}Detected: ${ms_found:-n/a}. Data fetched: installed binaries (clamscan/clamdscan/maldet/imunify), systemd/process state of clamd and Imunify, ClamAV signature file age (${sig_age} days), CustomBuild clamav option (${CB_CLAMAV:-unset}). The audit does not run a scan, so this confirms the scanner exists, not that every site is clean. ${REPORT_INFO}" \
        'A malware scanner is installed and running. Please confirm the scan scope (all /home/*/domains), schedule and who reviews the results; we can verify signature updates and scan history, and any detected file will be removed only with your approval.'
else
    emit 'MALWARE SCANNER' INACTIVE "Status basis: no usable malware scanner (ClamAV, Imunify360, ImunifyAV, LMD) was found running or installed with current signatures. Detected: ${ms_found:-nothing}. Data fetched: installed binaries, service/process state, ClamAV signature age (${sig_age}), CustomBuild clamav option (${CB_CLAMAV:-unset})." \
        'A malware scanner is not installed on the server. We recommend installing ClamAV (with Linux Malware Detect) or Imunify360/ImunifyAV and scheduling regular scans of the hosted accounts. Kindly let us know if we can install it.'
fi

# Failed login detection
fl_ok=''; fl_note=''
if active lfd && [[ -r /etc/csf/csf.conf ]] && grep -Eq '^[[:space:]]*LF_SSHD[[:space:]]*=[[:space:]]*"?[1-9]' /etc/csf/csf.conf &&
   ! grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"?1' /etc/csf/csf.conf && [[ ! -e /etc/csf/csf.disable ]]; then
    fl_ok+='CSF/LFD (running, LF_SSHD threshold set, not in testing mode); '
fi
if [[ -x /usr/local/sbin/bfd || -x /usr/local/bfd/bfd ]] && [[ -f /etc/cron.d/bfd ]]; then fl_ok+='APF/BFD (BFD installed with cron entry); '; fi
if have fail2ban-client; then
    jails=$(run fail2ban-client status | sed -nE 's/.*Jail list:[[:space:]]*(.*)/\1/p' | tr ',' ' ')
    for j in $jails; do
        [[ $j =~ ^[A-Za-z0-9_.-]+$ ]] || continue
        acts=$(run fail2ban-client get "$j" actions)
        printf '%s' "$acts" | grep -Eiq 'iptables|nftables|firewallcmd|ufw|route|ipset' && fl_ok+="Fail2Ban jail $j (blocking action); "
    done
fi
active imunify360 imunify-360 && fl_ok+='Imunify360 service running (includes login protection); '
bfm=$(dacfg brute_force_log_scanner); bfm_blk=0
[[ -x $DA_DIR/scripts/custom/block_ip.sh || -x $DA_DIR/scripts/block_ip.sh ]] && bfm_blk=1
if [[ $bfm == 1 && $bfm_blk == 1 ]] && { (( ipt_ok )) || [[ -d /etc/csf ]]; }; then fl_ok+='DirectAdmin Brute Force Monitor (brute_force_log_scanner=1, block_ip.sh present, firewall available); '
else fl_note="DirectAdmin BFM: brute_force_log_scanner=${bfm:-unset}, block_ip.sh present=$bfm_blk (not counted). "; fi
if [[ -n $fl_ok ]]; then
    emit 'FAILED LOGIN DETECTION' ACTIVE "Status basis: ${fl_ok}${fl_note}Data fetched: csf.conf LF_SSHD/TESTING, LFD/Imunify360 service state, BFD files, fail2ban-client jails and their actions, directadmin.conf brute_force_log_scanner key, block_ip.sh presence. No test ban was made." \
        'Failed-login protection is active. Please confirm your trusted admin IPs and acceptable attempt limits; we can review SSH, DirectAdmin (2222), FTP and mail login thresholds and exclusions so legitimate users are not blocked.'
else
    emit 'FAILED LOGIN DETECTION' INACTIVE "Status basis: no working failed-login blocking was found (CSF/LFD, APF/BFD, Fail2Ban, Imunify360 or DirectAdmin BFM with a blocker). ${fl_note}Data fetched: csf.conf, service states, fail2ban jails, directadmin.conf brute_force keys." \
        'Failed-login detection is not active. We recommend enabling CSF/LFD or Fail2Ban (SSH, DirectAdmin, FTP and mail jails) with a sensible lockout limit. Kindly let us know if we can enable it.'
fi

# Web application firewall
waf_engine=''
for f in /etc/httpd/conf/extra/httpd-modsecurity.conf /etc/httpd/conf/modsecurity.conf /etc/apache2/conf-enabled/*modsec*.conf /etc/modsecurity.d/modsecurity.conf /etc/nginx/nginx-modsecurity.conf /etc/nginx/modsec/modsecurity.conf; do
    [[ -r $f ]] || continue
    m=$(grep -hEi '^[[:space:]]*(SecRuleEngine|modsecurity[[:space:]]+(on|off))' "$f" | head -n 1 | flat)
    [[ -n $m ]] && waf_engine+="$f: $m; "
done
waf_on=0; printf '%s' "$waf_engine" | grep -Eiq 'SecRuleEngine[[:space:]]+On|modsecurity[[:space:]]+on' && waf_on=1
imuwaf=0; active imunify360 imunify-360 && imuwaf=1
if (( waf_on )) && [[ $CB_MODSEC == yes || -z $CB_MODSEC ]]; then
    emit 'WEB APP FIREWALL' ACTIVE "Status basis: ModSecurity engine is On (${waf_engine}). CustomBuild modsecurity=${CB_MODSEC:-unset}, ruleset=${CB_RULESET:-unset}, web server=${CB_WEBSERVER:-unknown}. Data fetched: custombuild/options.conf and the ModSecurity config files for SecRuleEngine / 'modsecurity on'. Rule coverage per website and false-positive exclusions are not tested." \
        'ModSecurity is enabled and protecting the web server. Please tell us about any sites with known false positives so we can review the ruleset (Comodo/OWASP), keep rules updated and check the audit log for blocked attacks.'
elif (( imuwaf )); then
    emit 'WEB APP FIREWALL' ACTIVE "Status basis: Imunify360 service is running (its WAF ruleset applies). ModSecurity engine lines found: ${waf_engine:-none}. Data fetched: Imunify360 service state, ModSecurity config files, custombuild modsecurity option. Per-site coverage not tested." \
        'Imunify360 WAF is running. Please confirm which sites need exclusions; we can review the WAF mode and rules.'
else
    emit 'WEB APP FIREWALL' INACTIVE "Status basis: ModSecurity engine is not On. Engine lines found: ${waf_engine:-none}; CustomBuild modsecurity=${CB_MODSEC:-unset}, ruleset=${CB_RULESET:-unset}, web server=${CB_WEBSERVER:-unknown}. Data fetched: custombuild/options.conf and ModSecurity config files. DetectionOnly logs attacks but does not block them." \
        'ModSecurity (Web Application Firewall) is disabled. It protects websites against XSS, SQL injection, bots and similar attacks. We recommend enabling it through CustomBuild with the Comodo or OWASP ruleset after a compatibility check. Please confirm if you want this enabled.'
fi

# Rootkit scanner
rk=''; have rkhunter && rk+='rkhunter '; have chkrootkit && rk+='chkrootkit '
if [[ -n $rk ]]; then
    emit 'ROOTKIT SCANNER' ACTIVE "Status basis: ${rk}found on the server. Data fetched: binary presence for rkhunter and chkrootkit; recent report result=$ROOTKIT_RESULT. The audit does not run a rootkit scan." \
        "Rootkit scanner (${rk}) is installed. Please let us confirm it runs on a schedule with results mailed to the administrator, and review any warnings against a known baseline."
else
    emit 'ROOTKIT SCANNER' INACTIVE 'Status basis: neither rkhunter nor chkrootkit was found. Data fetched: binary presence check.' \
        'RKHunter/chkrootkit is not installed on the server. We recommend installing it and scheduling regular scans with e-mail reports. Kindly let us know if we can install it.'
fi

# ================================================================ B
section 'B : Software Updates'

# Control panel
da_latest=''; da_txt_note='Latest version lookup skipped.'
if (( ! OFFLINE )) && have dig; then
    da_txt=$(run dig +short -t txt "${DA_CHANNEL}-version.directadmin.com"); da_latest=$(printf '%s' "$da_txt" | first_ver)
    da_txt_note="DNS TXT ${DA_CHANNEL}-version.directadmin.com returned ${da_latest:-nothing parsable}."
fi
da_status=NA
if [[ -n $DA_VER && -n $da_latest ]]; then
    if [[ $DA_VER == "$da_latest" ]]; then da_status='All updates installed'
    elif version_le "$DA_VER" "$da_latest"; then da_status='Updates pending to install'
    else da_status='All updates installed'; fi
fi
case "$da_status" in
    'Updates pending to install') da_rec="A newer DirectAdmin build ($da_latest) is available on the $DA_CHANNEL channel. We recommend updating DirectAdmin (da update) to receive security and compatibility fixes. $OFFPEAK";;
    'All updates installed') da_rec="DirectAdmin is on the latest build of the $DA_CHANNEL channel. Please keep automatic updates enabled (autoupdate=${DA_AUTOUPDATE:-unknown}) or let us review monthly so security releases are not missed.";;
    *) da_rec='We could not compare the DirectAdmin version with the vendor channel. Please let us verify the licence, update channel and latest build from the DirectAdmin Licensing / Updates page.';;
esac
emit 'CONTROL PANEL' "$da_status" "Status basis: installed DirectAdmin ${DA_VER:-unknown} vs channel latest ${da_latest:-unknown}. Data fetched: 'directadmin v', 'da config-get update_channel' (${DA_CHANNEL}) and autoupdate (${DA_AUTOUPDATE:-unknown}), ${da_txt_note}" "$da_rec"

# Operating system
kernel_pkgs=$(pkgmatch '^(kernel|linux-image)([-:]|$)')
if (( kcare )); then os_re='^(cloudlinux-release|almalinux-release|rocky-release|centos-release|redhat-release|base-files|lsb-release)$'; else os_re='^(kernel|linux-image-[a-z0-9.-]+|cloudlinux-release|almalinux-release|rocky-release|centos-release|redhat-release|base-files)$'; fi
os_pend=$(pending_match "$os_re" | sort -u | tr '\n' ' ')
other_total=$(( $(pending_match '.' | awk 'NF{n++}END{print n+0}') ))
os_status=NA
if [[ -n $os_pend ]]; then os_status='Updates pending to install'; elif pkg_check_ok; then os_status='All updates installed'; fi
(( OS_STANDARD_EOL )) && [[ -z $os_pend ]] && pkg_check_ok && os_status='All updates installed'
if (( OS_STANDARD_EOL )); then
    os_rec="The installed OS ($OS_NAME) is past standard vendor support and will not receive normal security updates. We recommend migrating to a new server running a current OS release supported by DirectAdmin (AlmaLinux/Rocky 9 or 10, Debian 12 or 13, Ubuntu 24.04 LTS or CloudLinux 9). Any extended-support subscription should be treated only as temporary cover while the migration is planned. $OFFPEAK"
elif [[ $os_status == 'Updates pending to install' ]]; then
    os_rec="Operating system/kernel updates are pending (${os_pend}). We recommend applying them in an off-peak window; a reboot is needed for a new kernel$( ((kcare)) && echo ', although KernelCare covers the running kernel'). $OFFPEAK"
elif [[ $os_status == 'All updates installed' ]]; then
    os_rec="No pending operating system or kernel updates were reported by the package manager. Please continue regular patching$( ((kcare)) && echo ' (KernelCare live patching is applied)'); we can schedule a monthly patch review."
else
    os_rec='We could not confirm the update state (package query failed or was skipped). Please let us run the package update check online and review the result.'
fi
emit 'OPERATING SYSTEM' "$os_status" "Status basis: ${os_pend:+pending OS/kernel packages: ${os_pend}; }${os_pend:-no pending OS/kernel candidate reported; }KernelCare patch applied=$kcare (kernel packages excluded when yes); standard-support-ended=$OS_STANDARD_EOL. OS=$OS_NAME; running kernel=$KERNEL; installed kernels: $(printf '%s' "$kernel_pkgs" | tr '\t\n' ' '). Total pending packages of all kinds=$other_total. Data fetched: /etc/os-release, rpm/dpkg inventory, yum/dnf check-update or apt-get -s upgrade, kcarectl --info. $RPM_CHECK_NOTE $APT_NOTE" "$os_rec"

# PHP
php_pend=0; php_eolc=0; php_unk=0; php_ev=''; php_eol_list=''; php_cnt=0
while IFS=$'\t' read -r ver bin idx; do
    [[ -n $ver ]] || continue; ((php_cnt++)); st=$(php_eol "$ver")
    used=$(printf '%s\n' "$PHP_DOMAIN_MAP" | awk -F '\t' -v i="$idx" '$2==i{n++}END{print n+0}')
    php_ev+="PHP $ver at $bin (slot $idx, mode ${PHP_REL_MODE[$idx]:-?}, $used sites; $st upstream); "
    if [[ $st == 'End Of Life Period' ]]; then
        ((php_eolc++)); doms=$(printf '%s\n' "$PHP_DOMAIN_MAP" | awk -F '\t' -v i="$idx" '$2==i{print $1}' | head -n 15 | tr '\n' ' ')
        php_eol_list+="PHP $ver: ${doms:-no sites mapped}; "
    elif [[ $st == NA ]]; then ((php_unk++)); fi
done <<< "$PHP_LIST"
cb_group '^PHP'; php_pend=$CBG_PEND; php_cb_ev=$CBG_EV
php_status=NA
(( php_cnt>0 )) && php_status='All updates installed'
(( php_pend>0 || php_eolc>0 )) && php_status='Updates pending to install'
(( php_cnt>0 && php_unk>0 )) && [[ $php_status != 'Updates pending to install' ]] && php_status=NA
if [[ $php_status == 'Updates pending to install' ]]; then
    php_rec="PHP updates/upgrades are required${php_eol_list:+; end-of-life branches in use: ${php_eol_list}}. End-of-life PHP no longer receives security patches. We recommend moving websites to PHP 8.3 or higher (PHP 8.2 security support ends 31 Dec 2026) after compatibility testing with your developers, and updating the remaining PHP versions to their latest patch release. $OFFPEAK"
elif [[ $php_status == 'All updates installed' ]]; then
    php_rec='Installed PHP versions are supported and show no pending update. Please keep using supported branches only; we can review PHP versions per site every quarter.'
else php_rec='PHP currency could not be confirmed. Please let us review the installed PHP versions and CustomBuild status.'; fi
emit 'PHP' "$php_status" "Status basis: ${php_ev:-no CustomBuild PHP binaries found}CustomBuild comparison: ${php_cb_ev:-none}. Data fetched: custombuild/options.conf php1-4_release/mode, /usr/local/phpNN/bin/php -v, 'build versions', data/users/*/domains/*.conf (php=ON, php1_select). ${CB_NOTE}" "$php_rec"

# CMS
cms_pend=0; cms_unk=$CMS_PARTIAL; cms_cnt=0; cms_ev=''; cms_old=''
WP_LATEST=''; wp_json=$(fetch_metadata 'https://api.wordpress.org/core/version-check/1.7/') && WP_LATEST=$(printf '%s' "$wp_json" | json_version current)
while IFS=$'\t' read -r product ver file; do
    [[ -n $product ]] || continue; ((cms_cnt++)); site=$(site_of "$file"); cms_ev+="$product $ver ${site:-$file}; "
    if [[ $product == joomla && $ver == 3.* ]]; then ((cms_pend++)); cms_old+="${site:-$file} (Joomla $ver, retired branch); "
    elif [[ $product == wordpress && -n $WP_LATEST ]]; then
        if [[ $ver == "$WP_LATEST" ]]; then :; elif version_le "$ver" "$WP_LATEST"; then ((cms_pend++)); cms_old+="${site:-$file} (WordPress $ver, latest $WP_LATEST); "; else ((cms_unk++)); fi
    else ((cms_unk++)); fi
done <<< "$CMS_LIST"
cms_status=NA; (( cms_pend>0 )) && cms_status='Updates pending to install'
(( cms_cnt>0 && cms_pend==0 && cms_unk==0 )) && cms_status='All updates installed'
if [[ $cms_status == 'Updates pending to install' ]]; then
    cms_rec="Outdated CMS installations were detected: ${cms_old}Outdated CMS versions are a common cause of hacked sites. Please ask the site owners to update the CMS core, themes and plugins (or approve an update by us after a backup), starting with the sites listed."
elif [[ $cms_status == 'All updates installed' ]]; then cms_rec='Detected CMS cores match the latest official release. Please keep plugins and themes updated; we can run a periodic review.'
else cms_rec='CMS currency could not be fully confirmed. Please provide the document roots or let us review the sites manually.'; fi
emit 'CMS' "$cms_status" "Status basis: CMS found=$cms_cnt, outdated=$cms_pend, unverified=$cms_unk. ${cms_ev:-none found}. Data fetched: version files of WordPress, Drupal, Joomla and Moodle under ${WEBROOTS[*]} (depth 12); WordPress latest=${WP_LATEST:-unavailable} from api.wordpress.org. Plugins/themes are not checked; discovery partial=$CMS_PARTIAL." "$cms_rec"

# Web server / Database / Other
group_status() { # item cbregex pkgregex friendly
    local item=$1 cbre=$2 pkre=$3 label=$4 st=NA ev rec pend_pk inst_pk
    cb_group "$cbre"
    pend_pk=$(pending_match "$pkre" | sort -u | tr '\n' ' ')
    inst_pk=$(pkgmatch "$pkre" | awk -F '\t' '{printf "%s=%s ",$1,$2}' | cut -c1-500)
    ev="CustomBuild: ${CBG_EV:-no rows}; OS packages: ${inst_pk:-none}${pend_pk:+ pending: $pend_pk}. $CB_NOTE $RPM_CHECK_NOTE $APT_NOTE"
    if (( CBG_PEND>0 )) || [[ -n $pend_pk ]]; then st='Updates pending to install'
    elif (( CBG_EQ>0 || 1 )) && { (( CBG_EQ>0 )) || [[ -n $inst_pk ]]; } && (( CBG_UNK==0 )) && { (( CBG_EQ>0 )) || pkg_check_ok; }; then st='All updates installed'; fi
    case "$st" in
        'Updates pending to install') rec="$label updates are available (${CBG_EV}${pend_pk}). We recommend applying them in an off-peak window after a backup. $OFFPEAK";;
        'All updates installed') rec="$label is on the latest available version. Please continue regular updates; we can re-check monthly.";;
        *) rec="No $label update information could be confirmed (nothing detected or the update check could not run). Please let us verify the installed version manually.";;
    esac
    emit "$item" "$st" "Status basis: $ev Data fetched: 'build versions' rows and rpm/dpkg inventory with the pending-update list." "$rec"
}
group_status 'WEB SERVER' '(apache|nginx|litespeed|openlitespeed|lsws|httpd)' '^(nginx|httpd|apache2|litespeed|openlitespeed|lsws)$' 'Web server'
group_status 'DATABASE SERVER' '(mysql|mariadb|percona)' '^(mysql|mariadb|percona)[a-z-]*server|^mysql-community-server$|^mariadb-server$|^MariaDB-server$' 'Database server'
group_status 'OTHER SOFTWARES' '(exim|dovecot|phpmyadmin|roundcube|openssl|openssh|proftpd|pureftpd|bind|spamassassin|redis|curl)' '^(exim|dovecot|openssh-server|openssl|proftpd|pure-ftpd|bind|bind9|spamassassin|redis)$' 'Other software'

# ================================================================ C
section 'C : Server Health'
upt=$(awk '{printf "%.0f",$1}' /proc/uptime 2>/dev/null)
if [[ $upt =~ ^[0-9]+$ ]] && (( upt>=3600 )); then us=GOOD; urec='Uptime is healthy. Please let us know of any planned maintenance reboots so we can track them.'; else us='NOT GOOD'; urec='The server was restarted less than an hour ago. Please confirm whether this was planned; we can review the reboot reason and service start-up.'; fi
emit 'SERVER UPTIME' "$us" "Status basis: uptime=${upt:-unknown} seconds (GOOD needs at least 3600). Data fetched: /proc/uptime. It measures time since boot, not historical availability." "$urec"

http_status='NOT GOOD'; http_ev=''; web_running=0; web_bad=0
declare -A HTTP_SEEN
for svc in nginx httpd apache2 lsws litespeed openlitespeed; do
    active "$svc" || continue
    age=''; key="svc:$svc"
    read -r pid age < <(run ps -C "$svc" -o pid=,etimes= | sort -k2,2nr | head -n 1)
    [[ $pid =~ ^[0-9]+$ ]] && key="pid:$pid"
    [[ -n ${HTTP_SEEN[$key]:-} ]] && continue; HTTP_SEEN[$key]=1; ((web_running++))
    if [[ $age =~ ^[0-9]+$ ]] && (( age>=3600 )); then http_ev+="$svc running ${age}s; "; else ((web_bad++)); http_ev+="$svc running age=${age:-unknown}s; "; fi
done
(( web_running>0 && web_bad==0 )) && http_status=GOOD
for url in "${HTTP_URLS[@]}"; do
    if (( OFFLINE )) || ! have curl; then http_ev+='URL check skipped; '; http_status='NOT GOOD'; continue; fi
    code=$(run curl -q --noproxy '*' --proto '=http,https' --connect-timeout 4 --max-time 10 -sS -I -o /dev/null -w '%{http_code}' -- "$url"); crc=$?
    if (( crc==0 )) && [[ $code =~ ^[23][0-9][0-9]$ ]]; then http_ev+="$url HTTP $code; "; else http_ev+="$url failed (curl=$crc HTTP=$code); "; http_status='NOT GOOD'; fi
done
if [[ $http_status == GOOD ]]; then hrec='The web server has been running continuously. Please share any external uptime monitor so we can compare history.'; else hrec='The web server is not running long enough or could not be confirmed. Please let us check the web server service, error log and recent restarts.'; fi
emit 'HTTP UPTIME' "$http_status" "Status basis: ${http_ev:-no running web service (nginx/httpd/apache2/litespeed) confirmed}. Data fetched: service/process state and process age (ps etimes)${HTTP_URLS:+, HEAD requests to supplied URLs}. Process age is not historical availability." "$hrec"

cpu_s() { awk '/^cpu / {t=0;for(i=2;i<=9;i++)t+=$i;print t,$5+$6;exit}' /proc/stat; }
read -r t1 i1 < <(cpu_s); sleep 2; read -r t2 i2 < <(cpu_s)
cores=$(awk '/^processor[[:space:]]*:/{n++} END{print n+0}' /proc/cpuinfo); load1=$(awk '{print $1}' /proc/loadavg)
cpu_busy=unknown; cpu_st='NOT GOOD'; load_pct=unknown
if [[ $t1 =~ ^[0-9]+$ && $t2 =~ ^[0-9]+$ ]] && (( t2>t1 && cores>0 )); then
    cpu_busy=$((100*(t2-t1-i2+i1)/(t2-t1))); load_pct=$(awk -v l="$load1" -v n="$cores" 'BEGIN{printf "%.0f",100*l/n}')
    (( cpu_busy<CPU_MAX && load_pct<CPU_MAX )) && cpu_st=GOOD
fi
if [[ $cpu_st == GOOD ]]; then crec='CPU usage is within the normal range. Please tell us about expected traffic growth so we can plan capacity.'; else crec='CPU usage/load is high. We recommend identifying the top accounts and processes (top, DirectAdmin resource usage), tuning or limiting them, and resizing the server if the load is genuine.'; fi
emit 'CPU USAGE' "$cpu_st" "Status basis: 2-second busy=$cpu_busy%, 1-minute load=$load1 on $cores cores (load/core=$load_pct%), limit=$CPU_MAX%. Data fetched: /proc/stat (two samples), /proc/loadavg, /proc/cpuinfo. A short sample can miss spikes." "$crec"

read -r mt ma mm < <(awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2;h=1}/^MemFree:/{f=$2}/^Buffers:/{b=$2}/^Cached:/{c=$2}/^SReclaimable:/{r=$2}/^Shmem:/{s=$2} END{if(h)print t,a,"MemAvailable";else print t,f+b+c+r-s,"estimated"}' /proc/meminfo)
ram_st='NOT GOOD'; ram_used=unknown
if [[ $mt =~ ^[0-9]+$ && $ma =~ ^[0-9]+$ ]] && (( mt>0 && ma<=mt )); then ram_used=$((100*(mt-ma)/mt)); (( ram_used<RAM_MAX )) && ram_st=GOOD; fi
swap_ev=$(awk '/^SwapTotal:/{t=$2}/^SwapFree:/{f=$2} END{printf "swap used %d of %d KiB",t-f,t}' /proc/meminfo)
if [[ $ram_st == GOOD ]]; then rrec='Memory usage is healthy. We will keep watching swap and OOM events.'; else rrec='Memory usage is high. We recommend reviewing the largest memory consumers (PHP-FPM pools, MySQL, Exim), tuning worker limits, and adding RAM if usage is genuine.'; fi
emit 'RAM USAGE' "$ram_st" "Status basis: used (excluding cache)=$ram_used% vs limit $RAM_MAX% ($mm); $swap_ev. Data fetched: /proc/meminfo." "$rrec"

dfout=$(run df -P -l -k); dfrc=$?; inout=$(run df -P -l -i)
disk_st=GOOD; (( dfrc!=0 )) && disk_st='NOT GOOD'
disk_bad=$(printf '%s\n' "$dfout" | awk -v m="$DISK_MAX" 'NR>1{v=$5;gsub(/%/,"",v);if(v+0>=m)print $6 " " $5}' | tr '\n' ';')
inode_bad=$(printf '%s\n' "$inout" | awk -v m="$DISK_MAX" 'NR>1{v=$5;gsub(/%/,"",v);if(v ~ /^[0-9]+$/ && v+0>=m)print $6 " " $5}' | tr '\n' ';')
root_use=$(printf '%s\n' "$dfout" | awk '$6=="/"{print $5}')
[[ -n $disk_bad || -n $inode_bad ]] && disk_st='NOT GOOD'
if [[ $disk_st == GOOD ]]; then drec="Disk and inode usage are below $DISK_MAX% (/ is ${root_use:-unknown}). Please keep an eye on account growth; we can add disk alerts."; else drec="Disk space is high on: ${disk_bad:-n/a} inodes: ${inode_bad:-n/a}. We recommend clearing old backups, logs and temporary data, reviewing account quotas, and extending the volume. Files are not removed without your approval."; fi
emit 'DISC SPACE USAGE' "$disk_st" "Status basis: limit=$DISK_MAX%; space alerts=${disk_bad:-none}; inode alerts=${inode_bad:-none}; / usage=${root_use:-unknown}. Data fetched: df -P -l (space and inodes, local filesystems only)." "$drec"

q_total=0; q_seen=0; q_unk=0; q_ev=''
if have exim; then q=$(run exim -bpc); if [[ $q =~ ^[0-9]+$ ]]; then ((q_seen++)); ((q_total+=q)); q_ev+="Exim messages=$q; "; else ((q_unk++)); fi; fi
if have postqueue; then qo=$(run postqueue -p); if [[ $qo == *'Mail queue is empty'* ]]; then ((q_seen++)); q_ev+='Postfix empty; '; else qn=$(printf '%s\n' "$qo" | sed -nE 's/^-- .* in ([0-9]+) Request.*/\1/p' | tail -n 1); if [[ $qn =~ ^[0-9]+$ ]]; then ((q_seen++)); ((q_total+=qn)); q_ev+="Postfix messages=$qn; "; else ((q_unk++)); fi; fi; fi
q_st='NOT GOOD'; (( q_seen>0 && q_unk==0 && q_total<=QUEUE_MAX )) && q_st=GOOD
if [[ $q_st == GOOD ]]; then qrec='The mail queue is small. Please tell us about expected bulk mailings so we can watch the queue.'; else qrec='The mail queue is large or could not be read. We recommend checking the dominant sender (exim -bp), compromised accounts or mail loops, and deferred messages. Mail is not deleted without your approval.'; fi
emit 'EMAIL QUEUE' "$q_st" "Status basis: ${q_ev:-no readable Exim/Postfix queue} total=$q_total vs limit $QUEUE_MAX. Data fetched: exim -bpc / postqueue -p (counts only; no message content)." "$qrec"

rep_st='NOT GOOD'; rep_ev='UNVERIFIED: needs a public IPv4, dig and network access.'; listed_names=''
if (( ! OFFLINE )) && [[ -n $TARGET_IP ]] && have dig; then
    IFS=. read -r a b c d <<< "$TARGET_IP"; rev="$d.$c.$b.$a"; rep_ev=''; dl=0; dc=0; du=0
    for spec in 'zen.spamhaus.org|^127\.0\.0\.(2|3|4|9|10|11)$|req' 'bl.spamcop.net|^127\.0\.0\.2$|req' 'b.barracudacentral.org|^127\.0\.0\.2$|opt'; do
        IFS='|' read -r zone okre kind <<< "$spec"
        pos=$(dns_query "2.0.0.127.$zone" A | dns_a); neg=$(dns_query "1.0.0.127.$zone" A | dns_code)
        if ! printf '%s\n' "$pos" | grep -Eq "$okre" || [[ $neg != NXDOMAIN ]]; then
            [[ $kind == req ]] && ((du++)); rep_ev+="$zone controls failed/unavailable (${kind}); "; continue
        fi
        ans=$(dns_query "$rev.$zone" A); code=$(printf '%s\n' "$ans" | dns_code); codes=$(printf '%s\n' "$ans" | dns_a)
        if [[ $code == NXDOMAIN ]]; then [[ $kind == req ]] && ((dc++)); rep_ev+="$zone not listed; "
        elif [[ $code == NOERROR && -n $codes ]] && ! printf '%s\n' "$codes" | grep -vEq "$okre" ; then ((dl++)); listed_names+="$zone "; rep_ev+="$zone LISTED ($(echo $codes)); "
        else [[ $kind == req ]] && ((du++)); rep_ev+="$zone unverified ($code); "; fi
    done
    (( dl==0 && du==0 && dc==2 )) && rep_st=GOOD
    rep_ev+="IP=$TARGET_IP listed=$dl clean=$dc unverified=$du. (SORBS was shut down in 2024 and is not queried; Barracuda needs a registered resolver, so it only counts if it answers its control queries.)"
fi
(( IP_MISMATCH )) && { rep_st='NOT GOOD'; rep_ev+=" OWNERSHIP UNVERIFIED: $IP_NOTE"; }
if [[ $rep_st == GOOD ]]; then rprec="The server IP $TARGET_IP is not blocklisted on the checked lists. Please confirm this is the actual outgoing mail IP; we can monitor the lists and set up SPF/DKIM/DMARC checks."; else rprec="The IP ${TARGET_IP:-of the server} is listed or could not be verified (${listed_names:-see issue}). We recommend finding and fixing the source (compromised account, spam script, open relay) and then requesting removal: Spamhaus https://check.spamhaus.org/ , SpamCop https://www.spamcop.net/bl.shtml , Barracuda https://www.barracudacentral.org/rbl/removal-request . Delisting is only accepted once the abuse is fixed."; fi
emit 'IP REPUTATION' "$rep_st" "Status basis: $rep_ev Data fetched: DNS blocklist lookups for the reversed IP, with known-listed and known-clean control queries to avoid false 'clean' results." "$rprec"

# ================================================================ D
section 'D : Software Life Time'
if (( OS_STANDARD_EOL )); then dls='End Of Life Period'; dnote='the OS release is past standard support, and DirectAdmin only supports current OS releases'
elif [[ -n $DA_VER ]]; then dls='Support Period Active'; dnote='DirectAdmin publishes no per-version end-of-life date; the vendor supports current builds on supported OS releases (pending update status is under Software Updates)'
else dls=NA; dnote='the DirectAdmin version could not be read'; fi
if [[ $dls == 'End Of Life Period' ]]; then drec='DirectAdmin cannot be kept on current builds on an unsupported OS. We recommend migrating to a new server with a supported OS and DirectAdmin; we can plan the account transfer, testing and cut-over in an agreed window.'
elif [[ $dls == 'Support Period Active' ]]; then drec='The panel is on a supported OS. Please keep the licence active and the panel updated; we can review the vendor life-cycle announcements each quarter.'
else drec='Please let us confirm the DirectAdmin version and licence manually.'; fi
emit 'CONTROL PANEL' "$dls" "Status basis: ${dnote}. DirectAdmin ${DA_VER:-unknown}; OS $OS_NAME. Data fetched: 'directadmin v', /etc/os-release and a built-in OS lifecycle table (reviewed 2026-10-05)." "$drec"

os_life=NA; os_end=''; os_note='OS release not in the built-in lifecycle table.'
case "$OS_ID:$OS_VERSION" in
    cloudlinux:7*) os_end=2024-06-30;; cloudlinux:8*) os_end=2029-05-31;; cloudlinux:9*) os_end=2032-05-31;; cloudlinux:10*) os_end=2035-05-31;;
    almalinux:8*|rocky:8*|rhel:8*) os_end=2029-05-31;; almalinux:9*|rocky:9*|rhel:9*) os_end=2032-05-31;; almalinux:10*|rocky:10*|rhel:10*) os_end=2035-05-31;;
    centos:7*) os_end=2024-06-30;; centos:8*) os_end=2021-12-31;;
    debian:9*) os_end=2022-06-30;; debian:10*) os_end=2024-06-30;; debian:11*) os_end=2026-08-31;; debian:12*) os_end=2028-06-30;; debian:13*) os_end=2030-06-30;;
    ubuntu:18.04) os_end=2023-05-31;; ubuntu:20.04) os_end=2025-05-31;; ubuntu:22.04) os_end=2027-04-30;; ubuntu:24.04) os_end=2029-04-30;; ubuntu:26.04) os_end=2031-04-30;;
esac
if [[ -n $os_end ]]; then
    if [[ $TODAY > $os_end ]]; then os_life='End Of Life Period'; else os_life='Support Period Active'; fi
    os_note="Standard/LTS support end date used: $os_end (built-in table reviewed 2026-10-05; paid extended support such as ELS/ESM/ELTS is not counted)."
fi
if [[ $os_life == 'End Of Life Period' ]]; then orec="The installed OS ($OS_NAME) reached end of standard support on $os_end and no longer receives regular security updates. We recommend migrating to a new server with a current supported OS (AlmaLinux/Rocky 9 or 10, Debian 12 or 13, Ubuntu 24.04 LTS). Extended-support subscriptions are only temporary cover. $OFFPEAK"
elif [[ $os_life == 'Support Period Active' ]]; then orec="The OS is within its vendor support period until $os_end. Please plan the next OS migration well before that date; we can track it and schedule it with you."
else orec='Please let us verify the OS vendor life-cycle manually.'; fi
emit 'OPERATING SYSTEM' "$os_life" "Status basis: $OS_NAME; $os_note Data fetched: /etc/os-release and the lifecycle table." "$orec"

cms_life=NA; cms_eol=0; cms_ok=0; cms_lu=$CMS_PARTIAL
while IFS=$'\t' read -r product ver file; do
    [[ -n $product ]] || continue
    if [[ $product == joomla && $ver == 3.* ]]; then ((cms_eol++))
    elif [[ $product == wordpress && -n $WP_LATEST ]]; then
        if [[ ${ver%.*} == "${WP_LATEST%.*}" ]]; then ((cms_ok++)); elif version_le "$ver" "$WP_LATEST"; then ((cms_eol++)); else ((cms_lu++)); fi
    else ((cms_lu++)); fi
done <<< "$CMS_LIST"
(( cms_eol>0 )) && cms_life='End Of Life Period'
(( cms_cnt>0 && cms_eol==0 && cms_lu==0 )) && cms_life='Support Period Active'
if [[ $cms_life == 'End Of Life Period' ]]; then crec2="Websites run CMS branches that no longer receive security fixes: ${cms_old}Please upgrade them to a supported branch or isolate them; we can help plan the upgrade."; elif [[ $cms_life == 'Support Period Active' ]]; then crec2='All detected CMS installations are on supported branches. Please keep them updated.'; else crec2='CMS support status could not be fully confirmed; please let us review the sites.'; fi
emit 'CMS' "$cms_life" "Status basis: CMS found=$cms_cnt, unsupported branches=$cms_eol, supported=$cms_ok, unverified=$cms_lu. Data fetched: same CMS version files as Section B; WordPress supports only its current major branch, Joomla 3 ended 2023-08-17." "$crec2"

stack_eol=0; stack_unk=0; stack_seen=0; stack_ev=''
while IFS=$'\t' read -r ver bin idx; do
    [[ -n $ver ]] || continue; ((stack_seen++)); st=$(php_eol "$ver"); stack_ev+="PHP $ver $st; "
    [[ $st == 'End Of Life Period' ]] && ((stack_eol++)); [[ $st == NA ]] && ((stack_unk++))
done <<< "$PHP_LIST"
dbv=$(run mariadbd --version | first_ver); dbname=MariaDB
[[ -n $dbv ]] || { dbv=$(run mysqld --version | first_ver); dbname=MySQL; }
[[ -n $dbv ]] || { dbv=$(run mysql --version | first_ver); dbname=MySQL/MariaDB; }
if [[ -n $dbv ]]; then
    ((stack_seen++)); br=${dbv%.*}; dend=''
    if run mysql --version | grep -qi mariadb || [[ $dbname == MariaDB ]]; then
        case "$br" in 10.4) dend=2024-06-18;; 10.5) dend=2025-06-24;; 10.6) dend=2026-07-06;; 10.11) dend=2028-02-16;; 11.4) dend=2029-05-29;; 11.8) dend=2028-06-04;; esac
    else case "$br" in 5.7) dend=2023-10-31;; 8.0) dend=2026-04-30;; 8.4) dend=2032-04-30;; esac; fi
    if [[ -z $dend ]]; then ((stack_unk++)); stack_ev+="DB $dbname $dbv lifecycle unknown; "
    elif [[ $TODAY > $dend ]]; then ((stack_eol++)); stack_ev+="DB $dbname $dbv ended $dend; "
    else stack_ev+="DB $dbname $dbv supported until $dend; "; fi
fi
stack_life=NA
(( stack_eol>0 )) && stack_life='End Of Life Period'
(( stack_seen>0 && stack_eol==0 && stack_unk==0 )) && stack_life='Support Period Active'
if [[ $stack_life == 'End Of Life Period' ]]; then srec="Part of the software stack is past its support date (${stack_ev}). End-of-life PHP/database versions get no security patches. We recommend moving to supported versions (PHP 8.3 or higher, a supported MariaDB/MySQL release) after compatibility testing. Sites on old PHP: ${php_eol_list:-see Software Updates}"
elif [[ $stack_life == 'Support Period Active' ]]; then srec='The PHP and database versions in use are within their support period. Please plan upgrades before the dates in the issue text.'
else srec='Some stack components could not be mapped to a lifecycle date; please let us verify them manually.'; fi
emit 'SOFTWARE STACK' "$stack_life" "Status basis: ${stack_ev:-nothing detected}. Data fetched: installed PHP versions, mariadbd/mysqld --version, built-in lifecycle dates (PHP, MariaDB, MySQL; reviewed 2026-10-05, verify against the vendor sites)." "$srec"

# ================================================================ E
section 'E : Proactive Defence'
tmp_st='Not Configured'; tmp_ev='UNVERIFIED: findmnt unavailable.'
if have findmnt; then
    opts=$(run findmnt -n -T /tmp -o OPTIONS); perms=$(stat -c %a /tmp 2>/dev/null)
    tmp_ev="/tmp mount options=$opts; permissions=$perms."
    [[ ,$opts, == *,noexec,* && ,$opts, == *,nosuid,* && ,$opts, == *,nodev,* && $perms == 1777 ]] && tmp_st=Configured
fi
if [[ $tmp_st == Configured ]]; then trec='/tmp is mounted with noexec, nosuid and nodev. Please let us know if any application needs to execute from /tmp; we will also check /var/tmp and /dev/shm.'; else trec='/tmp is not secured, which can let malicious scripts execute from it. We recommend mounting /tmp (and /var/tmp, /dev/shm) with noexec,nosuid,nodev. Please confirm if we can secure /tmp.'; fi
emit '/tmp SECURITY' "$tmp_st" "Status basis: $tmp_ev Configured needs noexec, nosuid, nodev and sticky 1777. Data fetched: findmnt -T /tmp and stat /tmp." "$trec"

emit 'REBOOT PROCEDURE' '' '' ''

rd_st='Not Configured'; rd_ev='UNVERIFIED: needs public IPv4, dig and network access.'
if (( ! OFFLINE )) && [[ -n $TARGET_IP ]] && have dig; then
    po=$(dns_query -x "$TARGET_IP"); ps=$(printf '%s\n' "$po" | dns_code); ptrs=$(printf '%s\n' "$po" | awk '$4=="PTR"{print $5}')
    rd_ev="IP=$TARGET_IP PTR status=$ps records=${ptrs:-none}. "
    while read -r ptr; do
        [[ $ptr =~ ^[A-Za-z0-9_.-]+\.$ ]] || continue
        printf '%s\n' "$(dns_query "$ptr" A | dns_a)" | grep -Fxq "$TARGET_IP" && { rd_st=Configured; rd_ev+="Forward-confirmed: $ptr resolves back to the IP. "; }
    done <<< "$ptrs"
fi
(( IP_MISMATCH )) && { rd_st='Not Configured'; rd_ev+="OWNERSHIP UNVERIFIED: $IP_NOTE"; }
if [[ $rd_st == Configured ]]; then rdrec='Reverse DNS is configured and matches. Please keep the PTR in step with any future IP or hostname change.'; else rdrec='IP RDNS is not configured properly. Please ask the IP provider to set the PTR record to the server hostname (or let us arrange it) and make sure the forward A record points back to the same IP; this affects mail deliverability.'; fi
emit 'IP RDNS' "$rd_st" "Status basis: $rd_ev Data fetched: PTR lookup of the IP and A lookup of the PTR name (forward-confirmed reverse DNS)." "$rdrec"

for kind in MALWARE ROOTKIT; do
    res=$MALWARE_RESULT; item='MALWARE SCAN'; [[ $kind == ROOTKIT ]] && { res=$ROOTKIT_RESULT; item='ROOTKIT CHECK'; }
    case "$res" in
        clean) st=Configured; iss="Status basis: a recent $kind scan summary reports zero findings. $REPORT_INFO Data fetched: the $kind section of the scan report (scanned/checked counts, infected/possible counts, completion marker). Report scope and authenticity are not verifiable."
               rec="The latest $kind report shows no findings. Please keep the scheduled scans and reports running; we can review the scope each quarter.";;
        found) st='Not Configured'; iss="Status basis: the $kind report lists findings. $REPORT_INFO Data fetched: the $kind section of the scan report."
               rec="$kind findings were reported. Please see the list in the report and let us know if we can go ahead and delete/quarantine them; nothing is removed without your approval.";;
        *)     st='MALWARE SCAN NEEDED'; iss="Status basis: $kind result unverified - report missing, stale, incomplete, or this scanner's section has no valid summary or contains warnings/errors. $REPORT_INFO Data fetched: $SCAN_REPORT"
               rec='No recent complete scan evidence is available. Please approve a scan; we will review scope and results with you and remove nothing without approval.';;
    esac
    emit "$item" "$st" "$iss" "$rec"
done

ssh_st='Not Configured'; ssh_ev='UNVERIFIED: sshd not found.'
if have sshd; then
    cfg=$(run sshd -T -C user=root,host=localhost,addr=127.0.0.1); src=$?
    mode='effective config for user root'
    if (( src!=0 )); then cfg=$(run sshd -T); src=$?; mode='sshd -T without connection context'; fi
    rl=$(printf '%s\n' "$cfg" | awk '$1=="permitrootlogin"{print $2;exit}')
    pf=$(run grep -rIliE '^[[:space:]]*PermitRootLogin[[:space:]]+(yes|without-password|prohibit-password|forced-commands-only)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d | flat)
    ssh_ev="$mode: PermitRootLogin=${rl:-unknown}; files with a permissive line: ${pf:-none}."
    (( src==0 )) && [[ $rl == no && -z $pf ]] && ssh_st=Configured
fi
if [[ $ssh_st == Configured ]]; then srec2='Direct root login over SSH is disabled. Please make sure a named sudo/wheel user and recovery access exist.'; else srec2='Root login is enabled (or could not be confirmed disabled) over SSH. We recommend creating a named sudo user with key-based access and then setting PermitRootLogin no. We will validate recovery access first and apply it only with your approval.'; fi
emit 'SSH ROOT ACCESS SECURITY' "$ssh_st" "Status basis: $ssh_ev Data fetched: sshd -T -C user=root effective value plus a scan of sshd_config and sshd_config.d for permissive PermitRootLogin lines." "$srec2"

# PHP functions: judge in-use DirectAdmin PHP versions
php_required=(exec shell_exec system passthru popen proc_open)
missing_fns() { local v=",${1,,}," f m=''; for f in "${php_required[@]}"; do [[ $v == *",$f,"* ]] || m+="$f "; done; printf '%s' "$m"; }
eff_disable() { cat "$1/lib/php.ini" "$1"/lib/php.conf.d/*.ini 2>/dev/null | awk '/^[[:space:]]*disable_functions[[:space:]]*=/{x=substr($0,index($0,"=")+1);sub(/[;#].*/,"",x);v=x} END{print v}' | tr -d ' \t\r"'"'"; }
pf_bad=''; pf_ok=0; pf_ev=''; pf_dirs=()
for idx in $PHP_INUSE_IDX; do [[ -n ${PHP_REL_DIR[$idx]:-} ]] && pf_dirs+=("${PHP_REL_DIR[$idx]}"); done
pf_basis='PHP versions in use by sites (domains/*.conf php=ON)'
if (( ${#pf_dirs[@]} == 0 )); then pf_dirs=(/usr/local/php[0-9]*); pf_basis='no per-site selection found, every installed /usr/local/phpNN evaluated'; fi
for d in "${pf_dirs[@]}"; do
    [[ -d $d ]] || continue
    ef=$(eff_disable "$d"); mf=$(missing_fns "$ef")
    if [[ -z $mf && -n $ef ]]; then ((pf_ok++)); pf_ev+="$d disables all required; "; else pf_bad+="$d does not disable: ${mf:-all} ; "; fi
    for pool in "$d"/etc/php-fpm.d/*.conf "$d"/etc/php-fpm.conf.d/*.conf; do
        [[ -f $pool ]] || continue
        pv=$(grep -hE '^[[:space:]]*php_(admin_)?value\[disable_functions\]' "$pool" | tail -n 1 | sed -E 's/.*=[[:space:]]*//' | tr -d ' "')
        [[ -n $pv ]] || continue
        pm=$(missing_fns "$pv"); [[ -n $pm ]] && pf_bad+="FPM pool $(basename "$pool") overrides and lacks: $pm; "
    done
done
pf_st=NA
if (( pf_ok>0 )) && [[ -z $pf_bad ]]; then pf_st=Configured; elif [[ -n $pf_bad ]]; then pf_st='Not Configured'; fi
if [[ $pf_st == Configured ]]; then pfrec='Dangerous PHP functions (exec, shell_exec, system, passthru, popen, proc_open) are disabled for the PHP versions in use. Please tell us about sites that legitimately need one so we can add narrow, per-site exceptions instead of enabling it globally.'
elif [[ $pf_st == 'Not Configured' ]]; then pfrec="Dangerous PHP functions are enabled: ${pf_bad}This can let a single compromised script run system commands. We recommend disabling them in the PHP configuration (php.conf.d/90-custom.ini or the PHP-FPM pool) after your developer team confirms what the applications need."
else pfrec='No DirectAdmin PHP configuration could be read. Please let us check the PHP setup manually.'; fi
emit 'PHP FUNCTIONS SECURITY' "$pf_st" "Status basis: evaluated $pf_basis; ${pf_ev}${pf_bad}Required disabled: ${php_required[*]}. Data fetched: /usr/local/phpNN/lib/php.ini + php.conf.d/*.ini (last disable_functions wins) and php-fpm pool overrides. Per-site .user.ini and custom per-user php.ini are not read." "$pfrec"

pw_st='Not Configured'; pw_ev='UNVERIFIED root password age.'
if [[ -r /etc/shadow ]]; then
    read -r changed lock < <(awk -F: '$1=="root" {s=($2 ~ /^[!*]/ ? "locked" : ($2==""?"empty":"set"));print $3,s;exit}' /etc/shadow)
    if [[ $changed =~ ^[0-9]+$ ]]; then
        pa=$((NOW/86400-changed)); pw_ev="Root password last changed $pa days ago; password state=$lock."
        if [[ $lock == locked ]]; then pw_st=NA; elif [[ $lock == set ]] && (( changed>0 && pa>=0 && pa<=90 )); then pw_st=Configured; fi
    fi
fi
case "$pw_st" in
    Configured) pwrec='The root password was changed within the last 90 days. Please keep rotating it every 90 days through the approved credential process.';;
    NA) pwrec='Root password login is locked (key-only access). Please keep the keys protected and reviewed.';;
    *) pwrec='The root password is older than 90 days or its age could not be confirmed. We recommend rotating it to a long random value and storing it in a password manager.';;
esac
emit 'ROOT PASSWORD HEALTH' "$pw_st" "Status basis: $pw_ev Configured means changed within 90 days. Data fetched: last-change day from /etc/shadow (the password hash is never read into the output)." "$pwrec"

# ================================================================ F
section 'F : Backup'
getk() { printf '%s' "$1" | grep -oE "(^|[&=])$2=[^&]*" | head -n 1 | sed -E "s/^[&=]?$2=//"; }
CRON_TEXT=''
for src in /etc/cron.d/directadmin_cron /var/spool/cron/diradmin /var/spool/cron/crontabs/diradmin; do [[ -r $src ]] && CRON_TEXT+=$(cat "$src" 2>/dev/null)$'\n'; done
CRON_TEXT+=$(run crontab -u diradmin -l)
cron_alive=0; active crond cron && cron_alive=1
BK_LIST="$DA_DIR/data/admin/backup_crons.list"
n_jobs=0; n_daily=0; n_weekly=0; n_monthly=0; n_local=0; n_remote=0; n_unsched=0; job_ev=''; local_paths=''
if [[ -r $BK_LIST ]]; then
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        act=$(getk "$line" action); [[ -z $act || $act == backup ]] || continue
        hour=$(getk "$line" hour); [[ -n $hour ]] || continue
        id=$(getk "$line" id); where=$(getk "$line" where); dow=$(getk "$line" dayofweek); dom=$(getk "$line" dayofmonth)
        lp=$(getk "$line" local_path); fh=$(getk "$line" ftp_ip); fp=$(getk "$line" ftp_path); who=$(getk "$line" who)
        ((n_jobs++))
        in_cron=0
        if [[ -n $id ]]; then printf '%s\n' "$CRON_TEXT" | grep -E 'action=backup' | grep -Eq "id=${id}([^0-9]|$)" && in_cron=1
        else printf '%s\n' "$CRON_TEXT" | grep -q 'action=backup' && in_cron=1; fi
        if (( ! in_cron || ! cron_alive )); then ((n_unsched++)); job_ev+="job id=${id:-?} defined but crontab entry/cron service not confirmed; "; continue; fi
        freq=daily
        if [[ $dom =~ ^[0-9]+$ ]]; then freq=monthly; elif [[ $dow != '*' && -n $dow ]] && [[ $(printf '%s' "$dow" | tr ',' '\n' | awk 'NF{n++}END{print n+0}') -lt 5 ]]; then freq=weekly; fi
        case $freq in daily) ((n_daily++));; weekly) ((n_weekly++));; monthly) ((n_monthly++));; esac
        if [[ $where == local || ( -z $where && -z $fh ) ]]; then ((n_local++)); lp=${lp%%%*}; [[ $lp == /* ]] && local_paths+="$lp "; dest="local ${lp:-/home/admin/admin_backups}"
        else ((n_remote++)); dest="remote ${where:-ftp} ${fh:-?}:${fp:-/}"; fi
        job_ev+="job id=${id:-?} $freq hour=$hour who=${who:-all} -> $dest (scheduled in crontab); "
    done < "$BK_LIST"
fi
jb_present=0; jb_d=0; jb_w=0; jb_m=0; jb_jobs=0; jb_ev=''
if have jetbackup5api || active jetbackup5d jetbackupd; then jb_present=1; fi
if have jetbackup5api; then
    jo=$(run jetbackup5api -F listBackupJobs -D 'limit=0' -O json)
    if printf '%s' "$jo" | grep -Eq '"success"[[:space:]]*:[[:space:]]*1'; then
        names=$(printf '%s' "$jo" | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/^"name"[[:space:]]*:[[:space:]]*"([^"]*)"/\1/' | sort -u)
        jb_jobs=$(printf '%s\n' "$names" | awk 'NF{n++}END{print n+0}')
        printf '%s\n' "$names" | grep -qi daily && jb_d=1; printf '%s\n' "$names" | grep -qi weekly && jb_w=1; printf '%s\n' "$names" | grep -qi monthly && jb_m=1
        jb_ev="JetBackup5 jobs seen: $(printf '%s' "$names" | head -n 12 | tr '\n' ',') (frequency guessed from job NAME only; schedule/enabled state not parsed). "
    else jb_ev='JetBackup5 present but job list not readable (UNVERIFIED). '; fi
    unset jo
elif (( jb_present )); then jb_ev='JetBackup seen but jetbackup5api missing (UNVERIFIED). '; fi
cron_tool=0
for file in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [[ -f $file && -r $file && ! -L $file ]] || continue
    grep -Eq '(^|[[:space:]/])(rsnapshot|restic|borg|borgmatic|duplicity|rdiff-backup|rclone|r1soft|idrive)([[:space:]]|$)' "$file" 2>/dev/null && { cron_tool=1; job_ev+="third-party backup tool entry in $file; "; }
done

# latest artifact
backup_file=''; backup_time=0; backup_size=0; partial=0
search_roots=(); for r in $local_paths "${BACKUP_DIRS[@]}"; do [[ -d $r && ! -L $r ]] && search_roots+=("$r"); done
for root in "${search_roots[@]}"; do
    listing=$(timeout -k 2s 30s find "$root" -xdev -maxdepth 5 -type f \( -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.tar.zst' -o -iname '*.zip' -o -iname '*.sql.gz' \) -printf '%T@\t%s\t%p\n' 2>/dev/null)
    (( $? == 0 )) || partial=1
    while IFS=$'\t' read -r t s p; do t=${t%%.*}; [[ $t =~ ^[0-9]+$ && $s =~ ^[0-9]+$ ]] || continue; (( t>backup_time )) && { backup_time=$t; backup_size=$s; backup_file=$p; }; done <<< "$listing"
done

bk_basis="DirectAdmin backup jobs in backup_crons.list=$n_jobs (confirmed in crontab=$((n_jobs-n_unsched)), not confirmed=$n_unsched); ${job_ev}${jb_ev}"
bk_data='Data fetched: data/admin/backup_crons.list (schedule/destination fields only - FTP user and password are never read into the output), /etc/cron.d/directadmin_cron and diradmin crontab (to confirm the job is scheduled), cron service state, JetBackup job names, third-party backup cron entries.'

if (( n_local>0 || cron_tool )); then ls='Configured'; else ls='Not configured'; fi
if [[ $ls == Configured ]]; then lrec='A local backup job is scheduled. Please confirm the retention and that there is enough free disk space; we can test a restore from the latest local backup.'; else lrec='A local backup is not configured. We recommend regular DirectAdmin backups (Admin Backup/Transfer) to a local directory plus a remote copy, so an account can be restored quickly. Please confirm backup scope, frequency and retention.'; fi
emit 'LOCAL BACKUP' "$ls" "Status basis: local-destination backup jobs scheduled=$n_local; third-party tool=$cron_tool. $bk_basis$bk_data" "$lrec"

if (( n_remote>0 )); then rs='Configured'; elif (( jb_present )) || (( cron_tool )); then rs=NA; else rs='Not configured'; fi
case "$rs" in
    Configured) rrec2='A scheduled backup sends copies to a remote destination. Please confirm the retention at the destination and let us test a restore from it; credentials stay in the panel.';;
    NA) rrec2='A backup tool is present but the destination type could not be read. Please let us confirm the remote destination and run a test restore.';;
    *) rrec2='No remote (off-server) backup is configured, so a server failure would lose the backups too. We recommend adding a scheduled remote backup (FTP/FTPS, S3-compatible or another server) with agreed retention.';;
esac
emit 'REMOTE BACKUP' "$rs" "Status basis: remote-destination backup jobs scheduled=$n_remote. $bk_basis$bk_data" "$rrec2"

for freq in DAILY WEEKLY MONTHLY; do
    case $freq in DAILY) c=$n_daily; j=$jb_d;; WEEKLY) c=$n_weekly; j=$jb_w;; MONTHLY) c=$n_monthly; j=$jb_m;; esac
    if (( c>0 || j>0 )); then fs=Configured; frec="A $freq backup is scheduled. Please confirm the retention you need and let us test a restore; a schedule alone does not prove every run succeeded."
    else fs='Not configured'; frec="A $freq backup is not configured. We recommend adding a $freq backup with an agreed retention period. Please confirm the schedule and retention you want."; fi
    emit "$freq BACKUP" "$fs" "Status basis: scheduled DirectAdmin jobs of this frequency=$c; JetBackup job named '${freq,,}'=$j. Frequency is derived from dayofweek/dayofmonth fields (daily: both *; weekly: fewer than 5 weekdays; monthly: a day-of-month). $bk_basis$bk_data" "$frec"
done

if (( backup_time>0 )); then
    bage=$(((NOW-backup_time)/86400))
    if (( NOW>=backup_time && NOW-backup_time<=BACKUP_MAX_DAYS*86400 && backup_size>0 )); then rl='Recent Backups Available'; else rl='No recent backups'; fi
elif (( n_remote>0 && n_local==0 )); then rl=NA; bage=unknown
else rl='No recent backups'; bage=unknown; fi
case "$rl" in
    'Recent Backups Available') lrec3="The latest backup is ${bage} day(s) old and non-empty. Please keep monitoring the backup e-mail reports; we can run a test restore to prove it is usable.";;
    NA) lrec3='Backups go to a remote destination only, so no local file can be checked. Please let us confirm the latest run in the remote location and the DirectAdmin task queue log.';;
    *) lrec3="No backup newer than ${BACKUP_MAX_DAYS} days was found. We recommend checking the DirectAdmin backup job, free disk space and destination credentials, and running a fresh backup. Please confirm the expected backup frequency.";;
esac
emit 'RECENT LAST BACKUP' "$rl" "Status basis: newest backup file=${backup_file:-none}; age=${bage:-unknown} days; size=$backup_size bytes; threshold=$BACKUP_MAX_DAYS days. Data fetched: newest archive modification time and size under ${search_roots[*]:-no backup directory}. Success of the backup run itself is not read; search partial=$partial." "$lrec3"

if [[ -n $backup_file ]] && (( EXPECTED_BACKUP_BYTES>0 )); then
    if (( backup_size>=EXPECTED_BACKUP_BYTES )); then sz='Expected size'; szr='The latest backup is at least the expected size. Please keep comparing sizes over time; we can validate with a restore.'; else sz='Too small'; szr='The latest backup is smaller than expected and may be incomplete. We recommend checking the backup log and running a test restore.'; fi
else sz=NA; szr='No expected size was supplied, so size cannot be judged. Please give us a known-good size (or let us compare against previous backups) and we can validate it; size alone cannot prove integrity.'; fi
emit 'SIZE OF LAST BACKUP' "$sz" "Status basis: newest backup ${backup_file:-none} is $backup_size bytes; supplied minimum=$EXPECTED_BACKUP_BYTES. Data fetched: file size of the newest archive. Unknown baseline stays NA." "$szr"

printf 'Audit complete. Nothing was changed. Review every UNVERIFIED/NA item before submitting the audit.\n'
exit 0
