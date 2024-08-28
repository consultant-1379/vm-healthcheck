#!/bin/bash

CONF=ping_hosts.conf

PING=/bin/ping
[[ $(uname -a ) == SunOS* ]] && PING=/usr/sbin/ping


function log {
    local prefix="$(date '+%Y-%m-%d %H:%M:%S')"
    local stdout=/dev/stdout

    [[ -z "$LOG_FILE" ]] && LOG_FILE=/dev/null
    [[ "$LOG_STDOUT" = true ]] || stdout=/dev/null
    [[ $# -gt 0 ]] && echo "$prefix $@" | tee -a $LOG_FILE > $stdout             # LOG ARGS
    [[ -p /dev/stdin ]] && { sed "s/^/$prefix /g"| tee -a $LOG_FILE > $stdout;}  # LOG PIPED STDIN - NOT WORKING FOR SOLARIS
    return 0
}


function send_mail {
    local subject="$1"
    local message="$2"

    local data=$(cat <<EOF
{ "personalizations":
[ { "to": [ { "email" : "$MAIL_TO" } ],
"subject" : "$subject" } ],
"from": { "email" : "$MAIL_FROM" },
"content" : [ { "type" : "text/plain", "value" : "$message" } ] }
EOF
    )

    curl --connect-timeout 10 -v  -k \
         -H 'content-type: application/json' \
         --data "$data" $MAIL_URL &>/dev/null
    return $?
}


function error {
    log ERROR "$@"

    send_mail "Ping Azure From $(hostname) failure" "$@"            &&
                     log "INFO  sent notification mail to $MAIL_TO" ||
                     log "ERROR failed to send notification mail to $MAIL_URL"
    exit 1
}


source $CONF || error "Could not read script configuration file $CONF"

for i in HOSTS RETRIES RETRY_WAIT LOG_FILE MAIL_URL MAIL_FROM MAIL_TO ; do
   [[ -z ${!i} ]] && error "$i is not defined in $CONF"
done


echo "$(tail -10000 $LOG_FILE 2>/dev/null)" > $LOG_FILE

log Started $0

for host in $(tr ',' ' ' <<< $HOSTS) ; do
    FAIL=true
    for seq in 1 $RETRIES ; do
        $PING $host > /dev/null 2>&1 && FAIL=false && break
        sleep $RETRY_WAIT
    done

    $FAIL && error "Failed to ping $host"
    log "INFO  host $host pinged successfully"
done
