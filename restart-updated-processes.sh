#!/bin/bash

shopt -s nullglob

function usage {
    local ME=$(basename "$0")
    cat <<EOF

Usage:

    $ME <login@host.name> ['restart']
    $ME --apt-dater <groupName>|'*' ['restart']

EOF
}

function check_compatibility {
    local DISTRIB=$(lsb_release -s -i)-$(lsb_release -s -r)
    case $DISTRIB in
	Ubuntu-12.04*)
	    ;;
	Ubuntu-14.04*)
	    ;;
	*)
	    printf "Error: unsupported distribution '%s'.\n" "$DISTRIB" 1>&2
	    exit 1
    esac
}

function echo_service {
    local NAME=$1
    local OP=$2
    if [ -z "$OP" ]; then
	OP="restart"
    fi
    echo -n "$FG_YELLOW"
    if [ "$COMMAND" = "restart" ]; then
	echo "$OP" "$NAME"
	service "$NAME" "$OP"
    else
	printf "\t# service %s %s\n" "$NAME" "$OP"
    fi
    echo -n "$COLOR_RESET"
}

function echo_kill {
    local PID=$1
    echo -n "$FG_YELLOW"
    if [ "$COMMAND" = "restart" ]; then
	kill "$PID"
    else
	printf "\t# kill %s\n" "$PID"
    fi
    echo -n "$COLOR_RESET"
}

function echo_run {
    local CMD=$1
    shift
    echo -n "$FG_YELLOW"
    if [ "$COMMAND" = "restart" ]; then
	"$CMD" "$@" &
    else
	local ARGS=""
	while [ $# -gt 0 ]; do
	    ARGS=$(printf "%s %q" "$ARGS" "$1")
	    shift
	done
	printf "\t# %s %s\n" "$CMD" "$ARGS"
    fi
    echo -n "$COLOR_RESET"
}

function echo_intf_restart {
    local CMDLINE=$1
    local INTF=$(echo "$CMDLINE" | awk '{print $(NF)}')
    if [ -z "$INTF" ]; then
	printf "\t\t%s*** dhclient interface not found ***%s\n" "$FG_RED" "$COLOR_RESET"
	return
    fi
    echo -n "$FG_YELLOW"
    if [ "$COMMAND" = "restart" ]; then
	ifdown "$INTF"
	ifup "$INTF"
    else
	printf "\t# ifdown %s\n" "$INTF"
	printf "\t# ifup   %s\n" "$INTF"
    fi
    echo -n "$COLOR_RESET"
}

function profile_restart {
    local PID=$1
    local BIN=$2
    local CMDLINE=$3

    kill -0 "$PID"
    if [ $? -ne 0 ]; then
	return
    fi

    printf "%s%s\t%s [%s]%s\n" "$FG_BLUE" "$PID" "$BIN" "$CMDLINE" "$COLOR_RESET"

    case "$CMDLINE" in
	*/BackupPC\ *)
	    echo_service backuppc restart
	    return
	    ;;
	*/qwebirc/run.py*)
	    echo_service qwebirc stop
	    echo_service qwebirc start
	    return
	    ;;
	*/bin/te_request_server*)
	    echo_service ted restart
	    return
	    ;;
	*/usr/sbin/xe-daemon*)
	    echo_service xe-linux-distribution restart
	    return
	    ;;
	*/usr/sbin/snmptt*)
	    echo_service snmptt restart
	    return
	    ;;
	*/openntpd/*)
	    echo_service openntpd restart
	    return
	    ;;
    esac

    case "$BIN" in
	/sbin/mdadm)
	    echo_service mdadm restart
	    ;;
	/usr/sbin/irqbalance)
	    echo_service irqbalance restart
	    ;;
	/usr/lib/ipsec/pluto)
	    echo_service ipsec restart
	    ;;
	/usr/lib/ipsec/charon)
	    echo_service ipsec restart
	    ;;
	/usr/sbin/dnsmasq)
	    echo_service dnsmasq restart
	    ;;
	/usr/sbin/pcscd)
	    echo_service pcscd restart
	    ;;
	tlsmgr*)
	    echo_service postfix restart
	    ;;
	/usr/lib/postfix/master)
	    echo_service postfix restart
	    ;;
	/usr/sbin/acpid)
	    echo_service acpid restart
	    ;;
	/usr/sbin/apache2)
	    echo_service apache2 restart
	    ;;
	/usr/sbin/xinetd)
	    echo_service xinetd restart
	    ;;
	/usr/sbin/inetd)
	    echo_service openbsd-inetd restart
	    ;;
	postgres:|*postgresql*)
	    echo_service postgresql restart
	    ;;
	/usr/sbin/zabbix_agentd)
	    echo_service zabbix-agent restart
	    ;;
	/usr/sbin/zabbix_server)
	    echo_service zabbix-server restart
	    ;;
	/usr/sbin/nagios3)
	    echo_service nagios3 restart
	    ;;
	/usr/sbin/smokeping*)
	    echo_service smokeping restart
	    ;;
	/usr/sbin/atd)
	    echo_service atd restart
	    ;;
	/usr/sbin/sshd)
	    echo_service ssh restart
	    ;;
	/usr/bin/redis-server*)
	    echo_service redis-server restart
	    ;;
	*/gitlab/*)
	    echo_service gitlab restart
	    ;;
	/usr/sbin/named)
	    echo_service bind9 restart
	    ;;
	/usr/sbin/rsyslogd)
	    echo_service rsyslog restart
	    ;;
	/usr/sbin/syslog-ng)
	    echo_service syslog-ng  restart
	    ;;
	/usr/sbin/mysqld)
	    echo_service mysql restart
	    ;;
	/usr/sbin/ntpd)
	    echo_service ntp restart
	    ;;
	/usr/sbin/cron)
	    echo_service cron restart
	    ;;
	/usr/sbin/openvpn)
	    echo_service openvpn restart
	    ;;
	/usr/sbin/dhcpd)
	    echo_service isc-dhcp-server restart
	    ;;
	proftpd:*)
	    echo_service proftpd restart
	    ;;
	pure-ftpd*)
	    echo_service pure-ftpd restart
	    ;;
	/sbin/rpcbind)
	    echo_service portmap restart
	    ;;
	/usr/sbin/rpc.idmapd)
	    echo_service idmapd restart
	    ;;
	/sbin/rpc.statd)
	    echo_service statd restart
	    ;;
	/usr/sbin/rpc.mountd)
	    echo_service nfs-kernel-server restart
	    ;;
	/usr/sbin/ircd-hybrid)
	    echo_service ircd-hybrid restart
	    ;;
	/sbin/udevd|/lib/systemd/systemd-udevd)
	    echo_service udev restart
	    ;;
	/bin/dbus-daemon)
	    echo_service dbus restart
	    ;;
	/usr/sbin/console-kit-daemon)
	    echo_service dbus restart
	    ;;
	/usr/lib/policykit-1/polkitd)	
	    echo_service dbus restart
	    ;;
	/usr/bin/memcached)
	    echo_service memcached restart
	    ;;
	/usr/sbin/lpd)
	    echo_service lpd restart
	    ;;
	avahi-daemon:*)
	    echo_service avahi-daemon restart
	    ;;
	nginx:*)
	    echo_service nginx restart
	    ;;
	php-fpm:*)
	    echo_service php5-fpm restart
	    ;;
	/usr/sbin/VBoxService)
	    echo_service virtualbox-guest-utils restart
	    ;;
	/usr/lib/virtualbox/vboxwebsrv)
	    echo_service vboxweb-service restart
	    ;;
	/usr/sbin/nullmailer-send)
	    echo_service nullmailer restart
	    ;;
	/usr/sbin/vmtoolsd)
	    echo_kill "$PID"
	    echo_run /usr/sbin/vmtoolsd
	    ;;
	/sbin/upstart-socket-bridge)
	    echo_kill "$PID"
	    ;;
	/sbin/getty)
	    echo_kill "$PID"
	    ;;
	/sbin/dhclient|/sbin/dhclient3)
	    echo_intf_restart "$CMDLINE"
	    ;;
	/usr/bin/whoopsie)
	    echo_kill "$PID"
	    ;;
	/usr/sbin/in.tftpd)
	    echo_service tftpd-hpa restart
	    ;;
	/usr/sbin/pxe)
	    echo_service pxe restart
	    ;;
	/usr/sbin/snmpd)
	    echo_service snmpd restart
	    ;;
	/usr/sbin/smartd)
	    echo_service smartd restart
	    ;;
	/sbin/init)
	    ;;
	sshd:)
	    ;;
	"")
	    ;;
	*)
	    printf "\t\t%s*** unknown ***%s\n" "$FG_RED" "$COLOR_RESET"
	    ;;
    esac
}

function main_inject {
    check_compatibility
    COMMAND=$1
    declare -A DONE
    for CMDLINE in /proc/*/cmdline; do
	PDIR=$(dirname "$CMDLINE")
	( grep '(deleted)' "$PDIR/maps" | grep '\.so' ) > /dev/null 2>&1
	if [ $? -ne 0 ]; then
	    continue
	fi
	PID=$(basename "$PDIR")
	if [ "$PID" = "self" ]; then
	    continue
	fi
	BIN=$(perl -ne 'BEGIN{$/=undef};@_=split("\x00", $_);printf("%s\n",$_[0]);' "$CMDLINE")
	CMDLINE=$(sed -e 's/\x0/ /g' "$CMDLINE")
	if [ "${BIN:0:1}" != "/" ]; then
	    FQBIN=$(which -- "$BIN")
	    if [ -n "$FQBIN" ]; then
		BIN=$FQBIN
	    fi
	fi
	profile_restart "$PID" "$BIN" "$CMDLINE"
    done
}

function restart_updated_single_host {
    if [ $# -eq 0 ]; then
	usage
	return 1
    fi
    ssh -o ConnectTimeout=5 "$1" /bin/bash /dev/stdin "--inject" "$2" < "$0"
}

function get_apt_dater_hosts {
    type -p php > /dev/null
    if [ $? -ne 0 ]; then
	printf "Missing required 'php' command!\n" 1>&2
	return 1
    fi
    php -r '
ini_set("error_log", null);
$ini = file_get_contents($argv[1]);
$ini = preg_replace("/;/", ",", $ini);
$ini = parse_ini_string($ini, true);
$groups = array();
foreach ($ini as $group => $conf) {
    $hosts = array();
    foreach ($conf as $k => $v) {
	if ($k == "Hosts") {
	    $hosts = preg_split("/\s*,\s*/", $v);
	    break;
	}
    }
    $groups[$group] = $hosts;
}
if (!isset($argv[2]) || $argv[2] == "") {
    foreach ($groups as $group => $hosts) {
	error_log(sprintf("\"%s\":", $group));
	foreach ($hosts as $host) {
	    error_log(sprintf("\t%s", $host));
	}
    }
    exit(1);
} else {
    foreach ($groups as $group => $hosts) {
	if ($group != $argv[2] && $argv[2] != "*") {
	    continue;
	}
	foreach ($hosts as $host) {
	    printf("%s\n", $host);
	}
    }
}
    ' ~/.config/apt-dater/hosts.conf "$1"
}

function restart_updated_apt_dater_group {
    local HOSTS=($(get_apt_dater_hosts "$1"))
    for H in ${HOSTS[@]}; do
	printf "[+] Processing host \"%s\"\n" "$H"
	restart_updated_single_host "$H" "$2"
    done
}

function define_colors {
    FG_RED=$(echo -e '\x1b[31m')
    FG_GREEN=$(echo -e '\x1b[32m')
    FG_YELLOW=$(echo -e '\x1b[33m')
    FG_BLUE=$(echo -e '\x1b[34m')
    COLOR_RESET=$(echo -e '\x1b[0m')
}

function main {
    define_colors
    case "$1" in
	--help)
	    usage
	    return 1
	    ;;
	--inject)
	    shift
	    main_inject "$@"
	    ;;
	--apt-dater)
	    shift
	    restart_updated_apt_dater_group "$@"
	    ;;
	*)
	    restart_updated_single_host "$@"
	    ;;
    esac
}

main "$@"
