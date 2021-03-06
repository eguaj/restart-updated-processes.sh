# restart-updated-processes.sh

Restart (update|upgrade)d processes.

After updating a system library (e.g. libc, libssl or libcurl), the processes
loaded on boot will still use the old library which was also loaded on boot.

This script is meant to detect theses processes (libs marked as deleted in
`/proc/%pid/maps`) and restart them in order to load the new library.

The restart is done by matching the processes name (or command line) against a
list of known names with the corresponding restart instructions.

At the present time, this script is meant for use with Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS.

# Usage

Default mode is to scan the processes and report what would be done:

    # ./restart-updated-processes.sh root@www.example.net
    [...]
    18881   /usr/lib/postgresql/9.1/bin/postgres [/usr/lib/postgresql/9.1/bin/postgres -D /var/lib/postgresql/9.1/main -c config_file=/etc/postgresql/9.1/main/postgresql.conf ]
            # service postgresql restart
    32397   /usr/sbin/sshd [/usr/sbin/sshd -D ]
            # service ssh restart
    514 /sbin/dhclient3 [dhclient3 -e IF_METRIC=100 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -1 eth0 ]
            # ifdown eth0
            # ifup   eth0
    529 /usr/sbin/rsyslogd [rsyslogd -c5 ]
            # service rsyslog restart
    626 /sbin/getty [/sbin/getty -8 38400 tty4 ]
            # kill 626
    [...]

To effectively restart the processes, use the `restart` argument:

    # ./restart-updated-processes.sh root@www.example.net restart
    [...]
    18881   /usr/lib/postgresql/9.1/bin/postgres [/usr/lib/postgresql/9.1/bin/postgres -D /var/lib/postgresql/9.1/main -c config_file=/etc/postgresql/9.1/main/postgresql.conf ]
    restart postgresql
    * Restarting PostgreSQL 9.1 database server
    ...done.
    32397   /usr/sbin/sshd [/usr/sbin/sshd -D ]
    restart ssh
    ssh stop/waiting
    ssh start/running, process 2215
    514 /sbin/dhclient3 [dhclient3 -e IF_METRIC=100 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -1 eth0 ]
    ssh stop/waiting
    ssh start/running, process 2372
    529 /usr/sbin/rsyslogd [rsyslogd -c5 ]
    restart rsyslog
    rsyslog stop/waiting
    rsyslog start/running, process 2404
    626 /sbin/getty [/sbin/getty -8 38400 tty4 ]
    [...]

If you use [`apt-dater`](https://www.ibh.de/apt-dater/) to manage/upgrade your
hosts, you can use the `apt-dater`'s groups.

List `apt-dater`'s groups:

    # ./restart-updated-processes.sh --apt-dater
    "Frontend servers":
            www1.example.net
            www2.example.net
    "Backend servers":
            back1.example.net
            back2.example.net

Apply to a specific `apt-dater`'s group:

    # ./restart-updated-processes.sh --apt-dater "Frontend servers"

    # ./restart-updated-processes.sh --apt-dater "Frontend servers" restart

Apply to all `apt-dater`'s groups:

    # ./restart-updated-processes.sh --apt-dater "*"

    # ./restart-updated-processes.sh --apt-dater "*" restart

To run locally (i.e. without passing through SSH) use the `--inject` argument:

    # ./restart-updated-processes.sh --inject

