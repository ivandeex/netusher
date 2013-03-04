#!/usr/bin/perl
#
# NetUsher
# Interface with OpenVPN, IPtables and DNS
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/nu-common.inc.pm";

#
# require: perl-DBD-mysql
#
use DBI;

our (%nu_config, $progname, %ev_watch, $ev_loop);

##############################################
# interaction with openvpn
#

our (@vpn_regex);
my  (%vpn_session);


sub vpn_init () {
    vpn_close();

    # create regular expression for vpn network
    @vpn_regex = split /\s*,\s*/, $nu_config{vpn_net};
    for my $i (0 .. $#vpn_regex) {
        my $regex = $vpn_regex[$i];
        fail("vpn_net: invalid format \"$regex\", shall be A.B.C.0")
            if $regex !~ /^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        $regex =~ s/(\.0+)+$//;
        $regex .= ".";
        $regex =~ s/\./\\./g;
        $vpn_regex[$i] = qr[$regex];
    }

    for my $path (@nu_config{qw[vpn_event_dir vpn_archive_dir]}) {
        fail("$path: path must be absolute") if $path && $path !~ m!^/!;
    }

    for my $path (split /\s*,\s*/, $nu_config{vpn_status_file}) {
        if ($path) {
            fail("$path: path must be absolute") if $path !~ m!^/!;
            # by default search for events in the status file directory
            if ($nu_config{vpn_event_mask} && !$nu_config{vpn_event_dir}) {
                ($nu_config{vpn_event_dir} = $path) =~ s!/+[^/]*$!!; #!
            }
        }
    }

    if ($nu_config{vpn_scan_interval}) {
        #
        # setup scanner
        #
        $ev_watch{vpn_scan_timer} = $ev_loop->timer(
                                        0, $nu_config{vpn_scan_interval},
                                        \&vpn_scan);
        $ev_watch{vpn_scan_signal} = $ev_loop->signal("USR2", \&vpn_scan);

        # create directories
        for my $dir (@nu_config{qw[vpn_event_dir vpn_archive_dir]}) {
            create_parent_dir("$dir/dummy_file") if $dir;
        }

        #
        # setup vpn ip mapping 
        #
        my $sth = db_execute("SELECT vpn_ip, real_ip, cname,
                                UNIX_TIMESTAMP(beg_time)
                                FROM nu_openvpn WHERE running = 1");
        my @purge;
        while (my @row = $sth->fetchrow_array) {
            my ($vpn_ip, $real_ip, $cname, $beg_time) = @row;
            if (exists($vpn_session{$vpn_ip})
                    && $vpn_session{$vpn_ip}{beg_time} != $beg_time) {
                if ($beg_time < $vpn_session{$vpn_ip}{beg_time}) {
                    push @purge, [ $vpn_ip, $beg_time ];
                    next;
                } else {
                    push @purge, [ $vpn_ip, $vpn_session{$vpn_ip}{beg_time} ];
                }
            }
            $vpn_session{$vpn_ip}{real_ip} = $real_ip;
            $vpn_session{$vpn_ip}{beg_time} = $beg_time;
            $vpn_session{$vpn_ip}{cname} = $cname;
        }

        # purge stale old sessions
        for my $ip_time (@purge) {
            db_execute("UPDATE nu_openvpn SET running = 0
                            WHERE beg_time = FROM_UNIXTIME(?) AND vpn_ip = ?",
                        $ip_time->[0], $ip_time->[1]);
        }
    }
}

sub vpn_close () {
    delete $ev_watch{vpn_scan_timer};
    delete $ev_watch{vpn_scan_signal};
    %vpn_session = ();
}

#
# periodic scan of openvpn status
#
sub vpn_scan () {
    #
    # scan and read all messages
    #
    if ($nu_config{vpn_event_dir} && $nu_config{vpn_event_mask}) {
        my %messages;
        my $cfg_mask = $nu_config{vpn_cfg_mask};
        my $path_mask = $nu_config{vpn_event_dir}."/".$nu_config{vpn_event_mask};
        my $arch_dir = $nu_config{vpn_archive_dir};

        # pick up all events from openvpn
        for my $path (glob $path_mask) {
            if (open(my $file, $path)) {
                my $msg = {};
                while(<$file>) {
                    chomp; s/^\s+//; s/\s+$//;
                    next unless m/^(\w+)=(\S.*)$/;
                    $msg->{$1} = $2;
                }
                close($file);
                $msg->{cmd_path} = $path;
                if ($msg->{time_unix}) {
                    $messages{ $msg->{time_unix} } = $msg;
                    #debug("$path: new vpn event");
                    next;
                }
            }
            info("$path: broken vpn event");
        }

        # handle gathered messages ordered by time
        for my $stamp (sort { $a <=> $b } keys %messages) {
            my $msg = $messages{$stamp};
            my $path = $msg->{cmd_path};
            my $event = $msg->{script_type};
            my $vpn_ip = $msg->{ifconfig_pool_remote_ip};
            my $beg_time = $msg->{time_unix};
            undef $beg_time if $beg_time !~ /^\d+/;
            debug("$path: next vpn event:$event vpn:$vpn_ip time:$beg_time");

            if ($cfg_mask && $msg->{config} !~ m/$cfg_mask/) {
                info("%s: foreign vpn event (%s)",
                    $msg->{cmd_path}, $msg->{config});
            }
            elsif ($event eq "client-connect") {
                if ($vpn_ip && $beg_time) {
                    vpn_connected(
                        "event",
                        vpn_ip      => $vpn_ip,
                        beg_time    => $beg_time,
                        end_time    => $beg_time,
                        cname       => $msg->{common_name},
                        real_ip     => $msg->{trusted_ip},
                        real_port   => $msg->{trusted_port}
                        );
                } else {
                    debug("$path: invalid vpn event without IP & time");
                }
            }
            elsif ($event eq "client-disconnect") {
                if ($vpn_ip) {
                    my $end_time = $beg_time
                                    ? $beg_time + $msg->{time_duration}
                                    : undef;
                    vpn_disconnected(
                        "event",
                        vpn_ip      => $vpn_ip,
                        beg_time    => $beg_time,
                        end_time    => $end_time,
                        cname       => $msg->{common_name},
                        real_ip     => $msg->{trusted_ip},
                        rx_bytes    => $msg->{bytes_received},
                        tx_bytes    => $msg->{bytes_sent}
                        );
                } else {
                    debug("$path: invalid vpn event without IP");
                }
            }
            else {
                info("%s: unknown vpn event \"%s\"",
                    $msg->{cmd_path}, $event);
            }

            # archive for debugging
            if ($arch_dir) {
                (my $arch = $path) =~ s!^.*/!!g;
                $arch = "$arch_dir/$arch";
                if (open(my $file, "> $arch")) {
                    print $file $_."=".$msg->{$_}."\n"
                        for (sort keys %$msg);
                    close($file);
                    #debug("$arch: archive created");
                } else {
                    info("$arch: cannot write archive");
                }
            }

            # remove event file
            unlink($path);
            #debug("$path: event file removed");
        }

        if (%messages) {
            debug("handled %d vpn events", scalar(keys %messages));
            # make a short pause after event and let status file update
            $ev_watch{vpn_scan_timer}->set($nu_config{vpn_scan_pause},
                                            $nu_config{vpn_scan_interval});
            return;
        }
    }

    #
    # scan openvpn status file
    #
    for my $path (split /\s*,\s*/, $nu_config{vpn_status_file}) {
        if ($path && open(my $file, $path)) {
            my %active;
            while(<$file>) {
                chomp(my $line = $_);
                my ($tag, $cname, $real_ip_port, $vpn_ip,
                    $rx_bytes, $tx_bytes, $beg_iso, $beg_time)
                    = split /,/, $line;
                next if $tag ne "CLIENT_LIST";
                my ($real_ip, $real_port) = split /:/, $real_ip_port;

                if (!$vpn_ip || !$beg_time || $beg_time !~ /^\d+/) {
                    debug("invalid vpn status line without IP/time: \"$line\"")
                        if $cname ne "UNDEF";
                    next;
                }
                if (!$cname || $cname eq "UNDEF") {
                    # don't care
                    undef $cname;
                }

                my $modified = vpn_connected(
                    "status",
                    vpn_ip      => $vpn_ip,
                    beg_time    => $beg_time,
                    end_time    => undef,
                    cname       => $cname,
                    real_ip     => $real_ip,
                    real_port   => $real_port,
                    rx_bytes    => $rx_bytes,
                    tx_bytes    => $tx_bytes
                    );
                debug("vpn status line was: \"$line\"") if $modified;

                $active{$vpn_ip} = 1;
            }
            close($file);

            # everyone beyond the list should be marked disconnected
            for my $vpn_ip (sort keys %vpn_session) {
                if (!$active{$vpn_ip}) {
                    vpn_disconnected(
                        "status",
                        vpn_ip      => $vpn_ip,
                        cname       => $vpn_session{$vpn_ip}{cname},
                        real_ip     => $vpn_session{$vpn_ip}{real_ip},
                        beg_time    => $vpn_session{$vpn_ip}{beg_time}
                        );
                }
            }
        } else {
            debug("$path: cannot read vpn status");
        }
    }
}

#
# mark vpn client as connected
# required fields: vpn_ip, beg_time, cname, real_ip
# optional fields: end_time, real_port, rx_bytes, tx_bytes
#
sub vpn_connected ($%) {
    my ($msg, %arg) = @_;
    my ($vpn_ip, $beg_time) = ($arg{vpn_ip}, $arg{beg_time});
    $arg{cname} =~ s/^client-//;
    my $modified = 0;

    # remove previous sessions, if any
    if (exists($vpn_session{$vpn_ip})
            && $vpn_session{$vpn_ip}{beg_time} ne $beg_time) {
        debug("purge previous vpn session vpn:$vpn_ip ($msg)");
        db_execute("
            UPDATE nu_openvpn SET running = 0, end_time = FROM_UNIXTIME(?)
            WHERE beg_time < FROM_UNIXTIME(?) AND vpn_ip = ? AND running = 1",
            $arg{beg_time} - 1, $arg{beg_time}, $arg{vpn_ip});
        delete $vpn_session{$vpn_ip};
    }

    if (exists $vpn_session{$vpn_ip}) {
        # prolong existsing session
        db_execute("
            UPDATE nu_openvpn SET end_time = COALESCE(FROM_UNIXTIME(?),NOW()),
                running=1, cname = COALESCE(?,cname),
                rx_bytes = COALESCE(?,rx_bytes), tx_bytes = COALESCE(?,tx_bytes)
            WHERE vpn_ip = ? AND beg_time = FROM_UNIXTIME(?)",
            $arg{end_time}, $arg{cname}, $arg{rx_bytes}, $arg{tx_bytes},
            $vpn_ip, $beg_time);
    } else {
        # create new session
        db_execute("
            INSERT INTO nu_openvpn (vpn_ip,beg_time,end_time,
                running,cname, real_ip,real_port,rx_bytes,tx_bytes)
            VALUES (?, FROM_UNIXTIME(?), COALESCE(FROM_UNIXTIME(?),NOW()),
                1,?, ?,?,?,?)",
            $vpn_ip, $beg_time, $arg{end_time},  $arg{cname},
            $arg{real_ip}, $arg{real_port}, $arg{rx_bytes}, $arg{tx_bytes});

        info("vpn $vpn_ip connected ($msg)");
        $vpn_session{$vpn_ip}{beg_time} = $beg_time;
        $vpn_session{$vpn_ip}{real_ip} = $arg{real_ip};
        $vpn_session{$vpn_ip}{cname} = $arg{cname};
        iptables_update($vpn_ip, 0, 1);
        dyndns_update(1, $arg{real_ip}, $arg{cname});
        $modified = 1;
    }

    db_commit();
    return $modified;
}

#
# mark vpn client as disconnected
# required fields: vpn_ip, beg_time, real_ip, cname
# optional fields: end_time, rx_bytes, tx_bytes
#
sub vpn_disconnected ($%) {
    my ($msg, %arg) = @_;
    my ($vpn_ip, $beg_time) = ($arg{vpn_ip}, $arg{beg_time});
    $arg{cname} =~ s/^client-//;
    my $modified = 0;

    if ($beg_time && exists($vpn_session{$vpn_ip})
            && $vpn_session{$vpn_ip}{beg_time} ne $beg_time) {
        info("ignoring stale disconnect vpn:$vpn_ip ($msg)");
        return 0;
    }

    db_execute("UPDATE nu_openvpn SET running = 0,
                    end_time = COALESCE(FROM_UNIXTIME(?),end_time),
                    rx_bytes = COALESCE(?,rx_bytes),
                    tx_bytes = COALESCE(?,tx_bytes)
                WHERE running = 1 AND vpn_ip = ?
                AND   (FROM_UNIXTIME(?) IS NULL OR beg_time = FROM_UNIXTIME(?))",
                $arg{end_time}, $arg{rx_bytes}, $arg{tx_bytes},
                $vpn_ip, $beg_time, $beg_time);
    db_commit();

    if (exists $vpn_session{$vpn_ip}) {
        info("vpn $vpn_ip disconnected ($msg)");
        # real ip can be shared by several vpn addresses
        # find if there are others using the same ip
        my $count = -1;
        for my $ip (keys %vpn_session) {
            $count++ if $vpn_session{$ip}{real_ip} eq $arg{real_ip};
        }
        debug("$count vpn sessions still use real ip $arg{real_ip}");
        iptables_update($vpn_ip, 0, $count);
        dyndns_update(0, $arg{real_ip}, $arg{cname});
        delete $vpn_session{$vpn_ip};
        $modified = 1;
    }

    return $modified;
}

##############################################
# Dynamic DNS
#

sub dyndns_init () {
    return unless $nu_config{ns_zone_real};
    require_program("nsupdate")
}

sub dyndns_update ($$$) {
    my ($enable, $real_ip, $cname) = @_;
    return unless $nu_config{ns_zone_real};

    $cname =~ s/^client-//;
    my $host = "${cname}.$nu_config{ns_zone_real}";

    my $cmd = "server $nu_config{ns_server}\n";
    $cmd .= "zone $nu_config{ns_zone_real}\n";
    $cmd .= "update delete $host A\n";
    $cmd .= "update add $host $nu_config{ns_rr_time} A $real_ip\n" if $enable;
    $cmd .= "send\n";

    my $temp = add_temp_file(undef);
    write_file($temp, $cmd);
    run_prog("$nu_config{nsupdate} $temp");
    del_temp_file($temp);
}

##############################################
# iptables control
#

use constant CHAIN_VPN  => 1;
use constant CHAIN_REAL => 2;
use constant CHAIN_USER => 4;
use constant CHAIN_HOST => 8;

my ($chains_enable, %chains_all, %chains_ips, %chains_extra);
my ($iptables_fail_num, $iptables_fail_log);

sub iptables_update ($$$) {
    my ($vpn_ip, $is_user_chain, $enable) = @_;
    return unless $chains_enable;

    my $real_ip;
    $real_ip = $vpn_session{$vpn_ip}{real_ip}
        if exists $vpn_session{$vpn_ip};

    my $chain_type = $is_user_chain ? CHAIN_USER : CHAIN_HOST;

    my ($chain, $changed);
    if ($enable) {
        # enable
        for $chain (keys %chains_all) {
            if ($vpn_ip && chain_is_mode($chain, CHAIN_VPN | $chain_type)) {
                if (!$chains_ips{$chain}{$vpn_ip}) {
                    chain_enable_ip($chain, $vpn_ip, 1);
                    $changed = 1;
                }
            }
            if ($real_ip && chain_is_mode($chain, CHAIN_REAL | $chain_type)) {
                if (!$chains_ips{$chain}{$real_ip}) {
                    chain_enable_ip($chain, $real_ip, 1);
                    $changed = 1;
                }
            }
        }
    } else {
        # disable
        for $chain (keys %chains_all) {
            if ($vpn_ip && chain_is_mode($chain, CHAIN_VPN | $chain_type)) {
                if ($chains_ips{$chain}{$vpn_ip}) {
                    chain_enable_ip($chain, $vpn_ip, 0);
                    $changed = 1;
                }
            }
            if ($real_ip && chain_is_mode($chain, CHAIN_REAL | $chain_type)) {
                if ($chains_ips{$chain}{$real_ip}) {
                    chain_enable_ip($chain, $real_ip, 0);
                    $changed = 1;
                }
            }
        }
    }

    if ($changed) {
        iptables_save_status();
        debug("iptables: enable:%s vpn:%s real:%s ",
                $enable, $vpn_ip, $real_ip);
    }
}

sub chain_enable_ip ($$$) {
    my ($chain, $ip, $enable) = @_;
    my $flag = $enable ? "-I" : "-D";
    if ($enable) {
        $chains_ips{$chain}{$ip} = 1;
    } else {
        delete $chains_ips{$chain}{$ip};
    }
    return run_iptables("$flag $chain -s $ip -j ACCEPT", undef);
}

sub chain_is_mode ($$) {
    my ($chain, $mode) = @_;
    return (defined($chains_all{$chain})
            && (($chains_all{$chain} & $mode) == $mode));
}

sub iptables_init () {
    iptables_close();

    # setup chain names
    $chains_all{$_} |= CHAIN_VPN | CHAIN_USER
        for (split /\s+/, $nu_config{iptables_user_vpn});
    $chains_all{$_} |= CHAIN_REAL | CHAIN_USER
        for (split /\s+/, $nu_config{iptables_user_real});
    $chains_all{$_} |= CHAIN_REAL | CHAIN_HOST
        for (split /\s+/, $nu_config{iptables_host_real});

    $chains_enable = (%chains_all ? 1 : 0);
    return unless $chains_enable;

    require_program("iptables");
    require_program("iptables_save");

    # consistency check
    for my $chain (qw[PREROUTING INPUT FORWARD OUTPUT POSTROUTING]) {
        fail("$chain: refusing to manage internal system chain")
            if $chains_all{$chain};
    }

    create_parent_dir($nu_config{iptables_status});
    iptables_rescan();
    $ev_watch{iptables} = $ev_loop->signal("USR1", \&iptables_rescan);
}

sub iptables_close () {
    $chains_enable = 0;
    %chains_ips = ();
    %chains_extra = ();
    %chains_all = ();
    $iptables_fail_num = 0;
    $iptables_fail_log = "";
}

sub iptables_rescan () {
    debug("rescan iptables");

    # setup structures
    my $iptables = $nu_config{iptables};
    my (%chain_exists, %chains_extra_set);
    for (keys %chains_all) {
        $chains_ips{$_} = {};
        $chains_extra{$_} = [];
        $chains_extra_set{$_} = {};
    }

    # scan saved status and current state of iptables
    for my $source ("status", "iptables") {
        my $out;

        # first scan saved status, then current state
        if ($source eq "status") {
            open(my $file, $nu_config{iptables_status}) or next;
            my $rs = $/;
            undef $/;
            $out = <$file>;
            $/ = $rs;
            close($file);
        }
        elsif ($source eq "iptables") {
            my $ret = run_prog($nu_config{iptables_save}, \$out);
        }

        # scan current source line by line
        for (split /\n/, $out) {
            # remove program name
            s/^\s*${iptables}\s+//;

            # skip empty lines and comments
            chomp; s/\s+/ /g; s/^ //; s/ $//;
            next if /^$/ || /^\#/;
            my $line = $_;
            #debug("ip scan source:$source line:$line");

            # detect whether chains exist
            if ($source eq "iptables" && $line =~ /^:(\S+) \S/) {
                my ($chain) = ($1);
                $chain_exists{$chain} = 1;
                #debug("ip scan source:$source found chain:$chain");
                next;
            }

            # simple rules for ordinary IPs
            if ($line =~ /^-A (\S+) -s ([\w\d\.\:]+) -j ACCEPT$/) {
                my ($chain, $ip) = ($1, $2);
                my $is_vpn = 0;
                for my $regex (@vpn_regex) {
                    $is_vpn = 1 if $ip =~ $regex;
                }
                if ($is_vpn && chain_is_mode($chain, CHAIN_VPN)) {
                    $chains_ips{$chain}{$ip} = $source;
                    debug("ip scan source $source chain $chain vpn: $ip");
                    next;
                }
                if (!$is_vpn && chain_is_mode($chain, CHAIN_REAL)) {
                    $chains_ips{$chain}{$ip} = $source;
                    debug("ip scan source:$source chain:$chain real: $ip");
                    next;
                }
            }

            # custom user rules
            if ($line =~ /^-A (\S+) (\S.*)$/) {
                my ($chain, $rule) = ($1, $2);
                next unless $chains_all{$chain};
                my $exists = exists $chains_extra_set{$chain}{$rule};
                $chains_extra_set{$chain}{$rule} = $source;
                debug("ip scan source:$source chain:$chain rule: $rule");
                push(@{ $chains_extra{$chain} }, $rule)  unless $exists;
                next;
            }
        }
    }

    # augment empty chains with default drop rule
    for my $chain (keys %chains_all) {
        unless (@{ $chains_extra{$chain} }) {
            my $rule = "-j DROP";
            push @{ $chains_extra{$chain} }, $rule;
            $chains_extra_set{$chain}{$rule} = "auto";
        }
    }

    # identify chains which have to be updated
    my %need_update;
  CHAIN_FOR_UPDATE:
    for my $chain (keys %chains_all) {
        if (!$chain_exists{$chain}) {
            $need_update{$chain} = "create";
            debug("chain $chain needs: create");
            next CHAIN_FOR_UPDATE;
        }
        for my $src (values %{ $chains_extra_set{$chain} }) {
            if ($src ne "iptables") {
                $need_update{$chain} = "extra";
                debug("chain $chain needs: extra rules");
                next CHAIN_FOR_UPDATE;
            }
        }
        for my $src (values %{ $chains_ips{$chain} }) {
            if ($src ne "iptables") {
                $need_update{$chain} = "ip";
                debug("chain $chain needs: add IPs");
                next CHAIN_FOR_UPDATE;
            }
        }
    }

    # test all changes with a temporary chain
    $iptables_fail_num = 0;
    $iptables_fail_log = "";
    my $temp = "NETUSHER_TEMP";

    for my $chain (sort keys %need_update) {
        debug("begin test of chain $chain changes");
        sleep(1);
        if ($chain_exists{$temp}) {
            run_iptables("-F $temp", 0);
            run_iptables("-X $temp", 0);
            $chain_exists{$temp} = 0;
        }
        run_iptables("-N $temp", 1);
        $chain_exists{$temp} = 1;
        last if $iptables_fail_num;

        for my $ip (sort keys %{ $chains_ips{$chain} }) {
            run_iptables("-A $temp -s $ip -j ACCEPT", 1);
            last if $iptables_fail_num;
        }
        for my $rule (@{ $chains_extra{$chain} }) {
            run_iptables("-A $temp $rule", 1);
            last if $iptables_fail_num;
        }
    }

    # remove temporary chain and check the result
    if ($chain_exists{$temp}) {
        run_iptables("-F $temp", 0);
        run_iptables("-X $temp", 0);
        $chain_exists{$temp} = 0;
    }
    fail("iptables error:\n%s", $iptables_fail_log)
        if $iptables_fail_num;

    # since test is fine, repeat actions on real chains
    for my $chain (sort keys %need_update) {
        run_iptables("-N $chain", 0)
            unless $chain_exists{$chain};

        if ($need_update{$chain} eq "ip") {
            # simply add IPs to the beginning of the chain
            for my $ip (sort keys %{ $chains_ips{$chain} }) {
                if ($chains_ips{$chain}{$ip} ne "iptables") {
                    run_iptables("-I $chain -s $ip -j ACCEPT", 1);
                }
            }
        }
        else {
            # fully remake the chain
            run_iptables("-F $chain", 0);
            for my $ip (sort keys %{ $chains_ips{$chain} }) {
                run_iptables("-A $chain -s $ip -j ACCEPT", 1);
            }
            for my $rule (@{ $chains_extra{$chain} }) {
                run_iptables("-A $chain $rule", 1);
            }
        }
    }

    if ($iptables_fail_num) {
        info("warning: iptables errors: %s", $iptables_fail_log);
    } elsif (%need_update) {
        info("iptables modified successfully: %s",
            join(" ", sort keys %need_update));
    }

    iptables_save_status();
}

sub iptables_save_status () {
    my $path = $nu_config{iptables_status};
    my $iptables = $nu_config{iptables};

    my $out = "# generated by $progname on " . POSIX::ctime(time);
    for my $chain (sort keys %chains_all) {
        $out .= "$iptables -F $chain\n";
        for my $ip (sort keys %{ $chains_ips{$chain} }) {
            $out .= "$iptables -A $chain -s $ip -j ACCEPT\n";
        }
        for my $rule (@{ $chains_extra{$chain} }) {
            $out .= "$iptables -A $chain $rule\n";
        }
    }
    $out .= "# end of file\n";

    if (open(my $file, ">", $path)) {
        print $file $out;
        close($file);
        debug("iptables status saved in $path");
    } else {
        info("$path: cannot create status file");
    }
}

sub run_iptables ($$) {
    my ($cmd, $log) = @_;
    my $iptables = $nu_config{iptables};
    my $out;
    my $ret = run_prog("$iptables $cmd", \$out);
    if ($ret && $log) {
        $iptables_fail_num++;
        $iptables_fail_log .= $out;
    }
    debug("$iptables ($ret) \"$cmd\"");
    return $ret;
}

##############################################
# mysql stuff
#

my  ($dbh, %sth_cache);

sub db_connect () {
    db_close();
    my $dsn;
    if ($nu_config{db_type} eq "mysql") {
        $nu_config{db_port} = 3306 unless $nu_config{db_port};
        $dsn = sprintf("DBI:mysql:database=%s;host=%s;port=%s",
                $nu_config{db_dbname}, $nu_config{db_host}, $nu_config{db_port});
        $dbh = DBI->connect($dsn, $nu_config{db_user}, $nu_config{db_pass})
	            or fail("cannot connect to database");
        $dbh->{mysql_enable_utf8} = 1;
        $dbh->{mysql_auto_reconnect} = 1;
        $dbh->{AutoCommit} = 0;
        $dbh->do("SET NAMES 'utf8'");
    }
    elsif ($nu_config{db_type} eq "pgsql") {
        $nu_config{db_port} = 5432 unless $nu_config{db_port};
        $dsn = sprintf("DBI:Pg:dbname=%s;host=%s;port=%s",
                $nu_config{db_dbname}, $nu_config{db_host}, $nu_config{db_port});
        $dbh = DBI->connect($dsn, $nu_config{db_user}, $nu_config{db_pass})
	            or fail("cannot connect to database");
        $dbh->{pg_enable_utf8} = 1;
        $dbh->{AutoCommit} = 0;
        $dbh->do("set client_encoding=\"UTF8\"");
    }
    else {
        fail("invalid database type '".$nu_config{db_type}."'");
    }
}

sub db_close () {
    %sth_cache = ();
    if (defined $dbh) {
        eval { $dbh->disconnect() };
        undef $dbh;
    }
}

sub db_clone () {
    my $child_dbh = $dbh->clone();
    db_close();
    $dbh = $child_dbh;
}

sub db_execute ($@) {
    my ($sql, @params) = @_;
    my ($sth, $ok, $num, $err);

    while (1) {
        # prepare
        $sth = $sth_cache{$sql};
        unless (defined $sth) {
            $sth = $dbh->prepare($sql);
            $sth_cache{$sql} = $sth
                if $nu_config{db_type} eq "mysql";
        }

        # execute
        $ok = eval { $sth->execute(@params) };
        $num = $sth->rows();
        $ok = 0 if $num < 0;
        last if $ok;

        # handle errors
        $num = -1;
        $err = $sth->errstr();
        info("database error: $err\n");
        last if $err !~ /no connection/i;

        # reconnect
        while (1) {
            info("reconnecting with database");
            eval { db_connect(); };
            last if $dbh;
            sleep(5);
        }
    }

    if ($nu_config{debug} & 2) {
        debug("execute: %s\n\t((%s)) = \"$num\"", $sql,
             join(',', map { defined($_) ? "\"$_\"" : "NULL" } @params));
    }
    return $sth;
}

sub db_fetch1 ($) {
    my ($sth) = @_;
    my @row = $sth->fetchrow_array();
    return $row[0];
}

sub db_commit () {
    eval { $dbh->commit(); };
}

##############################################
1;

