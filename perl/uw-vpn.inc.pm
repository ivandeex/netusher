#!/usr/bin/perl
#
# UserWatch
# Interface with OpenVPN and IPtables
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

#
# require: perl-DBD-mysql
#
use DBI;

our (%uw_config, $progname, %ev_watch, $ev_loop);
our ($vpn_regex);

##############################################
# iptables control
#

use constant CHAIN_VPN  => 1;
use constant CHAIN_REAL => 2;

my ($chains_enable, %chains_all, %chains_ips, %chains_extra);
my ($iptables_fail_num, $iptables_fail_log);

sub iptables_update ($) {
    my ($vpn_ip) = @_;
    return unless $chains_enable;
    my $active = users_from_ip($vpn_ip);
    my $real_ip = get_real_ip($vpn_ip);
    debug("got $active active users from vpn:$vpn_ip real:$real_ip");

    my ($chain, $changed);
    if ($active) {
        # enable
        for $chain (keys %chains_all) {
            if ($vpn_ip && chain_is_mode($chain, CHAIN_VPN)) {
                if (!$chains_ips{$chain}{$vpn_ip}) {
                    enable_ip($chain, $vpn_ip, 1, 0);
                    $changed = 1;
                }
            }
            if ($real_ip && chain_is_mode($chain, CHAIN_REAL)) {
                if (!$chains_ips{$chain}{$real_ip}) {
                    enable_ip($chain, $real_ip, 1, 0);
                    $changed = 1;
                }
            }
        }
    } else {
        # disable
        for $chain (keys %chains_all) {
            if ($vpn_ip && chain_is_mode($chain, CHAIN_VPN)) {
                if ($chains_ips{$chain}{$vpn_ip}) {
                    enable_ip($chain, $vpn_ip, 0, 0);
                    $changed = 1;
                }
            }
            if ($real_ip && chain_is_mode($chain, CHAIN_REAL)) {
                if ($chains_ips{$chain}{$real_ip}) {
                    enable_ip($chain, $real_ip, 0, 0);
                    $changed = 1;
                }
            }
        }
    }

    if ($changed) {
        iptables_save_status();
        debug("iptables: enable:%s vpn:%s real:%s ",
                $active, $vpn_ip, $real_ip);
    }
}

sub get_real_ip ($) {
    my ($vpn_ip) = @_;
    return unless $vpn_ip;
    my $sth = mysql_execute("SELECT real_ip FROM uw_openvpn
                            WHERE running = 1 AND vpn_ip = ?
                            LIMIT 1",
                            $vpn_ip);
    my $real_ip = mysql_fetch1($sth);
    return $real_ip;
}

sub enable_ip ($$$$) {
    my ($chain, $ip, $enable, $log) = @_;
    my $flag = $enable ? "-I" : "-D";
    if ($enable) {
        $chains_ips{$chain}{$ip} = 1;
    } else {
        delete $chains_ips{$chain}{$ip};
    }
    return run_iptables("$flag $chain -s $ip -j ACCEPT", $log);
}

sub iptables_init () {
    iptables_close();

    # setup chain names
    $chains_all{$_} |= CHAIN_VPN
        for (split /\s+/, $uw_config{iptables_user_vpn});
    $chains_all{$_} |= CHAIN_REAL
        for (split /\s+/, $uw_config{iptables_user_real});
    $chains_enable = (%chains_all ? 1 : 0);
    return unless $chains_enable;

    # consistency check
    for my $chain (qw[PREROUTING INPUT FORWARD OUTPUT POSTROUTING]) {
        fail("$chain: refusing to manage internal system chain")
            if $chains_all{$chain};
    }

    create_parent_dir($uw_config{iptables_status});
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
    my $iptables = $uw_config{iptables};
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
            open(my $file, $uw_config{iptables_status}) or next;
            my $rs = $/;
            undef $/;
            $out = <$file>;
            $/ = $rs;
            close($file);
        }
        elsif ($source eq "iptables") {
            my $ret = run_prog($uw_config{iptables_save}, \$out);
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
                my $is_vpn = ($ip =~ $vpn_regex) ? 1 : 0;
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
    my $temp = "USERWATCH_TEMP";

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
    my $path = $uw_config{iptables_status};
    my $iptables = $uw_config{iptables};

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
    my $iptables = $uw_config{iptables};
    my $out;
    my $ret = run_prog("$iptables $cmd", \$out);
    if ($ret && $log) {
        $iptables_fail_num++;
        $iptables_fail_log .= $out;
    }
    debug("$iptables ($ret) \"$cmd\"");
    return $ret;
}

sub chain_is_mode ($$) {
    my ($chain, $mode) = @_;
    return (defined($chains_all{$chain})
            && (($chains_all{$chain} & $mode) == $mode));
}

##############################################
# mysql stuff
#

my  ($dbh, %sth_cache);

sub mysql_connect () {
    mysql_close();
    my $uri = sprintf("DBI:mysql:%s;host=%s",
                    $uw_config{mysql_db}, $uw_config{mysql_host});
    $dbh = DBI->connect($uri, $uw_config{mysql_user}, $uw_config{mysql_pass})
		or fail("cannot connect to database");
    $dbh->{mysql_enable_utf8} = 1;
    $dbh->{mysql_auto_reconnect} = 1;
    $dbh->{AutoCommit} = 0;
    $dbh->do("SET NAMES 'utf8'");
}

sub mysql_close () {
    %sth_cache = ();
    if (defined $dbh) {
        eval { $dbh->disconnect() };
        undef $dbh;
    }
}

sub mysql_clone () {
    my $child_dbh = $dbh->clone();
    mysql_close();
    $dbh = $child_dbh;
}

sub mysql_execute ($@) {
    my ($sql, @params) = @_;
    my $sth = $sth_cache{$sql};
    unless (defined $sth) {
        $sth = $dbh->prepare($sql);
        $sth_cache{$sql} = $sth;
    }
    my $ok = { $sth->execute(@params) };
    my $num = $sth->rows();
    if (!$ok) {
        info("mysql error: %s\n", $sth->errstr());
        $num = -1;
    }
    debug("execute: %s\n\t((%s)) = \"%s\"", $sql,
         join(',', map { defined($_) ? "\"$_\"" : "NULL" } @params),
         $num);
    return $sth;
}

sub mysql_fetch1 ($) {
    my ($sth) = @_;
    my @row = $sth->fetchrow_array();
    return $row[0];
}

sub mysql_commit () {
    eval { $dbh->commit(); };
}

##############################################
1;

