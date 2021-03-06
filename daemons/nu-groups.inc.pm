#!/usr/bin/perl
#
# NetUsher
# Local users and groups
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/nu-common.inc.pm";
require "$Bin/nu-cache.inc.pm";

#
# require: perl-User-Utmp
#
# you can obtain perl-User-Utmp RPM from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/perl-User-Utmp.html
#
use User::Utmp qw(:constants :utmpx);

our (%nu_config, $progname);
our ($etc_group_str, $etc_group_sign, %local_users, %local_groups);

##############################################
# group mirroring
#

my ($skin_name, %lg_gid, %lg_members, %group_to_lg, %user_groups);

sub gmirror_init () {
    # detect our skin
    $skin_name = get_skin_name();
    debug("kernel skin name: $skin_name");
    #$skin_name = "ut";

    # initialize local groups
    %lg_gid = ();
    %lg_members = ();
    %group_to_lg = ();
    %user_groups = ();

    parse_gmirror_rules();
    update_etc_group("gshadow");
    update_etc_group();
}

#
# parse group ids from server
#
sub handle_groups ($$) {
    my ($job, $arg) = @_;
    return unless $arg;
    if ($job->{cmd} eq "update") {
        # flash completely
        %user_groups = ();
    }
    for my $part (split /~/, $arg) {
        my ($user, @groups) = split /!/, $part;
        $user_groups{$user} = \@groups;
        debug("gmirror %s: %s", $user, join(",", @groups));
    }
}

#
# apply mirroring rules to all active users
#
sub gmirror_apply ($) {
    my ($job) = @_;
    my (%users_set, $off_user, $off_sid);
    my $cmd = defined($job) ? $job->{cmd} : "";

    if ($cmd eq "login" || $cmd eq "groups") {
        $users_set{$job->{user}} = 1;
        debug("gmirror include user:%s", $job->{user});
    }
    if ($cmd eq "logout") {
        ($off_user, $off_sid) = @$job{qw[user sid]};
        debug("gmirror exclude user:$off_user sid:\"$off_sid\"");
    }

    # create list of active users
    for my $u (scan_utmp()) {
        next if is_local_user($u->{user});
        if ($off_user && $u->{user} eq $off_user && $u->{sid} eq $off_sid) {
            undef $off_user;
            next;
        }
        $users_set{$u->{user}} = 1;
    }

    # clean up local groups
    $lg_members{$_} = {} for (keys %lg_gid);

    # apply rules
    for my $user (keys %users_set) {
        my (%lgroups, $ugroups);
        if ($nu_config{prefer_nss}) {
            my $gmap = inquire_groups( [{ user => $user }] );
            $ugroups = $gmap->{$user};
        } else {
            $ugroups = $user_groups{$user};
        }
        next unless defined $ugroups;
        for my $group (@$ugroups) {
            my $lg_set = $group_to_lg{$group};
            next unless defined $lg_set;
            for my $lgroup (keys %$lg_set) {
                $lg_members{$lgroup}{$user} = 1;
            }
        }
    }

    # re-create /etc/group
    update_etc_group();
}

#
# parse mirroring rules
#
sub parse_gmirror_rules () {
    my (%rules, %skip);
    $rules{add} = {};
    $rules{sub} = {};

    my $conf_path = $nu_config{gmirror_conf};
    open(my $conf_file, $conf_path)
        or fail("$conf_path: cannot read configuration");
    my $sum = "";

    while (<$conf_file>) {
        # skip empty lines and comments
        chomp; s/\#.*$//; s/\s+/ /g; s/^ //; s/ $//;
        next if /^$/;
        $sum .= $_;
        if (/\\$/) {
            $sum =~ s/\\$//;
            next;
        }
        my $line = $sum;
        $sum = "";

        if ($line =~ /(\w+) ?([\+\-\:])\=+ ?(.*)$/) {
            # rule lines
            my ($group, $op, $members) = ($1, $2, $3);
            my $rule = $op eq "-" ? "sub" : "add";
            $rules{$rule}{$group} = {}
                unless exists $rules{$rule}{$group};
            $rules{$rule}{$group}{$_} = 1
                for (split / /, $members);
        }
        elsif ($line =~ /(\w+) ?\=+ ?(\d+)$/) {
            # local group definitions
            $lg_gid{$1} = $2;
        }
        elsif ($line =~ /^disable_for_skin ?\( ?(\w+) ?\) ?\:+ ?(.*)$/) {
            # skin filter
            my ($skin, $groups) = ($1, $2);
            if ($skin eq $skin_name) {
                $skip{$_} = 1
                    for (split / /, $groups);
            }
        }
        else {
            fail("$conf_path: syntax error in line $.");
        }
    }
    close($conf_file);

    ##############
    # create mapping rules from add/remove rules
    #
    my (%map, $changed, $src, $dst, $more, $less);

    # pin up the mapping from adding rules
    for $src (keys %{ $rules{add} }) {
        for $dst (keys %{ $rules{add}{$src} }) {
            $map{$src}{$dst} = 1;
        }
    }

    # apply additions
    for $src (keys %map) {
        do {
            $changed = 0;
            for $dst (keys %{ $map{$src} }) {
                next unless $rules{add}{$dst};
                for $more (keys %{ $rules{add}{$dst} }) {
                    unless ($map{$src}{$more}) {
                        $map{$src}{$more} = 1;
                        $changed = 1;
                    }
                }
            }
        } while ($changed);
    }

    # apply substractions
    for $src (keys %map) {
        do {
            $changed = 0;
            for $dst (keys %{ $map{$src} }) {
                next unless $rules{sub}{$dst};
                for $less (keys %{ $rules{sub}{$dst} }) {
                    if ($map{$src}{$less}) {
                        delete $map{$src}{$less};
                        $changed = 1;
                    }
                }
                # invalidate the iterator
                last if $changed;
            }
        } while ($changed);
    }

    # remove groups disabled by skin
    for $less (keys %skip) {
        delete $map{$less};
        for $src (keys %map) {
            delete $map{$src}{$less};
        }
    }

    # remove local groups on the left side
    for $less (keys %lg_gid) {
        delete $map{$less};
    }

    # remove non-local groups on the right side
    for $src (keys %map) {
        for $dst (keys %{ $map{$src} }) {
            delete $map{$src}{$dst}
                unless $lg_gid{$dst};
        }
    }

    # copy non-empty mappings to global map
    %group_to_lg = ();
    for $src (keys %map) {
        next unless %{ $map{$src} };
        $group_to_lg{$src} = {};
        for $dst (keys %{ $map{$src} }) {
            $group_to_lg{$src}{$dst} = 1;
        }
    }

    if ($nu_config{debug}) {
        debug("local groups: ".
                join(", ", map("$_=$lg_gid{$_}",
                    sort { $lg_gid{$a} <=> $lg_gid{$b} } keys %lg_gid)
                ));
        dump_rules(\%group_to_lg, "group mapping");
    }
}

sub dump_rules ($$) {
    my ($map, $msg) = @_;
    return unless $nu_config{debug};
    debug("$msg: " .
        join("; ", map { "$_:" . join(",", (sort keys %{$map->{$_}})) }
                    (sort keys %$map)));
}

#
# update /etc/group (or /etc/gshadow)
#
sub update_etc_group (;$) {
    my ($shadow) = @_;
    my $path = $shadow ? "/etc/gshadow" : $nu_config{etc_group};

    # /etc/gshadow is optional, update only if exists...
    if ($shadow && !(-r $path)) {
        debug("$path: does not exist");
        return 0;
    }

    while (1) {
        my ($new, $orig, $sign1, %pending);

        # list of managed groups to be added at the end
        $pending{$_} = 1 for (keys %lg_gid);

        # read group file, inquire access mode and owners
        if ($shadow) {
            ($sign1) = super_stat($path);
            $orig = read_file($path) or fail("$path: cannot open");
        } else {
            rescan_etc();
            ($orig, $sign1) = ($etc_group_str, $etc_group_sign);
        }

        # replace lines related to managed groups
        for (split /\n/, $orig) {
            if (!$shadow && /^(\w+):(\w+):(\d+):(.*?)(\s*)$/) {
                my ($g, $x, $gid, $members, $eol) = ($1, $2, $3, $4, $5);
                if ($lg_gid{$g}) {
                    # replace line with managed group
                    $gid = $lg_gid{$g};
                    $new .= sprintf("%s:%s:%s:%s%s\n",
                                $g, $x, $lg_gid{$g},
                                join(",", sort keys %{ $lg_members{$g} }),
                                $eol);
                    delete $pending{$g};
                    next;
                }
            }
            if ($shadow && /^(\w+):(.*)$/) {
                delete $pending{$1} if $lg_gid{$1};
            }
            $new .= $_ . "\n";
        }

        # add remaining managed groups at the end
        for my $g (sort { $lg_gid{$a} <=> $lg_gid{$b} } keys %pending) {
            if ($shadow) {
                $new .= "$g:!::\n";
            } else {
                $new .= sprintf("%s:x:%s:%s\n", $g, $lg_gid{$g},
                                join(",", sort keys %{ $lg_members{$g} }));
            }
        }

        # return if file should not change
        if ($orig eq $new) {
            debug("$path: no changes");
            last;
        }

        # create temporary file with new contents
        my $temp_path = "$path.$progname.$$";
        add_temp_file($temp_path);
        my $sign3 = write_file($temp_path, $new)
            or fail("$temp_path: cannot create");

        # now check whether original file has changed
        my ($sign2, $f_mode, $f_uid, $f_gid) = super_stat($path);

        if ($sign1 eq $sign2) {
            # keep original file access, rename and clobber the original file
            chown($f_uid, $f_gid, $temp_path);
            chmod($f_mode, $temp_path);
            rename($temp_path, $path)
                or fail("cannot rename $temp_path to $path");
            if (!$shadow) {
                ($etc_group_str, $etc_group_sign) = ($new, $sign3);
                $local_groups{$_} = $lg_gid{$_} for (keys %lg_gid);
            }
            del_temp_file($temp_path);
            info("$path: modified successfully");
            invalidate_nscd() if $nu_config{update_nscd};
            last;
        }

        # the original file has changed. try again.
        del_temp_file($temp_path);
    }

    return 0;
}

#
# invalidate nscd groups
#
sub invalidate_nscd () {
    my $pid_path = $nu_config{nscd_pid_file};
    my $pid_file;
	unless (open($pid_file, $pid_path)) {
		debug("$pid_path: nscd pid file not found");
		return 1;
	}
	my $pid = <$pid_file>;
	close $pid_file;
	$pid = int($pid);
	unless ($pid) {
		info("$pid_path: invalid nscd pid");
		return 1;
	}
	unless (kill(0, $pid)) {
		info("$pid_path: stale nscd pid $pid");
		return 1;
	}
    my $ret = run_prog("/proc/$pid/exe -i group");
    if ($ret) {
        info("nscd invalidation failed with code $ret");
        return 1;
    }
    debug("nscd invalidated");
    return 0;
}

#
# return value of the "skin=" parameter from the kernel parameter line.
#
sub get_skin_name () {
	my $kernel_cmd_path = "/proc/cmdline";
	my $skin = "";
    if (open(my $file, $kernel_cmd_path)) {
        while (<$file>) {
            if (/\bskin=(\w+)\b/) {
                $skin = $1;
                last;
            }
        }
        close($file);
    } else {
        info("$kernel_cmd_path: cannot read");
    }
    return $skin;
}

##############################################
# scan /var/utmpx
#
sub scan_utmp () {
    my $cached = cache_get("host", "utmp");
    return @$cached if defined $cached;

    rescan_etc();
    my @utmp;

    # scan utmpx
    for my $ut (sort { $a->{ut_time} <=> $b->{ut_time} } getutx()) {
        # filter out local users
        my ($user, $tty, $rhost, $btime, $pid)
            = @$ut{qw[ut_user ut_line ut_addr ut_time ut_pid]};
        next if $ut->{ut_type} != USER_PROCESS;

        $rhost = $rhost ? join(".", unpack("C4", $rhost)) : "";
        $rhost =~ y# |!@~#_#;
        $user =~ y# |!@~#_#;
        $tty =~ y# |!@~#_#;
        $tty =~ s#^/dev/##;
        my $sid = $rhost ? "${tty}\@${rhost}" : $tty;

        push @utmp, {
            user => $user,
            btime => $btime,
            sid => $sid,
            tty => $tty,
            rhost => $rhost,
            pid => $pid
            };

        #debug("utmp next: user:$user sid:$sid pid:$pid time:$btime");
        #$ut->{ut_addr} = $rhost;
        #debug("utmp next: ".join(", ", map "$_=\"$ut->{$_}\"", sort keys %$ut));
    }

    cache_put("host", "utmp", [ @utmp ], $nu_config{utmp_cache_ttl});
    return @utmp;
}

##############################################
1;

