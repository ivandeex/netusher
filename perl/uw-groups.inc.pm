#!/usr/bin/perl
#
# UserWatch
# Local users and groups
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

#
# require: perl-User-Utmp
#
# you can obtain perl-User-Utmp RPM from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/perl-User-Utmp.html
#
use User::Utmp qw(:constants :utmpx);

our (%uw_config, $progname);

##############################################
# group mirroring
#

my ($skin_name, %lg_gid, %lg_members, %g_map);

sub gmirror_init () {
    # detect our skin
    $skin_name = get_skin_name();
    debug("kernel skin name: $skin_name");
    #$skin_name = "ut";

    # initialize local groups
    %lg_gid = ();
    %lg_members = ();

    parse_gmirror_rules();
    update_etc_group(0);    # /etc/group
    update_etc_group(1);    # /etc/gshadow
}

#
# parse group ids from server
#
sub handle_gmirror_reply ($$$) {
    my ($job, $reply, $arr_ref) = @_;
    return unless @$arr_ref;
    my @arr = @$arr_ref;
    my $ntokens = $arr[1];
    if ($arr[0] ne "~" || $arr[$#arr] ne "~" || $ntokens !~ /^\d+$/) {
        info("invalid gmirror reply");
        return;
    }

    my $group_map = {};
    my $k = 2;
    for (my $i = 0; $i < $ntokens; $i++) {
        my $user = $arr[$k++];
        my $ngroups = $arr[$k++];
        if ($ngroups !~ /^\d+$/ || $arr[$k + $ngroups] ne "/") {
            info("invalid gmirror reply at token $i");
            return;
        }
        $group_map->{$user} = [ @arr[$k .. ($k + $ngroups - 1)] ];
    }

    debug("gmirror reply ok ($ntokens tokens)");
}

#
# parse mirroring rules
#
sub parse_gmirror_rules () {
    my (%rules, %skip);
    $rules{add} = {};
    $rules{sub} = {};

    my $conf_path = $uw_config{gmirror_conf};
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
    %g_map = ();
    for $src (keys %map) {
        next unless %{ $map{$src} };
        $g_map{$src} = {};
        for $dst (keys %{ $map{$src} }) {
            $g_map{$src}{$dst} = 1;
        }
    }

    if ($uw_config{debug}) {
        debug("local groups: ".
                join(", ", map("$_=$lg_gid{$_}",
                    sort { $lg_gid{$a} <=> $lg_gid{$b} } keys %lg_gid)
                ));
        for $src (keys %g_map) {
            debug("group mapping $src: ".
                join(",", sort { $lg_gid{$a} <=> $lg_gid{$b} }
                            keys %{ $g_map{$src} }
                ));
        }
    }
}

#
# update /etc/group (or /etc/gshadow)
#
sub update_etc_group (;$) {
    my ($shadow) = @_;
    my $path = $shadow ? "/etc/gshadow" : "/etc/group";

    # /etc/gshadow is optional, update only if exists...
    if ($shadow && !(-r $path)) {
        debug("$path: does not exist");
        return 0;
    }

    while (1) {
        # get file access mode and owners
        my @st = stat($path);
        my ($mode1, $uid1, $gid1, $size1, $mtime1) = @st[2,4,5,7,9];
        my $stat_1 = "$mode1|$uid1|$gid1|$size1|$mtime1";

        # strings with contents of original and new files
        my $orig = "";
        my $new = "";

        # list of managed groups to be added at the end
        my %pending;
        $pending{$_} = 1 for (keys %lg_gid);

        # read group file line by line
        open(my $file, $path) or fail("$path: cannot open");
        while (<$file>) {
            $orig .= $_;
            if (!$shadow && /^(\w+):(\w+):(\d+):(.*?)(\s*)$/) {
                my ($g, $x, $gid, $members, $eol) = ($1, $2, $3, $4, $5);
                if ($lg_gid{$g}) {
                    # replace line with managed group
                    $gid = $lg_gid{$g};
                    $new .= sprintf("%s:%s:%s:%s%s",
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
            $new .= $_;
        }
        close($file);

        # add remaining managed groups at the end
        my $x = "x";
        for my $g (sort { $lg_gid{$a} <=> $lg_gid{$b} } keys %pending) {
            if ($shadow) {
                $new .= "$g:!::\n";
            } else {
                $new .= sprintf("%s:%s:%s:%s\n", $g, $x, $lg_gid{$g},
                                join(",", sort keys %{ $lg_members{$g} }));
            }
        }

        # return if file should not change
        if ($orig eq $new) {
            debug("$path: changes not needed");
            last;
        }

        # create temporary file with new contents
        my $temp_path = "$path.$progname.$$";
        add_temp_file($temp_path);
        open(my $temp_file, "> $temp_path")
            or fail("$temp_path: cannot create");
        print $temp_file $new;
        close($temp_file);

        # keep file access the same
        chown($uid1, $gid1, $temp_path);
        chmod($mode1, $temp_path);

        # now check whether original file has changed
        @st = stat($path);
        my ($mode2, $uid2, $gid2, $size2, $mtime2) = @st[2,4,5,7,9];
        my $stat_2 = "$mode2|$uid2|$gid2|$size2|$mtime2";
        if ($stat_1 eq $stat_2) {
            # rename and clobber the original file
            rename($temp_path, $path)
                or fail("cannot rename $temp_path to $path");
            del_temp_file($temp_path);
            info("$path: modified successfully");
            invalidate_nscd() if $uw_config{update_nscd};
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
sub invalidate_nscd {
    my $pid_path = $uw_config{nscd_pid_file};
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
# scan /etc/passwd
#

our (%local_users);
my  ($passwd_modified_stamp);

sub get_local_users () {
    # check whether file was modified
    my $passwd_path = "/etc/passwd";
    my $modified = -M($passwd_path);
    return if $modified eq $passwd_modified_stamp;
    $passwd_modified_stamp = $modified;

    # if the file was modified, refresh the hash
    debug("updating local user list");
    %local_users = ();
    open(my $passwd_file, $passwd_path)
        or fail("$passwd_path: cannot open");
    while (<$passwd_file>) {
        next unless m"^([a-xA-Z0-9\.\-_]+):\w+:(\d+):\d+:";
        $local_users{$1} = $2;
    }
    close($passwd_file);
}

##############################################
# scan /var/utmpx
#
sub get_active_users () {
    get_local_users();
    my @user_list;

    # scan utmpx
    for my $ut (sort { $a->{ut_time} <=> $b->{ut_time} } getutx()) {
        next unless $ut->{ut_type} == USER_PROCESS;
        # filter out local users
        my $user = $ut->{ut_user};
        next if !$uw_config{also_local} && exists($local_users{$user});

        # detect login methos
        my $method;
        my $id = $ut->{ut_id};
        if ($id =~ m"^s/\d+$") { $method = "RSH" }
        elsif ($id =~ m"^\d+$") { $method = "CON" }
        elsif ($id =~ m"^:\d+(\.\d+)?$") { $method = "XDM" }
        elsif ($id =~ m"^/\d+$") { $method = "XTY" }
        elsif ($ut->{ut_addr}) { $method = "RSH" }
        else { $method = "UNK" }

        # detect user id
        my $uid = "";
        if (exists $local_users{$user}) {
            $uid = $local_users{$user};
        } else {
            my ($xname, $xpass, $xuid) = getpwnam($user);
            $uid = $xuid if defined $xuid;
        }

        my $u = {
                beg_time => $ut->{ut_time},
                method => $method,
                user => $user,
                uid => $uid,
                };
        push @user_list, $u;
        #debug("user_list next: user:%s uid:%s method:%s beg_time:%s",
        #        $user, $uid, $method, $u->{beg_time});
    }

    return @user_list;
}

##############################################
1;

