#!/usr/bin/perl
# Migrate NetUsher table fro MySQL to PostgreSQL.

use DBI;
use Data::Dumper;
use strict;

my $srcdb = DBI->connect("dbi:mysql:database=netusher;host=localhost","netusher","netusher") or die;
my $destdb = DBI->connect("dbi:Pg:dbname=netusher;host=localhost","netusher","netusher") or die;

$srcdb->do("SET names \'utf8\'"); #character_set_client = utf8");
$destdb->do("SET client_encoding=\'UTF8\'") or die;


my $srctables = $srcdb->selectall_arrayref("show tables");
my $desttables = $destdb->selectall_hashref("select * from pg_tables where not tablename ~\'^(pg_|sql_)\'","tablename");

$destdb->{AutoCommit}=0;

# rearrange tables
my @tlist = qw[nu_users nu_openvpn];
  
foreach my $t(@tlist) {
  my $table = $t;
  unless (exists $desttables->{$table}) {
    print STDERR "WARN: table $table does not exists in dest db Pg:$ARGV[1]\n";
    next;
  }
  clear_table($destdb,$table);
  my $cnt = copy_table($srcdb,$destdb,$table);
  print "$cnt rows copied ($table)\n";
}

#init_seq($destdb,'lxr_files','fileid','lxr_filenum');

$destdb->commit;
exit 0;

sub init_seq {
  my ($db,$table,$field,$seq)=@_;
  return unless $seq;
  my $ref = $db->selectall_arrayref("select max($field) from $table") or die;
  my $val = $ref->[0]->[0];
  return unless $val;
  $val += 1;
  my $sql = "ALTER SEQUENCE $seq RESTART WITH $val";
  $db->do($sql) or die;
  print STDERR "[ $sql ]\n";
}

sub clear_table {
  my ($dbh,$table)=@_;
  return unless $table;
  $dbh->do("delete from $table") or die;
}

sub copy_table {
  my ($srcdb,$destdb,$table)=@_;
  die unless $table;
  my $slf = $srcdb->prepare("select * from $table limit 1");
  my $rows = $slf->execute() or die;
  return 0 if $rows < 1;
  my $rec1 = $slf->fetchrow_hashref;
  $slf->finish;
  my @fieldnames = sort keys %$rec1;
  my @qm =  map { '?'} @fieldnames;
  my $ins = $destdb->prepare("INSERT into $table (".join(",",@fieldnames).") values(".join(",",@qm).")");
  my $sel = $srcdb->prepare("select * from $table");
  $sel->execute or die;
  my $cnt = 0;
  while (my $data = $sel->fetchrow_hashref) {
    $ins->execute(map {$data->{$_}} @fieldnames) or die;
    $cnt++;
  }
  $ins->finish;
  $sel->finish;
  return $cnt;
}

