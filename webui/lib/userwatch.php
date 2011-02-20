<?php
/////////////////////////////////////////////////////////
// UserWatch Web Interface
// Main Program
// $Id$
/////////////////////////////////////////////////////////

$cfg = array(
    'mysql_host'  => 'localhost',
    'mysql_user'  => 'userwatch',
    'mysql_pass'  => 'userwatch',
    'mysql_db'    => 'userwatch',
);

$dbh = null;

function setup () {
    $file = fopen("/etc/userwatch/uw-server.conf", "r");
    if ($file) {
        while ($line = fgets($file)) {
            if (preg_match('!^\\s*$!', $line) || preg_match('!^\\s*#!', $line))
                continue;
            if (preg_match('!^\\s*([^\\s=]+)\\s*=\\s*(.*)\\s*$!', $line, $parts)) {
                $cfg[$parts[1]] = $parts[2];
            }
        }
        fclose($file);
    }

    global $dbh;
    $dbh = @mysql_connect($cfg['mysql_host'], $cfg['mysql_user'], $cfg['mysql_pass']);
    if (!$dbh)
        return "cannot connect to database: " . mysql_error();
    if (!mysql_select_db($cfg['mysql_db']))
        return "cannot select default database";
    return "";
}

/*
    vpn_ip      varchar(16) NOT NULL,
    beg_time    datetime NOT NULL,
    end_time    datetime,
    running     tinyint(1),
    cname       varchar(16),
    real_ip     varchar(16),
    real_port   int(5),
    rx_bytes    int(8),
    tx_bytes    int(8),
*/

function show_hosts () {
    echo "<h1>Hosts</h1>\n";
    $count = 0;
    $res = mysql_query("select count(*) from uw_openvpn");
    if ($res) {
        $row = mysql_fetch_array($res);
        if ($row)
            $count = $row[0];
    }
    echo "<p>$count host record(s)</p>\n";
}

function show_users () {
    echo "<h1>Users</h1>\n";
    $count = 0;
    $res = mysql_query("select count(*) from uw_users");
    if ($res) {
        $row = mysql_fetch_array($res);
        if ($row)
            $count = $row[0];
    }
    echo "<p>$count user record(s)</p>\n";
}

function userwatch () {
    global $dbh;
    $err = setup();
    if ($err) {
        echo "<p>$err</p>";
        @mysql_close($dbh);
        return;
    }
    show_hosts();
    show_users();
    mysql_close($dbh);
}


