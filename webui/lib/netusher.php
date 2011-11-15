<?php
/////////////////////////////////////////////////////////
// NetUsher Web Interface
// Main Program
// $Id$
/////////////////////////////////////////////////////////

$cfg = array(
    'db_type'    => 'mysql',
    'db_host'    => 'localhost',
    'db_port'    => '0',
    'db_user'    => 'netusher',
    'db_pass'    => 'netusher',
    'db_dbname'  => 'netusher',
);

$dbh = null;

function setup () {
    global $cfg, $dbh;

    $file = fopen("/etc/netusher/nu-server.conf", "r");
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

    if ($cfg['db_type'] == 'mysql') {
        if (!function_exists('mysql_connect'))
            return "mysql extension is not installed";
        $dsn = $cfg['db_host'];
        if ($cfg['db_port'] && $cfg['db_port'] !== '0')
            $dsn .= ':' . $cfg['db_port'];
        $dbh = @mysql_connect($dsn, $cfg['db_user'], $cfg['db_pass']);
        if (!$dbh)
            return "cannot connect to database: " . mysql_error();
        if (!mysql_select_db($cfg['db_dbname']))
            return "cannot select default database";
        mysql_query('SET NAMED utf8', $dbh);
    }
    else if ($cfg['db_type'] == 'pgsql') {
        if (!function_exists('pg_connect'))
            return "postgresql extension is not installed";
        $dsn = ' user=' . $cfg['db_user'] . ' password=' . $cfg['db_pass'] . ' host=' . $cfg['db_host'];
        if ($cfg['db_port'] && $cfg['db_port'] !== '0')
            $dsn .= ' port=' . $cfg['db_port'];
        $prev_track = ini_get('track_errors');
        ini_set('track_errors', 1);
        $dbh = @pg_connect($dsn);
        $pgsql_error = $dbh ? "" : $php_errormsg;
        ini_set('track_errors', $prev_track);
        if (!$dbh)
            return "cannot connect to database [$dsn]: $pgsql_error";
        pg_query($dbh, "set client_encoding=\"UTF8\"");
    }
    else {
        return "invalid database type '".$cfg['db_type']."'";
    }
    return "";
}

function db_close () {
    global $cfg, $dbh;
    if ($cfg['db_type'] == 'mysql' && function_exists('mysql_close') && $dbh)
        @mysql_close($dbh);
    if ($cfg['db_type'] == 'pgsql' && function_exists('pg_close') && $dbh)
        @pg_close($dbh);
    $dbh = null;
}

function db_query ($query) {
    global $cfg, $dbh;
    if ($cfg['db_type'] == 'mysql') {
        $res = mysql_query($query, $dbh);
    }
    else if ($cfg['db_type'] == 'pgsql') {
        $res = pg_query($dbh, $query);
    }
    else {
        $res = FALSE;
    }
    return $res;
}

function db_fetch_array ($res) {
    global $cfg, $dbh;
    if ($res === FALSE)
        return FALSE;
    if ($cfg['db_type'] == 'mysql') {
        $row = mysql_fetch_array($res, MYSQL_ASSOC);
    }
    else if ($cfg['db_type'] == 'pgsql') {
        $row = pg_fetch_assoc($res);
    }
    else {
        $row = FALSE;
    }
    return $row;
}

function setup_sort ($table, $columns) {
    $sort_field = isset($_GET["$table-sort"]) ? $_GET["$table-sort"] : null;
    $sort_dir = isset($_GET["$table-dir"]) ? $_GET["$table-dir"] : null;
    if ($sort_dir != "asc" && $sort_dir != "desc") {
        $sort_dir = null;
    }
    if (!$sort_dir || !array_key_exists($sort_field, $columns)) {
        $sort_dir = null;
        $sort_field = null;
    }
    return array($sort_field, $sort_dir);
}

function table_header ($self, $table, $columns) {
    echo "<div class=\"clear-block\"></div>\n";
    echo "<div class=\"$table-query query-results\">\n";
    echo "<table class=\"$table-block index-block\">\n";
    echo "<thead><tr>\n";
    list($sort_field, $sort_dir) = setup_sort($table, $columns);
    foreach ($columns as $field => $title) {
        $sort = $sort_field === $field ? $sort_dir : "";
        $rev_sort = $sort === "asc" ? "desc" : "asc";
        echo "<th>";
        echo "<a href=\"$self?$table-sort=$field&amp;$table-dir=$rev_sort";
        foreach ($_GET as $param => $value) {
            if ($param != "$table-sort" && $param != "$table-dir")
                echo "&amp;$param=$value";
        }
        echo "\">$title</a>";
        if (!empty($sort)) echo "<img alt=\"$sort\" title=\"$sort\" src=\"$sort.png\" />";
        echo "</th>\n";
    }
    echo "</tr></thead>\n";
    echo "<tbody>\n";
}

function table_footer ($table, $count) {
    echo "</tbody>\n";
    echo "</table>\n";
    echo "<p>$count $table record(s)</p>\n";
    echo "</div>";
}

function table_query ($table, $db_table, $columns) {
    $query = "select ";
    $query .= implode(",", array_keys($columns));
    $query .= " from $db_table ";
    list($sort_field, $sort_dir) = setup_sort($table, $columns);
    if ($sort_field && $sort_dir)  $query .= "order by $sort_field $sort_dir";
    return $query;
}

function table_fetch_all ($query, $columns) {
    $count = 0;
    $res = db_query($query);
    while ($row = db_fetch_array($res)) {
        $count++;
        $even_odd = $count & 1 ? "odd" : "even";
        echo "<tr class=\"$even_odd\">";
        foreach ($columns as $field => $title) {
            $value = $row[$field];
            echo "<td>$value</td>";
        }
        echo "</tr>\n";
    }
    return $count;
}

function show_hosts ($self) {
    echo "<h1>Hosts</h1>\n";
    $table = "host";
    $columns = array(
        "vpn_ip"    => "VPN IP",
        "beg_time"  => "Start Time",
        "end_time"  => "End Time",
        "running"   => "Active",
        "cname"     => "Common Name",
        "real_ip"   => "Real IP",
        "rx_bytes"  => "Received Bytes",
        "tx_bytes"  => "Sent Bytes"
        );
    table_header($self, $table, $columns);
    $query = table_query($table, "nu_openvpn", $columns);
    $count = table_fetch_all($query, $columns);
    table_footer($table, $count);
}

function show_users ($self) {
    echo "<h1>Users</h1>\n";
    $table = "user";
    $columns = array(
        "beg_time"  => "Start Time",
        "end_time"  => "End Time",
        "username"  => "Username",
        "vpn_ip"    => "VPN IP",
        "running"   => "Active",
        "method"    => "Method",
        "sid"       => "SID"
        );
    table_header($self, $table, $columns);
    $query = table_query($table, "nu_users", $columns);
    $count = table_fetch_all($query, $columns);
    table_footer($table, $count);
}

function netusher () {
    $err = setup();
    if ($err) {
        echo "<p>$err</p>";
        db_close();
        return;
    }
    $self = "index.php";
    show_users($self);
    show_hosts($self);
    db_close();
}


