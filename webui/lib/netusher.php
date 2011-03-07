<?php
/////////////////////////////////////////////////////////
// NetUsher Web Interface
// Main Program
// $Id$
/////////////////////////////////////////////////////////

$cfg = array(
    'mysql_host'  => 'localhost',
    'mysql_user'  => 'netusher',
    'mysql_pass'  => 'netusher',
    'mysql_db'    => 'netusher',
);

$dbh = null;

function setup () {
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

    global $dbh;
    $dbh = @mysql_connect($cfg['mysql_host'], $cfg['mysql_user'], $cfg['mysql_pass']);
    if (!$dbh)
        return "cannot connect to database: " . mysql_error();
    if (!mysql_select_db($cfg['mysql_db']))
        return "cannot select default database";
    return "";
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
    $res = mysql_query($query);
    while ($row = mysql_fetch_array($res)) {
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
    global $dbh;
    $err = setup();
    if ($err) {
        echo "<p>$err</p>";
        @mysql_close($dbh);
        return;
    }
    $self = "index.php";
    show_users($self);
    show_hosts($self);
    mysql_close($dbh);
}


