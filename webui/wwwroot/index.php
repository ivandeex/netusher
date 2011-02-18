<?php
/////////////////////////////////////////////////////////
// UserWatch Web Interface
// Index page
// $Id$
/////////////////////////////////////////////////////////
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML Basic 1.0//EN" "http://www.w3.org/TR/xhtml-basic/xhtml-basic10.dtd">
<html>
<head>
  <title>UserWatch</title>
  <link rel="shortcut icon" href="userwatch.ico" type="image/x-icon" />
  <link rel="stylesheet" type="text/css" href="userwatch.css" />
</head>
<body>
<?php

ini_set('display_errors',1);
error_reporting(E_ALL);

require "../lib/userwatch.php";
userwatch();
    
?>
</body>
</html>

