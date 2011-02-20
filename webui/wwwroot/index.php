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
  <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.4.4/jquery.min.js"></script>
</head>
<body>
  <div id="page">
  <div id="page-inner">
    <div id="header">
    <div id="header-inner">
      <div id="logo-text">
      <div id="logo-text-inner">
        <p>UserWatch</p>
      </div>
      </div>
      <div id="logo-image"> <img src="userwatch-banner.png"/> </div>
      </div>
    </div>
    </div>
    <div id="content">
    <div id="content-inner">
<?php

ini_set('display_errors',1);
error_reporting(E_ALL);

require "../lib/userwatch.php";
userwatch();
    
?>
    </div>
    </div>
    <div id="footer">
      <div id="footer-inner"> <p>&copy; 2011, vitki.net</p> </div>
    </div>
  </div>
  </div>
</body>
</html>

