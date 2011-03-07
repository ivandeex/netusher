<?php
/////////////////////////////////////////////////////////
// NetUsher Web Interface
// Index page
// $Id$
/////////////////////////////////////////////////////////
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML Basic 1.0//EN" "http://www.w3.org/TR/xhtml-basic/xhtml-basic10.dtd">
<html>
<head>
  <title>NetUsher</title>
  <link rel="shortcut icon" href="netusher.ico" type="image/x-icon" />
  <link rel="stylesheet" type="text/css" href="netusher.css" />
  <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.4.4/jquery.min.js"></script>
</head>
<body>
  <div id="page">
  <div id="page-inner">
    <div id="header">
    <div id="header-inner">
      <div id="logo-text">
      <div id="logo-text-inner">
        <p>NetUsher</p>
      </div>
      </div>
      <div id="logo-image"> <img src="netusher-banner.png"/> </div>
      </div>
    </div>
    </div>
    <div id="content">
    <div id="content-inner">
<?php

ini_set('display_errors',1);
error_reporting(E_ALL);

require "../lib/netusher.php";
netusher();
    
?>
    </div>
    </div>
    <div id="footer"> <div id="footer-inner"></div> </div>
  </div>
  </div>
</body>
</html>

