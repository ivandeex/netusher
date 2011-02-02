-- $Id$
-- Create database tables for UserWatch

DROP DATABASE IF EXISTS userwatch;
CREATE DATABASE userwatch DEFAULT CHARACTER SET utf8;
USE userwatch;

DROP TABLE IF EXISTS uw_traffic;
CREATE TABLE uw_traffic (
	beg_time	datetime NOT NULL,
	end_time	datetime,
    running		tinyint(1),
	cname		varchar(16),
	real_ip		varchar(16),
	real_port	int(5),
	vpn_ip		varchar(16),
	rx_bytes	int(8),
	tx_bytes	int(8),
	PRIMARY KEY (beg_time)
);


