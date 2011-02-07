-- $Id$
-- Create database tables for UserWatch

DROP DATABASE IF EXISTS userwatch;
CREATE DATABASE userwatch DEFAULT CHARACTER SET utf8;
USE userwatch;

DROP TABLE IF EXISTS uw_openvpn;
CREATE TABLE uw_openvpn (
    cname       varchar(16) NOT NULL,
    beg_time    datetime NOT NULL,
    end_time    datetime,
    running     tinyint(1),
    real_ip     varchar(16),
    real_port   int(5),
    vpn_ip      varchar(16),
    rx_bytes    int(8),
    tx_bytes    int(8),
    PRIMARY KEY (beg_time, cname),
    KEY (vpn_ip)
);

DROP TABLE IF EXISTS uw_users;
CREATE TABLE uw_users (
    username    varchar(24) NOT NULL,
    beg_time    datetime NOT NULL,
    end_time    datetime NOT NULL,
    running     tinyint(1),
    method      varchar(3),
    vpn_ip      varchar(16),
    PRIMARY KEY (beg_time, username, vpn_ip),
    KEY (vpn_ip, username)
);

