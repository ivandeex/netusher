-- $Id$
-- Create database tables for NetUsher

DROP DATABASE IF EXISTS netusher;
CREATE DATABASE netusher DEFAULT CHARACTER SET utf8;
USE netusher;

DROP TABLE IF EXISTS nu_openvpn;
CREATE TABLE nu_openvpn (
    vpn_ip      varchar(16) NOT NULL,
    beg_time    datetime NOT NULL,
    end_time    datetime,
    running     tinyint(1),
    cname       varchar(20),
    real_ip     varchar(16),
    real_port   int(5),
    rx_bytes    int(8),
    tx_bytes    int(8),
    PRIMARY KEY (vpn_ip, beg_time)
);

DROP TABLE IF EXISTS nu_users;
CREATE TABLE nu_users (
    beg_time    datetime NOT NULL,
    end_time    datetime,
    username    varchar(24) NOT NULL,
    vpn_ip      varchar(16) NOT NULL,
    running     tinyint(1),
    method      varchar(3),
    sid         varchar(32),
    PRIMARY KEY (beg_time, username, vpn_ip),
    KEY (vpn_ip)
);

