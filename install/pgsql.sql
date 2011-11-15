-- $Id$
-- Create database tables for NetUsher

SET client_encoding = 'UTF8';

DROP DATABASE netusher;
CREATE DATABASE netusher WITH ENCODING='UTF8' OWNER=netusher;
\connect netusher

DROP INDEX nu_users_idx_vpn_ip;

DROP TABLE nu_openvpn;
DROP TABLE nu_users;

CREATE TABLE nu_openvpn (
    vpn_ip      varchar(16) NOT NULL,
    beg_time    timestamp NOT NULL,
    end_time    timestamp,
    running     smallint,
    cname       varchar(20),
    real_ip     varchar(16),
    real_port   int,
    rx_bytes    int,
    tx_bytes    int,
    PRIMARY KEY (vpn_ip, beg_time)
);

CREATE TABLE nu_users (
    beg_time    timestamp NOT NULL,
    end_time    timestamp,
    username    varchar(24) NOT NULL,
    vpn_ip      varchar(16) NOT NULL,
    running     smallint,
    method      varchar(3),
    sid         varchar(32),
    PRIMARY KEY (beg_time, username, vpn_ip)
);

CREATE INDEX nu_users_idx_vpn_ip ON nu_users(vpn_ip);

-- Functions for MySQL compatibility

CREATE OR REPLACE FUNCTION from_unixtime(INTEGER) RETURNS TIMESTAMP AS $$ 
    SELECT to_timestamp($1)::timestamp AS result
$$ LANGUAGE 'SQL';

-- timestamp without time zone (i.e. 1973-11-29 21:33:09)
CREATE OR REPLACE FUNCTION unix_timestamp(TIMESTAMP) RETURNS BIGINT AS $$
    SELECT EXTRACT(EPOCH FROM $1)::bigint AS result;
$$ LANGUAGE 'SQL';
 
-- timestamp with time zone (i.e. 1973-11-29 21:33:09+01)
CREATE OR REPLACE FUNCTION unix_timestamp(TIMESTAMP WITH TIME zone) RETURNS BIGINT AS $$
    SELECT EXTRACT(EPOCH FROM $1)::bigint AS result;
$$ LANGUAGE 'SQL';

