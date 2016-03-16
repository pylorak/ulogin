-- --
-- When importing this file in phpMyAdmin, use the ANSI dialect
-- --

CREATE TABLE "ul_blocked_ips" (
  "ip" varchar(39) CHARACTER SET ascii NOT NULL,
  "block_expires" varchar(26) CHARACTER SET ascii NOT NULL,
  PRIMARY KEY ("ip")
);

CREATE TABLE "ul_log" (
  "timestamp" varchar(26) CHARACTER SET ascii NOT NULL,
  "action" varchar(20) CHARACTER SET ascii NOT NULL,
  "comment" varchar(255) CHARACTER SET ascii NOT NULL DEFAULT '',
  "user" varchar(400) COLLATE utf8_unicode_ci NOT NULL,
  "ip" varchar(39) CHARACTER SET ascii NOT NULL
);

CREATE TABLE "ul_logins" (
  "id" int(11) NOT NULL AUTO_INCREMENT,
  "username" varchar(400) COLLATE utf8_unicode_ci NOT NULL,
  "password" varchar(2048) CHARACTER SET ascii NOT NULL,
  "date_created" varchar(26) CHARACTER SET ascii NOT NULL,
  "last_login" varchar(26) CHARACTER SET ascii NOT NULL,
  "block_expires" varchar(26) CHARACTER SET ascii NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "username" ("username"(255))
) AUTO_INCREMENT=1 ;

CREATE TABLE "ul_nonces" (
  "code" varchar(100) CHARACTER SET ascii NOT NULL,
  "action" varchar(850) CHARACTER SET ascii NOT NULL,
  "nonce_expires" varchar(26) CHARACTER SET ascii NOT NULL,
  PRIMARY KEY ("code"),
  UNIQUE KEY "action" ("action"(255))
);

CREATE TABLE "ul_sessions" (
  "id" varchar(128) CHARACTER SET ascii NOT NULL DEFAULT '',
  "data" blob NOT NULL,
  "session_expires" varchar(26) CHARACTER SET ascii NOT NULL,
  "lock_expires" varchar(26) CHARACTER SET ascii NOT NULL,
  PRIMARY KEY ("id")
);

CREATE TABLE "ul_apikeys" (
  "id" int(10) unsigned NOT NULL AUTO_INCREMENT,
  "uid" int(11) NOT NULL,
  "key" varchar(64) CHARACTER SET ascii NOT NULL,
  "type" int(11) NOT NULL,
  "date_created" varchar(26) CHARACTER SET ascii NOT NULL,
  "stats_reset" varchar(26) CHARACTER SET ascii NOT NULL,
  "count" int(3) NOT NULL DEFAULT '0',
  "blockedcount" int(1) NOT NULL DEFAULT 0,
  "tstamp" varchar(27) CHARACTER SET ascii NOT NULL DEFAULT '01-01-2000 00:00:00.000000',
  "block_expires" varchar(26) CHARACTER SET ascii NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "key" ("key"),
  FOREIGN KEY ("uid") REFERENCES "ul_logins"("id") ON DELETE CASCADE ON UPDATE CASCADE
) AUTO_INCREMENT=1;
