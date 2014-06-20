----
-- Useful interfaces for sqlite administration
-- Web: http://code.google.com/p/phpliteadmin/
-- Local: SQLite Manager (Firefox extension)
----

CREATE TABLE "ul_blocked_ips" (
  "ip" VARCHAR(39) NOT NULL,
  "block_expires" VARCHAR(26) NOT NULL,
  PRIMARY KEY ("ip")
);

CREATE TABLE "ul_log" (
  "timestamp" VARCHAR(26) NOT NULL,
  "action" VARCHAR(20) NOT NULL,
  "comment" VARCHAR(255) NOT NULL DEFAULT '',
  "user" VARCHAR(400) NOT NULL,
  "ip" VARCHAR(39) NOT NULL
);

CREATE TABLE "ul_logins" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "username" VARCHAR(400) NOT NULL,
  "password" VARCHAR(2048) NOT NULL,
  "date_created" VARCHAR(26) NOT NULL,
  "last_login" VARCHAR(26) NOT NULL,
  "block_expires" VARCHAR(26) NOT NULL,
  UNIQUE ("username")
);

CREATE TABLE "ul_nonces" (
  "code" VARCHAR(100) NOT NULL,
  "action" VARCHAR(850) NOT NULL,
  "nonce_expires" VARCHAR(26) NOT NULL,
  PRIMARY KEY ("code"),
  UNIQUE ("action")
);

CREATE TABLE "ul_sessions" (
  "id" VARCHAR(128) NOT NULL DEFAULT '',
  "data" BLOB NOT NULL,
  "session_expires" VARCHAR(26) NOT NULL,
  "lock_expires" VARCHAR(26) NOT NULL,
  PRIMARY KEY ("id")
);