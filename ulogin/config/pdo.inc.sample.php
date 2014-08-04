<?php

// TODO: change user names and passwords back to "CHANGE ME!!!"
// TODO: rename dbname back to ulogin

// ------------------------------------------------
//	DATABASE ACCESS
// ------------------------------------------------

// Connection string to use for connecting to a PDO database.
define('UL_PDO_CON_STRING', 'mysql:host=127.0.0.1;dbname=ulogin');
// Example for SQLite: 
//define('UL_PDO_CON_STRING', 'sqlite:/path/to/db.sqlite');

// SQL query to execute at the start of each PDO connection.
// For example, "SET NAMES 'UTF8'" if your database engine supports it.
// Unused if empty.
define('UL_PDO_CON_INIT_QUERY', "");

// ------------------------------------------------
//	DATABASE USERS
// ------------------------------------------------

// Following database users should only have access to their specified table(s).
// Optimally, no other user should have access to the same tables, except
// where listed otherwise.

// If you do not want to create all the different users, you can of course
// create just one with appropriate credentials and supply the same username and password
// to all the following fields. However, that is not recommended. You should at least have
// a separate user for the AUTH user.

// You do not need to set logins for functionality that you do not use
// (for example, if you use a different user database).

// AUTH
// Used to log users in.
// Database user with SELECT access to the
// logins table.
define('UL_PDO_AUTH_USER', 'CHANGE ME!!!');
define('UL_PDO_AUTH_PWD', 'CHANGE ME!!!');

// LOGIN UPDATE
// Used to add new and modify login data.
// Database user with SELECT, UPDATE and INSERT access to the
// logins table.
define('UL_PDO_UPDATE_USER', 'CHANGE ME!!!');
define('UL_PDO_UPDATE_PWD', 'CHANGE ME!!!');

// LOGIN DELETE
// Used to remove logins.
// Database user with SELECT and DELETE access to the
// logins table
define('UL_PDO_DELETE_USER', 'CHANGE ME!!!');
define('UL_PDO_DELETE_PWD', 'CHANGE ME!!!');

// SESSION
// Database user with SELECT, UPDATE and DELETE permissions to the
// sessions and nonces tables.
define('UL_PDO_SESSIONS_USER', 'CHANGE ME!!!');
define('UL_PDO_SESSIONS_PWD', 'CHANGE ME!!!');

// LOG
// Used to log events and analyze previous activity.
// Database user with SELECT, INSERT and DELETE access to the
// logins-log table.
define('UL_PDO_LOG_USER', 'CHANGE ME!!!');
define('UL_PDO_LOG_PWD', 'CHANGE ME!!!');

// ------------------------------------------------
//	RUNTIME CONFIGURATION 
//	 (priority over constants - uncomment if needed)
// ------------------------------------------------

/**
 * All the options in form of array. UL_PDO_CON_INIT_QUERY is 
 * assumed to be the same for all configs but it can be added
 * here later.
 */
// $UL_PDO = array(
//     'con_string'=> 'mysql:host=127.0.0.1;dbname=ulogin',
//     'auth' 	=> array('user'=> 'CHANGE ME!!!', 'pass'=> 'CHANGE ME!!!'),
//     'update' 	=> array('user'=> 'CHANGE ME!!!', 'pass'=> 'CHANGE ME!!!'),
//     'delete' 	=> array('user'=> 'CHANGE ME!!!', 'pass'=> 'CHANGE ME!!!'),
//     'session' 	=> array('user'=> 'CHANGE ME!!!', 'pass'=> 'CHANGE ME!!!'),
//     'log' 	=> array('user'=> 'CHANGE ME!!!', 'pass'=> 'CHANGE ME!!!')
// );

?>