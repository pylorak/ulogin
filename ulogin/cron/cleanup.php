<?php

require_once('../main.inc.php');

// Limit size of log by cleaning it
ulLog::Clean();

// Clean up expired sessions of the default storage engine set in the configuration
$SessionStoreClass = UL_SESSION_BACKEND;
$SessionStore = new $SessionStoreClass();
$SessionStore->gc();

// Remove expired nonces
ulPdoNonceStore::Clean();

?>