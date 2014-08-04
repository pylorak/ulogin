<?php

// Remote SSH2 server host.
define('UL_SSH2_REMOTE_HOST', 'CHANGE ME!!!');

// Remote SSH2 server port.
// Usually 22.
define('UL_SSH2_REMOTE_PORT', 22);

// Fingerprint of the remote SSH2 server.
// If set to an empty string, uLogin will not check the fingerprint.
// If set to a non-empty string, uLogin will only connect to the remote server
// if its SSH fingerprint (sha1 in hex form) matches this setting.
define('UL_SSH2_REMOTE_FINGERPRINT', '');

?>