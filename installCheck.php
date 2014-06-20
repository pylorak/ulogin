<?php

require_once('ulogin/config/all.inc.php');
require_once('ulogin/main.inc.php');

$tests = array();

function add_test($dscr, $explain, $result)
{
	global $tests;
	$tests[] = array(
		'dscr' => $dscr,
		'explain' => $explain,
		'result' => $result
	);
}

function CheckDBTables()
{
	return (
		ulPdoDb::TableExists('session', 'ul_sessions') &&
		ulPdoDb::TableExists('log', 'ul_blocked_ips') &&
		ulPdoDb::TableExists('log', 'ul_log') &&
		ulPdoDb::TableExists('session', 'ul_nonces')
	);
}

function SuhosinInstalled()
{
	ob_start();
	phpinfo();
	$phpinfo = ob_get_contents();
	ob_end_clean();
	return (strpos($phpinfo, "Suhosin") !== FALSE);
}

function install_checks()
{
	global $tests;
	$tests = array();

	$dscr = 'Class uLogin available?';
	$explain = 'A basic check to see if one of the core classes is available.';
	if (class_exists('uLogin'))
		$result = 'OK';
	else
		$result = 'Error';
	add_test($dscr, $explain, $result);

	$dscr = 'PDO backend available and usable?';
	$explain = 'A basic check to see if one of the core classes is available. Also checks if the PHP PDO extension is there.';
	if (defined('PDO::ATTR_DRIVER_NAME') && class_exists('ulPdoDb'))
		$result = 'OK';
	else
		$result = 'Error';
	add_test($dscr, $explain, $result);

	$dscr = 'Default user authentication database accessible?';
	$explain = 'A correctly configured authentication database is necessary to perform logins using uLogin. If you get an error here, make sure not only that you have a working database, but also that your configuration of uLogin is correct.';
	$ulogin = new uLogin();
	if ($ulogin->Backend->AuthTest())
		$result = 'OK';
	else
		$result = 'Error';
	add_test($dscr, $explain, $result);

	$dscr = 'All support database tables exist?';
	$explain = 'Checks if database tables necessary for functionality other than logins are accessible. Operation without these tables might be possible, but with reduced functionaly, probably with reduced security.';
	if (CheckDBTables())
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'PHP installation supported?';
	if (version_compare(PHP_VERSION, '5.3.0') >= 0)
  {
    $explain = 'Your PHP version is supported. You are using ' . PHP_VERSION . '.';
		$result = 'OK';
  }
	else if (version_compare(PHP_VERSION, '5.2.0') >= 0)
  {
    $explain = 'Your PHP version (' . PHP_VERSION . ') is still supported, but future versions of uLogin will likely drop support for PHP 5.2. Please consider upgrading to PHP 5.3 or newer soon.';
		$result = 'Warning';
  }
	else
  {
    $explain = 'uLogin does not work with versions of PHP older than 5.2. You are using ' . PHP_VERSION . '.';
		$result = 'Error';
  }
	add_test($dscr, $explain, $result);

	$dscr = 'PHP on this system supports Blowfish?';
	$explain = 'uLogin uses bcrypt to store passwords, which is based on a blowfish implementation. Without blowfish, uLogin cannot store passwords.';
	if ((CRYPT_BLOWFISH == 1) || SuhosinInstalled())
		$result = 'OK';
	else
		$result = 'Error';
	add_test($dscr, $explain, $result);

	$dscr = 'PHP session.auto_start disabled?';
	$explain = 'session.auto_start interferes with the operation of secure sessions and must be disabled. To start sessions automaically for every page, enable UL_SESSION_AUTOSTART in uLogin.';
	if (!ini_get('session.auto_start'))
		$result = 'OK';
	else
		$result = 'Error';
	add_test($dscr, $explain, $result);

  if (UL_USES_AJAX)
  {
    $dscr = 'Are settings AJAX compatible?';
    $explain = 'You have indicated that your website uses AJAX technology. If you get a warning here, double-check your uLogin settings to make sure no problems arise.';
    if (UL_PREVENT_REPLAY || (UL_SESSION_REGEN_PROB > 0))
      $result = 'Warning';
    else
      $result = 'OK';
    add_test($dscr, $explain, $result);
  }
}

function security_checks()
{
	global $tests;
	$tests = array();

	$dscr = 'Is UL_SITE_KEY long enough?';
	$explain = 'The cryptographic strength of UL_SITE_KEY is important to some security features implemented by uLogin. The string should be random and contain more than 40 characters. Try using a random string from the end of this page.';
	if (strlen(UL_SITE_KEY) > 40)
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Are pages using uLogin redirected to SSL?';
	$explain = 'It is highly recommended to turn on the UL_HTTPS option. uLogin encrypts passwords serverside, so to ensure a secure password transmit from the client, an SSL-secured connection is necessary.';
	if (UL_HTTPS)
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is automatic username filtering on?';
	$explain = 'If uLogin is not set to only allow specific characters in usernames, the host application is responsible for properly filtering user input to avoid some attacks.';
	if (strlen(trim(UL_USERNAME_CHECK))>0)
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	if (UL_AUTH_BACKEND=='pdo')
	{
		$dscr = 'Is there a separate DB user for authentication?';
		$explain = 'There should be a separate database account for UL_PDO_AUTH_USER with minimal privileges.';
		if (
			(UL_PDO_AUTH_USER!=UL_PDO_UPDATE_USER) &&
			(UL_PDO_AUTH_USER!=UL_PDO_DELETE_USER) &&
			(UL_PDO_AUTH_USER!=UL_PDO_SESSIONS_USER) &&
			(UL_PDO_AUTH_USER!=UL_PDO_LOG_USER)
		)
			$result = 'OK';
		else
			$result = 'Warning';
		add_test($dscr, $explain, $result);
	}

	$dscr = 'Is the debug mode of uLogin disabled?';
	$explain = 'On a production website UL_DEBUG should be disabled or it might leak information that is useful for an attacker.';
	if (UL_DEBUG === false)
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP display_errors disabled?';
	$explain = 'On a production website the PHP display_errors directive should be set to Off or it might leak information that is useful for an attacker.';
	if ((ini_get('display_errors') == '0') || (strtolower(ini_get('display_errors')) == 'off'))
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP register_globals disabled?';
	$explain = 'If PHP register_globals is turned on, it might allow an attacker to inject and overwrite variables on the server.';
	if (!ini_get('register_globals'))
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP session.use_only_cookies enabled?';
	$explain = 'PHP should not be allowed to propagate session identifiers in URLs, because it is easier to manipulate than a cookie.';
	if (ini_get('session.use_only_cookies'))
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP session.use_trans_sid disabled?';
	$explain = 'PHP should not be allowed to rewrite form requests and URIs to contain your session ID. This is a security threat, amongst other disadvantages.';
	if (!ini_get('session.use_trans_sid'))
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP session.cookie_httponly enabled?';
	$explain = 'Enabling this will protect all your cookies from being read by user-side scripts. Even if this option is disabled uLogin will still set the \'httponly\' flag on its own cookies.';
	if (ini_get('session.cookie_httponly'))
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP session.hash_function enforced?';
	$explain = 'To make session identifiers harder to guess set session.hash_function to a valid value other than \'0\'.';
	if (ini_get('session.hash_function') != '0')
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);

	$dscr = 'Is PHP expose_php disabled?';
	$explain = 'Your HTTP server should not explicitly advertise that it is running PHP.';
	if (!ini_get('expose_php'))
		$result = 'OK';
	else
		$result = 'Warning';
	add_test($dscr, $explain, $result);
}

function WriteTable()
{
	global $tests;
?>
	<table border="0" width="400px">
		<?php foreach ($tests as $test): ?>
		 <tr>
			<td class="dscr"><a href="#" class="info"><?php echo $test['dscr'];?><span><?php echo $test['explain'];?></span></a></td>
			<td class="res"><?php echo '<span class="'.$test['result'].'">'.$test['result'].'</span>';?></td>
		 </tr>
		<?php endforeach; ?>
	</table>
<?php
}

function generate_keys()
{
	for ($i = 0; $i < 10; ++$i)
	{
		$key = ulUtils::RandomBytes(42,  true);
		echo "$key<br>";
	}
}

?>

<html>
<head>
<title>uLogin Installation Checks</title>
<style type="text/css">
<!--
.Warning{color: orange;}
.Error{color: red;}
td.res{text-align: right}

a.info{
    position:relative; /*this is the key*/
    z-index:24;
    color:#000;
    text-decoration:none;
}

a.info:hover{z-index:25; background-color:#ff0}

a.info span{display: none}

a.info:hover span{ /*the span will display just on :hover state*/
    display:block;
    position:absolute;
    top:2em; left:2em; width:15em;
    border:1px solid #0cf;
    background-color:#cff; color:#000;
    text-align: center;
}
-->
</style>
</head>
<body>

<h4>This script performs basic installation checks for uLogin as well as verifies trivial security settings.<br>
Note that this script does NOT try to detect all possible security misconfigurations, and for maximized security you should consult additional server and uLogin settings.</h4>

<h3>Installation checks</h3>
<?php install_checks(); WriteTable(); ?>

<h3>Security checks</h3>
<?php security_checks(); WriteTable(); ?>

<h3>Random strings</h3>
<?php generate_keys(); ?>



</body>
</html>
