<?php

// This is an exmaple that shows how to do proper two-factor authentication with uLogin.
// This example builds on top of example.php, so make sure you understand that first.
// For the same reason, this files is much less commented, comments are only given
// for parts new in this example.

// This example will perform first-factor authentication using UL_AUTH_BACKEND,
// and proceed with second-factor authentication using the DuoSec backend.
// Although it is not necessary in general, for simplicity
// this example is constructed in a way such that the username
// for the first- and second factors must match.

// Before using this example, make sure to create a web integration account
// at DuoSec, and add a user with a username that already exists in your
// first-factor authentication database.

require_once('ulogin/config/all.inc.php');
require_once('ulogin/main.inc.php');

if (!sses_running())
	sses_start();

function isAppLoggedIn(){
	return (isset($_SESSION['uid']) && isset($_SESSION['username']) && isset($_SESSION['loggedIn']) && ($_SESSION['loggedIn']===true));
}

// We keep track of the authentication proccess in a session variable.
// $_SESSION['loginPhase1Success'] will be set if we have
// successfully authenticated using the password, but still waiting for DuoSec.

function appAuthFactorOne($uid, $username, $ulogin){
	$_SESSION['uid'] = $uid;
	$_SESSION['username'] = $username;
	$_SESSION['loginPhase1Success'] = true;
}

function appAuthFactorTwo($uid, $username, $ulogin){
	$_SESSION['factorsCompleted'] = 2;
	$_SESSION['loggedIn'] = true;
}

function appLoginFail($uid, $username, $ulogin){
	echo 'login failed<br>';
}

function appLogout(){
	if (isAppLoggedIn())
		$GLOBALS['uloginFactorOne']->Logout($_SESSION['uid']);

	unset($_SESSION['factorsCompleted']);
	unset($_SESSION['uid']);
	unset($_SESSION['username']);
	unset($_SESSION['loggedIn']);
}

$action = @$_POST['action'];

// The first uLogin instance is used to perform first-factor auth.
// The auth backend to be used is taken from the config files.
$uloginFactorOne = new uLogin('appAuthFactorOne', 'appLoginFail');

// The second uLogin instance is used to perform second-factor auth.
// We specify the backend we want to use explicitly here.
$uloginFactorTwo = new uLogin('appAuthFactorTwo', 'appLoginFail', new ulDuoSecLoginBackend());

if (isAppLoggedIn()){
	if ($action == 'logout'){ // We were requested to log out
		// Logout
		appLogout();
	}
} else {

	if (($action=='login'))
	{
		if (!isset($_SESSION['loginPhase1Success'])) {	// are we authenticating the first factor?
			// Nonce verification
			if (isset($_POST['nonce']) && ulNonce::Verify('login', $_POST['nonce'])){

				$uloginFactorOne->Authenticate($_POST['user'],  $_POST['pwd']);

			}else
				echo 'invalid nonce<br>';
		}
		if (isset($_SESSION['loginPhase1Success'])) {		// are we authenticating the second factor?

			unset($_SESSION['loginPhase1Success']);

			// For the DuoSec backend (which we use in this example) the password is not supplied by us
			// but is collected by an external page, so we just supply an empty string as the password.
			$uloginFactorTwo->Authenticate($_SESSION['username'],  '');

		}
	}
}


// Now we handle the presentation, based on whether we are logged in or not.
// Nothing fancy, except where we create the 'login'-nonce towards the end
// while generating the login form.


if (isAppLoggedIn()){
	?>
		<h3>This is a protected page. You are logged in, <?php echo($_SESSION['username']);?>.</h3>
		<form action="example-twofactor.php" method="POST"><input type="hidden" name="action" value="refresh"><input type="submit" value="Refresh page"></form>
		<form action="example-twofactor.php" method="POST"><input type="hidden" name="action" value="logout"><input type="submit" value="Logout"></form>
	<?php
} else {
?>

	<h3>uLogin two-factor authentication example</h3>

	<form action="example-twofactor.php" method="POST">
	<table>

	<tr>
		<td>
			Username:
		</td>
		<td>
			<input type="text" name="user">
		</td>
	</tr>

	<tr>
		<td>
			Password:
		</td>
		<td>
			<input type="password" name="pwd">
		</td>
	</tr>

	<tr>
		<td>
			Nonce:
		</td>
		<td>
			<input type="text" id="nonce" name="nonce" value="<?php echo ulNonce::Create('login');?>">
		</td>
	</tr>

	<tr>
		<td>
		<input type="hidden" id="action" name="action" value="login">
		<input type="submit" value="Log in!">
		</td>
	</tr>

	</table>
	</form>
<?php
}
?>