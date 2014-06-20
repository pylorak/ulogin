<?php

// This is an example that shows how to incorporate uLogin into a webpage.
// It showcases nonces, login authentication, account creation, deletion and
// remember-me functionality, all at the same time in a single page.
// Because of the number of functions shown and all the comments,
// it seems a little bit longish, but fear not.

// This is the one and only public include file for uLogin.
// Include it once on every authentication and for every protected page.
require_once('ulogin/config/all.inc.php');
require_once('ulogin/main.inc.php');

// Start a secure session if none is running
if (!sses_running())
	sses_start();

// We define some functions to log in and log out,
// as well as to determine if the user is logged in.
// This is needed because uLogin does not handle access control
// itself.

function isAppLoggedIn(){
	return isset($_SESSION['uid']) && isset($_SESSION['username']) && isset($_SESSION['loggedIn']) && ($_SESSION['loggedIn']===true);
}

function appLogin($uid, $username, $ulogin){
	$_SESSION['uid'] = $uid;
	$_SESSION['username'] = $username;
	$_SESSION['loggedIn'] = true;

	if (isset($_SESSION['appRememberMeRequested']) && ($_SESSION['appRememberMeRequested'] === true))
	{
		// Enable remember-me
		if ( !$ulogin->SetAutologin($username, true))
			echo "cannot enable autologin<br>";

		unset($_SESSION['appRememberMeRequested']);
	}
	else
	{
		// Disable remember-me
		if ( !$ulogin->SetAutologin($username, false))
			echo 'cannot disable autologin<br>';
	}
}

function appLoginFail($uid, $username, $ulogin){
	// Note, in case of a failed login, $uid, $username or both
	// might not be set (might be NULL).
	echo 'login failed<br>';
}

function appLogout(){
  // When a user explicitly logs out you'll definetely want to disable
  // autologin for the same user. For demonstration purposes,
  // we don't do that here so that the autologin function remains
  // easy to test.
  //$ulogin->SetAutologin($_SESSION['username'], false);

	unset($_SESSION['uid']);
	unset($_SESSION['username']);
	unset($_SESSION['loggedIn']);
}

// Store the messages in a variable to prevent interfering with headers manipulation.
$msg = '';

// This is the action requested by the user
$action = @$_POST['action'];

// This is the first uLogin-specific line in this file.
// We construct an instance and pass a function handle to our
// callback functions (we have just defined 'appLogin' and
// 'appLoginFail' a few lines above).
$ulogin = new uLogin('appLogin', 'appLoginFail');


// First we handle application logic. We make two cases,
// one for logged in users and one for anonymous users.
// We will handle presentation after our logic because what we present is
// also based on the logon state, but the application logic might change whether
// we are logged in or not.

if (isAppLoggedIn()){
	if ($action=='delete')	{	// We've been requested to delete the account

		// Delete account
		if ( !$ulogin->DeleteUser( $_SESSION['uid']) )
			$msg = 'account deletion failure';
		else
			$msg = 'account deleted ok';

		// Logout
		appLogout();
	} else if ($action == 'logout'){ // We've been requested to log out
		// Logout
		appLogout();
		$msg = 'logged out';
	}
} else {
	// We've been requested to log in
	if ($action=='login') {
		// Here we verify the nonce, so that only users can try to log in
		// to whom we've actually shown a login page. The first parameter
		// of Nonce::Verify needs to correspond to the parameter that we
		// used to create the nonce, but otherwise it can be anything
		// as long as they match.
		if (isset($_POST['nonce']) && ulNonce::Verify('login', $_POST['nonce'])){
			// We store it in the session if the user wants to be remembered. This is because
			// some auth backends redirect the user and we will need it after the user
			// arrives back.
      if (isset($_POST['autologin']))
        $_SESSION['appRememberMeRequested'] = true;
      else
        unset($_SESSION['appRememberMeRequested']);

			// This is the line where we actually try to authenticate against some kind
			// of user database. Note that depending on the auth backend, this function might
			// redirect the user to a different page, in which case it does not return.
			$ulogin->Authenticate($_POST['user'],  $_POST['pwd']);
			if ($ulogin->IsAuthSuccess()){
				// Since we have specified callback functions to uLogin,
				// we don't have to do anything here.
			}
		}else
			$msg = 'invalid nonce';

	} else if ($action=='autologin'){	// We were requested to use the remember-me function for logging in.
		// Note, there is no username or password for autologin ('remember me')
		$ulogin->Autologin();
		if (!$ulogin->IsAuthSuccess())
			$msg = 'autologin failure';
		else
			$msg = 'autologin ok';

	} else if ($action=='create'){	// We were requested to try to create a new acount.
		// New account
		if ( !$ulogin->CreateUser( $_POST['user'],  $_POST['pwd']) )
			$msg = 'account creation failure';
		else
			$msg = 'account created';
	}
}

// Now we handle the presentation, based on whether we are logged in or not.
// Nothing fancy, except where we create the 'login'-nonce towards the end
// while generating the login form.

header('Content-Type: text/html; charset=UTF-8');  

// This inserts a few lines of javascript so that we can debug session problems.
// This will be very usefull if you experience sudden session drops, but you'll
// want to avoid using this on a live website.
ulLog::ShowDebugConsole();

if (isAppLoggedIn()){
	?>
		<?php echo ($msg);?>
		<h3>This is a protected page. You are logged in, <?php echo($_SESSION['username']);?>.</h3>
		<form action="example.php" method="POST"><input type="hidden" name="action" value="refresh"><input type="submit" value="Refresh page"></form>
		<form action="example.php" method="POST"><input type="hidden" name="action" value="logout"><input type="submit" value="Logout"></form>
		<form action="example.php" method="POST"><input type="hidden" name="action" value="delete"><input type="submit" value="Delete account"></form>
	<?php
} else {
?>
	<?php echo ($msg);?>
	<h3>uLogin authentication example</h3>

	<form action="example.php" method="POST">
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
			Remember me:
		</td>
		<td>
			<input type="checkbox" name="autologin" value="1">
		</td>
	</tr>

    <tr>
		<td>
			Action:
		</td>
		<td>
			<select name="action">
			<option>login</option>
			<option>autologin</option>
			<option>create</option>
			</select>
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
		<input type="submit">
		</td>
	</tr>

	</table>
	</form>
<?php
}
?>