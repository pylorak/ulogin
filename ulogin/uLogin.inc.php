<?php

class uLogin
{
	public $Backend = NULL;
	public $LoginCallback = NULL;
	public $LoginFailCallback = NULL;

	// This can be checked any time by the caller.
	// NULL if no authentication process was in place,
	// false if there was an authentication attempt but failed,
	// or a valid Uid if authentication succeeded.
	public $AuthResult = NULL;

	public function __construct($loginCallback=NULL ,$loginFailCallback=NULL, $backend=NULL)
	{
		if ($backend == NULL)
		{
			$backend = UL_AUTH_BACKEND;
			$this->Backend = new $backend();
		}
		else
		{
			$this->Backend = $backend;
		}
		$this->LoginCallback = $loginCallback;
		$this->LoginFailCallback = $loginFailCallback;

		$this->AuthResult = $this->Backend->AuthResult;
		if ($this->IsAuthSuccess())
		{
			$uid = $this->AuthResult;
			$username = $this->Username($uid);
			$this->AuthSuccess($uid, $username);
		}
		else if ($this->AuthResult === false)
		{
			$this->AuthFail(NULL, NULL);
		}
	}

	private static function ValidateUsername($str)
	{
		// Cap user input to maximum length
		if (strlen($str) > UL_MAX_USERNAME_LENGTH)
			return false;

		// See if minimum length requirement is met
		if (strlen(trim($str)) < 1)
			return false;
      
    if (strlen(UL_USERNAME_CHECK)>0)
		{
      return preg_match(UL_USERNAME_CHECK, $str) === 1;
		}

		return true;
	}

	public function IsAuthSuccess()
	{
		return (($this->AuthResult != NULL) && ($this->AuthResult !== false));
	}

	private function AuthSuccess($uid, $username)
	{
		// Change session id to fight attacks on the session
		sses_regenerate_id(true);

		// Update last login timestamp
		$this->Backend->UpdateLastLoginTime($uid);

		// Log authentication
		ulLog::Log('auth-success', $username, ulUtils::GetRemoteIP(false));

		$this->AuthResult = $uid;

		if (is_callable($this->LoginCallback))
		{
			$callback = $this->LoginCallback;
			$callback($uid, $username, $this);
		}
	}

	private function AuthFail($uid, $username)
	{
		$this->AuthResult = false;

		// Change session id to fight attacks on the session
		sses_regenerate_id(true);

		// Log authentication attempt
		ulLog::Log('auth-fail', $username, ulUtils::GetRemoteIP(false));

		// Let us check for brute forcing attempts

		// See if the username is being brute forced
		if (($uid !== false) && ($uid != NULL) && (UL_BF_USER_LOCKOUT > 0))
		{
			// Get how many seconds ago did this user log in successfully
			$last_login_rel = ulLog::GetUserLastLoginAgo($username);
			if ($last_login_rel === false)
				$bf_window = UL_BF_WINDOW;
			else
				$bf_window = min($last_login_rel, UL_BF_WINDOW);

			$failed_attempts = ulLog::GetFrequencyForUser($username, 'auth-fail', $bf_window);
			if ($failed_attempts >= UL_BF_USER_ATTEMPTS)
			{
				// Okay, we know there have been at least UL_BF_USER_ATTEMPTS unsuccessful login attempts,
				// in the past $bf_window seconds, zero sucessfull logins since then.
				$this->Backend->BlockUser($uid, UL_BF_USER_LOCKOUT);
			}
		}

		// See if an IP is brute forcing
		if (UL_BF_IP_LOCKOUT > 0)
		{
			// Get how many seconds ago did this user log in successfully
			$ip = ulUtils::GetRemoteIP(false);
			$last_login_rel = ulLog::GetIpLastLoginAgo($ip);
			if ($last_login_rel === false)
				$bf_window = UL_BF_WINDOW;
			else
				$bf_window = min($last_login_rel, UL_BF_WINDOW);

			$failed_attempts = ulLog::GetFrequencyForIp($ip, 'auth-fail', $bf_window);
			if ($failed_attempts >= UL_BF_IP_ATTEMPTS)
			{
				// Okay, we know there have been at least UL_BF_IP_ATTEMPTS unsuccessful login attempts,
				// in the past $bf_window seconds, zero sucessfull logins since then.
				ulIpBlocker::SetBlock($ip, UL_BF_IP_LOCKOUT);
			}
		}

		if (is_callable($this->LoginFailCallback))
		{
			$callback = $this->LoginFailCallback;
			$callback($uid, $username, $this);
		}
	}

	private function BlockCheck($uid)
	{
		// Check if the IP is blocked
		if (UL_BF_IP_LOCKOUT > 0)
		{
			$block_expires = ulIpBlocker::IpBlocked(ulUtils::GetRemoteIP(false));
			if ($block_expires == false)
			{
				ul_fail('Failure during login, cannot get block status.');
				return false;
			}

			if ($block_expires > date_create('now'))
			{
				// IP is blocked
				return false;
			}
		}

		// Check if the user is blocked
		if (UL_BF_USER_LOCKOUT > 0)
		{
			$block_expires = $this->Backend->UserBlocked($uid);
			if ((!is_object($block_expires) || (get_class($block_expires) != 'DateTime')))
			{
				ul_fail('Failure during login, cannot get block status.');
				return false;
			}

			if ($block_expires > date_create('now'))
			{
				// User is blocked
				return false;
			}
		}

		return true;
	}

	// Given a uid and a password, this function returns the uid,
	// if all of the following conditions are met:
	// - specified user has the specified password
	// - IP or user has not been blocked
	private function Authenticate3($uid, $password)
	{
		if ($uid == false)
		{
			// No such user
			return false;
		}

		if ($this->BlockCheck($uid) !== true)
			return false;

		if ($this->Backend->Authenticate($uid, $password) === true)
			return $uid;
		else
			return false;
	}

	// If the specified user has the specified password, logs the user in
	// and returns true. Returns false otherwise.
	// If the user is blocked, the return of this function will be
	// as if the login information was incorrect.
	private function Authenticate2($username, $password)
	{
		$this->AuthResult = NULL;

		// Validate user input
		if (!self::ValidateUsername($username))
			return false;
		if (!ulPassword::IsValid($password))
			return false;

		$uid = $this->Backend->Uid($username);
		$this->AuthResult = $this->Authenticate3($uid, $password);

		if ($this->IsAuthSuccess())
			$this->AuthSuccess($uid, $username);
		else
			$this->AuthFail($uid, $username);

		return $this->AuthResult;
	}

	// If the specified user has the specified password, logs the user in
	// and returns true. Returns false otherwise.
	// If the user is blocked, the return of this function will be
	// as if the login information was incorrect.
	public function Authenticate($username, $password)
	{
		$start = microtime(true);
		$ret = $this->Authenticate2($username, $password);
		$total = microtime(true) - $start;

		if (!$this->IsAuthSuccess() && (UL_LOGIN_DELAY > 0))
		{
			// Here we make all false login attempts last the same amount of time
			// to avoid timing attacks on valid usernames.

			$exec_limit = ini_get('max_execution_time');
			set_time_limit(0);

			while ($total < UL_LOGIN_DELAY)
			{
				$us = (UL_LOGIN_DELAY-$total)*1000000;

				// Stall next login for a bit.
				// This will considerably slow down brute force attackers.
				usleep($us);

				$total = microtime(true) - $start;
			}

			set_time_limit($exec_limit);
		}

		return $ret;
	}

	// Returns the username corresponding to a user id.
	// Returns false on error.
	public function Username($uid)
	{
		return $this->Backend->Username($uid);
	}

	// Returns the uid corresponding to a username.
	// Returns false on error.
	public function Uid($username = NULL)
	{
		// Validate user input
		if (!self::ValidateUsername($username))
			return false;

		return $this->Backend->Uid($username);
	}

	// Perform actions related to a logout, like disabling remember-me.
	// However, actually logging out is a task of the host application.
	public function Logout($uid)
	{
		$username = $this->Username($uid);
		ulLog::Log('logout', $username, ulUtils::GetRemoteIP(false));

		$this->SetAutologin($username, false);
	}

	// Creates a new user in the database.
	// Returns true if successful, false if the user already exists or inputs are
  // invalid, NULL on other errors.
  // $profile, if supplied, contains backend-specific data to be inserted, where
  // backend is supposed to simultanously contain login and profile information (eg. LDAP.)
	public function CreateUser($username, $password, $profile=NULL)
	{
		// Validate user input
		if (!self::ValidateUsername($username))
			return false;
		if (!ulPassword::IsValid($password))
			return false;

		$ret = $this->Backend->CreateLogin($username, $password, $profile);
		if ($ret !== true)
		{
			if ($ret == ulLoginBackend::ALREADY_EXISTS)
				return false;
			else
				return NULL;
		}

		ulLog::Log('create login', $username, ulUtils::GetRemoteIP(false));

		return true;
	}

	// Sets a new password to a user.
	// Returns true if successful, false otherwise.
	public function SetPassword($uid, $password)
	{
		// Validate user input
		if (!ulPassword::IsValid($password))
			return false;

		return $this->Backend->SetPassword($uid, $password) === true;
	}

	// Deletes new user from the database.
	// Returns true if successful, false otherwise.
	public function DeleteUser($uid)
	{
		// Needed for logging
		$username = self::Username($uid);
		if ($username === false)
			return false;

		// Delete user and logout
		$ret = $this->Backend->DeleteLogin($uid);
		if ($ret === true)
			ulLog::Log('delete login', $username, ulUtils::GetRemoteIP(false));
		return $ret === true;
	}

	// Blocks or unblocks a user.
	// Set $block to a positive value to block for that many seconds.
	// Set $block to zero or negative to unblock.
	// Returns true on success, false otherwise.
	public function BlockUser($uid, $block)
	{
		return $this->Backend->BlockUser($uid, $block) === true;
	}

	// If the user is blocked, returns a DateTime object
	// telling when to unblock the user. If block expired, user is unblocked
	// automatically.
	// If the user is not blocked, returns a DateTime from the past.
	// Returns false on error.
	public function IsUserBlocked($uid)
	{
		return $this->Backend->UserBlocked($uid) == true;
	}

	public function SetAutologin($username, $enable)
	{
		// Set SSL level
		$httpsOnly = ulUtils::IsHTTPS();

		// Cookie-name
		$autologin_name = 'AutoLogin';

		if ($enable == true)
		{
			if (!$this->Backend->IsAutoLoginAllowed())
				return false;

			// Validate user input
			if (!self::ValidateUsername($username))
				return false;

			// Check whetehr the user exists
			$uid = $this->Uid($username);
			if ($uid === false)
				return false;

			// Cookie expiry
			$expire = time()+UL_AUTOLOGIN_EXPIRE;

			// We store a nonce in the cookie so that it can only be used once
			$nonce = ulNonce::Create("$username-autologin", UL_AUTOLOGIN_EXPIRE, true);

			// HMAC
			// Used to verify that cookie really comes from us
			$hmac = hash_hmac(UL_HMAC_FUNC, "$username:::$nonce", UL_SITE_KEY);

			// Construct contents
			$autologin_data = "$username:::$nonce:::$hmac";

			// Set autologin cookie
			setcookie($autologin_name, $autologin_data, $expire, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN, $httpsOnly, true);
		}
		else
		{
			// Cookie expiry
			$expire = time()-(3600*24*365);

			$autologin_data = '';

			// Set autologin cookie
			setcookie($autologin_name, $autologin_data, $expire, '/', (UL_DOMAIN === 'localhost') ? '' : UL_DOMAIN, $httpsOnly, true);
		}

		return true;
	}

	public function Autologin()
	{
		if (!$this->Backend->IsAutoLoginAllowed())
			return false;

		// Cookie-name
		$autologin_name = 'AutoLogin';

		// Read encrypted cookie
		if (!isset($_COOKIE[$autologin_name]))
			return false;
		$data = $_COOKIE[$autologin_name];

		// Decrypt cookie data
		$parts = explode(':::', $data);
		$username = $parts[0];
		$nonce = $parts[1];
		$hmac = $parts[2];

		// Check if nonce in cookie is valid
		if (!ulNonce::Verify("$username-autologin", $nonce))
		{
			$this->SetAutologin($username, false);
			return false;
		}

		// Check if cookie was set by us.
		if ($hmac != hash_hmac(UL_HMAC_FUNC, "$username:::$nonce", UL_SITE_KEY))
		{
			$this->SetAutologin($username, false);
			$this->AuthFail(NULL, $username);
			return false;
		}

		// Get Uid and see if user exists. See if user is still valid.
		$uid = $this->Uid($username);
		if ($uid === false)
		{
			$this->SetAutologin($username, false);
			$this->AuthFail(NULL, $username);
			return false;
		}

		// Check if there is a block that applies to us
		if ($this->BlockCheck($uid) !== true)
		{
			$this->SetAutologin($username, false);
			$this->AuthFail($uid, $username);
			return false;
		}

		// Everything seems alright. Log user in and set new autologin cookie.
		$this->AuthSuccess($uid, $username);
		$this->SetAutologin($username, true);

		return $uid;
	}
}

?>