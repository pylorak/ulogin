<?php

class ulLoginBackend
{
	const ERROR = -1;			// Unidentifieable error
	const BAD_CREDENTIALS = -2;	// Bad login
	const NO_SUCH_USER = -3;	// User not found
	const BACKEND_ERROR = -4;	// Error in backend
	const NOT_SUPPORTED = -5;	// Not supprted by this backend, will never be unless "upstream" fixes it
	const NOT_IMPLEMENTED = -6;	// Not yet implemented in uLogin
	const ALREADY_EXISTS = -7;	// Trying to add a duplicate of a unique object
	const INVALID_OP = -8;	// Operation not valid in the current state

	// This can be checked any time by the caller.
	// NULL if no authentication process was in place,
	// false if there was an authentication attempt but failed,
	// or a valid Uid if authentication succeeded.
	public $AuthResult = NULL;

	// Returns true if it is possible to perform user authentication by the
	// current settings. Can also return error codes.
	public function AuthTest()
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// Returns true if remember-me functionality can be used
	// with this backend.
	public function IsAutoLoginAllowed()
	{
		return false;
	}

	// Tries to authenticate a user against the backend.
	// Returns true if sccessfully authenticated,
	// or an error code otherwise.
	public function Authenticate($uid, $pass)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// Given the backend-specific unique identifier, returns
	// a unique identifier that can be displayed to the user.
	// False on error.
	public function Username($uid)
	{
		return false;
	}

	// Given a user-friendly unique identifier, returns
	// a backed-specific unique identifier.
	// False on error.
	public function Uid($username)
	{
		return false;
	}

	// Sets the timestamp of the last login for the
	// specified user to NOW. True on success or error code.
	public function UpdateLastLoginTime($uid)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// Creates a new login for a user.
	// Returns true if successful, or an error code.
	// The format of the $profile parameter is backend-specific
	// and need not/may not be supported by the current backend.
	public function CreateLogin($username, $password, $profile)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// Deletes a login from the database.
	// Returns true if successful, an error code otherwise.
	public function DeleteLogin($uid)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// Changes the password for an already existing login.
	// Returns true if successful, an error code otherwise.
	public function SetPassword($uid, $pass)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// Blocks or unblocks a user.
	// Set $block to a positive value to block for that many seconds.
	// Set $block to zero or negative to unblock.
	// Returns true on success, otherwise an error code.
	public function BlockUser($uid, $block_secs)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

	// If the user is blocked, returns a DateTime (local timezone) object
	// telling when to unblock the user. If a past block expired
	// or the user is not blocked, returns a DateTime from the past.
	// If there is a block flag on the user but the block expired,
	// this method also automatically unblocks the user.
	// Can also return error codes.
	public function UserBlocked($uid)
	{
		$flagged = false;
		$expire = $this->UserBlockExpires($uid, $flagged);
		if (is_object($expire) && (get_class($expire) == 'DateTime'))	// make sure not an error code
		{
			if ($flagged && ($expire <= date_create('now')))
			{
				$this->BlockUser($uid, -1);
			}
		}
		return $expire;
	}

	// If the user is blocked, returns a DateTime (local timezone) object
	// telling when to unblock the user. If a past block expired
	// or the user is not blocked, returns a DateTime from the past.
	// Can also return error codes.
	// &$flagged is a boolean value which tells whether the user
	// was flagged as blocked (no matter if the block expired).
	protected function UserBlockExpires($uid, &$flagged)
	{
		return ulLoginBackend::NOT_IMPLEMENTED;
	}

}

?>