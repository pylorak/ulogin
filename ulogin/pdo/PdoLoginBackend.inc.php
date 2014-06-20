<?php
require_once(UL_INC_DIR.'/LoginBackend.inc.php');

class ulPdoLoginBackend extends ulLoginBackend
{
	// Returns true if it is possible to perform user authentication by the
	// current settings. False otherwise.  Used to check cnfiguration.
	public function AuthTest()
	{
		$stmt = ulPdoDb::Prepare('auth', 'SELECT id, username, password, date_created, last_login, block_expires FROM ul_logins LIMIT 1');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,	// output
			NULL	// input
		))
		{
			return false;
		}

		ulPdoDb::Fetch($stmt);

		return true;
	}

	// Returns true if remember-me functionality can be used
	// with this backend.
	public function IsAutoLoginAllowed()
	{
		return true;
	}

	// Tries to authenticate a user against the backend.
	// Returns true is sccessfully authenticated,
	// or an error code otherwise.
	public function Authenticate($uid, $pass)
	{
		$pwd_hash = '';

		$stmt = ulPdoDb::Prepare('auth', 'SELECT password FROM ul_logins WHERE id=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$pwd_hash, 'str'
			),
			array(		// input
				&$uid, 'int'
			)
		))
		{
			ul_db_fail();
			return ulLoginBackend::BACKEND_ERROR;
		}

		if (ulPdoDb::Fetch($stmt) == false)
			return ulLoginBackend::NO_SUCH_USER;

		if (ulPassword::Verify($pass, $pwd_hash))
		{
			$this->AuthResult = $uid;
			return true;
		}
		else
		{
			$this->AuthResult = false;
			return ulLoginBackend::BAD_CREDENTIALS;
		}
	}

	// Given the backend-specific unique identifier, returns
	// a unique identifier that can be displayed to the user.
	// False on error.
	public function Username($uid)
	{
		$username = '';

		$stmt = ulPdoDb::Prepare('auth', 'SELECT username FROM ul_logins WHERE id=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$username, 'str'
			),
			array(		// input
				&$uid, 'int'
			)
		))
		{
			ul_db_fail();
			return false;
		}

		if (ulPdoDb::Fetch($stmt) == false)
			return false;

		return $username;
	}

	// Given a user-friendly unique identifier, returns
	// a backed-specific unique identifier.
	// False on error.
	public function Uid($username)
	{
		$uid = '';

		$stmt = ulPdoDb::Prepare('auth', 'SELECT id FROM ul_logins WHERE username=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$uid, 'int'
			),
			array(		// input
				&$username, 'str'
			)
		))
		{
			ul_db_fail();
			return false;
		}

		if (ulPdoDb::Fetch($stmt) == false)
			return false;

		return $uid;
	}

	// Sets the timestamp of the last login for the
	// specified user to NOW. True on success or error code.
	function UpdateLastLoginTime($uid)
	{
		$now = ulUtils::nowstring();
		$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_logins SET last_login=? WHERE id=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$now, 'str',
				&$uid, 'int'
			)
		))
		{
			ul_db_fail();
			return ulLoginBackend::BACKEND_ERROR;
		}

		if ($stmt->rowCount() == 0)
			return ulLoginBackend::NO_SUCH_USER;

		return true;
	}

	// Creates a new login for a user.
	// Returns true if successful, or an error code.
	// The format of the $profile parameter is backend-specific
	// and need not/may not be supported by the current backend.
	function CreateLogin($username, $password, $profile)
	{
		// Create password hash with a new salt
		$hashed_password = ulPassword::Hash($password, UL_PWD_FUNC);

		$now = ulUtils::nowstring();
		$past = date_format(date_create('1000 years ago'), UL_DATETIME_FORMAT);
		$stmt = ulPdoDb::Prepare('update', 'INSERT INTO ul_logins (username, password, date_created, last_login, block_expires) VALUES (?, ?, ?, ?, ?)');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$username, 'str',
				&$hashed_password, 'str',
				&$now, 'str',
				&$now, 'str',
				&$past, 'str'
			)
		))
		{
			if (ulPdoDb::ErrorCode() == '23000')
			{
				// Probably, the user already exists
				return ulLoginBackend::ALREADY_EXISTS;
			}
			else
			{
				// No, it wasn't a duplicate user... let's fail miserably.
				return ulLoginBackend::BACKEND_ERROR;
			}
		}

		return true;
	}

	// Deletes a login from the database.
	// Returns true if successful, an error code otherwise.
	public function DeleteLogin($uid)
	{
		$stmt = ulPdoDb::Prepare('delete', 'DELETE FROM ul_logins WHERE id=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$uid, 'int'
			)
		))
		{
			ul_db_fail();
			return ulLoginBackend::BACKEND_ERROR;
		}

		if ($stmt->rowCount() == 0)
			return ulLoginBackend::NO_SUCH_USER;

		return true;
	}

	// Changes the password for an already existing login.
	// Returns true if successful, an error code otherwise.
	public function SetPassword($uid, $pass)
	{
		$salt = '';
		$hashed_pass = ulPassword::Hash($pass, $salt);

		$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_logins SET password=? WHERE id=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$hashed_pass, 'str',
				&$uid, 'int'
			)
		))
		{
			return ulLoginBackend::BACKEND_ERROR;
		}

		if ($stmt->rowCount() == 0)
			return ulLoginBackend::NO_SUCH_USER;

		return true;
	}

	// Blocks or unblocks a user.
	// Set $block to a positive value to block for that many seconds.
	// Set $block to zero or negative to unblock.
	// Returns true on success, otherwise an error code.
	public function BlockUser($uid, $block_secs)
	{
		$stmt = NULL;
		$query_ret = true;

		if ($block_secs > 0)
		{
			$block_expires = ulUtils::date_seconds_add(new DateTime(), $block_secs)->format(UL_DATETIME_FORMAT);
			$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_logins SET block_expires=? WHERE id=?');
			$query_ret = ulPdoDb::BindExec(
				$stmt,
				NULL,		// output
				array(		// input
					&$block_expires, 'str',
					&$uid, 'int'
				)
			);
		}
		else
		{
			$past = date_format(date_create('1000 years ago'), UL_DATETIME_FORMAT);
			$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_logins SET block_expires=?  WHERE id=?');
			$query_ret = ulPdoDb::BindExec(
				$stmt,
				NULL,		// output
				array(		// input
					&$past, 'str',
					&$uid, 'int'
				)
			);
		}

		if ($query_ret === false)
		{
			ul_db_fail();
			return ulLoginBackend::BACKEND_ERROR;
		}

		if ($stmt->rowCount()==0)
			return ulLoginBackend::NO_SUCH_USER;

		return true;
	}

	// If the user is blocked, returns a DateTime (local timezone) object
	// telling when to unblock the user. If a past block expired
	// or the user is not blocked, returns a DateTime from the past.
	// Can also return error codes.
	// &$flagged is a boolean value which tells whether the user
	// was flagged as blocked (no matter if the block expired).
	protected function UserBlockExpires($uid, &$flagged)
	{
		$expires = NULL;
		$flagged = false;

		$stmt = ulPdoDb::Prepare('auth', 'SELECT block_expires FROM ul_logins WHERE id=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$expires, 'str'
			),
			array(		// input
				&$uid, 'int'
			)
		))
		{
			ul_db_fail();
			return ulLoginBackend::BACKEND_ERROR;
		}

		if(!ulPdoDb::Fetch($stmt))
			return ulLoginBackend::NO_SUCH_USER;


		return new DateTime($expires);
 	}
}

?>