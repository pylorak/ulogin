<?php

class ulPdoNonceStore
{
	public static function Store($action, $code, $expire)
	{
		// Insert new nonce into database
		$nonce_expires = ulUtils::date_seconds_add(new DateTime(), $expire)->format(UL_DATETIME_FORMAT);
		$stmt = ulPdoDb::Prepare('session', 'INSERT INTO ul_nonces (code, action, nonce_expires) VALUES (?, ?, ?)');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$code, 'str',
				&$action, 'str',
				&$nonce_expires, 'str'
			)
		))
		{
			if (ulPdoDb::ErrorCode() == '23000')
			{
				// Probably, the action already exists
				$stmt = ulPdoDb::Prepare('session', 'UPDATE ul_nonces SET code=?, nonce_expires=? WHERE action=?');
				if (!ulPdoDb::BindExec(
					$stmt,
					NULL,		// output
					array(		// input
						&$code, 'str',
						&$nonce_expires, 'str',
						&$action, 'str'
					)
				))
				{
					ul_db_fail();
					return false;
				}
			}
			else
			{
				// No, it wasn't a duplicate user... let's fail miserably.
				ul_db_fail();
				return false;
			}
		}

		return true;
	}


	public static function Verify($action, $code)
	{
		// See if there is a nonce like the one requested
		$exists = 0;
		$now = ulUtils::nowstring();
		$stmt = ulPdoDb::Prepare('session', 'SELECT COUNT(*) FROM ul_nonces WHERE code=? AND action=? AND nonce_expires>?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$exists, 'int'
			),
			array(		// input
				&$code, 'str',
				&$action, 'str',
				&$now, 'str'
			)
		))
		{
			ul_db_fail();
			return false;
		}

		ulPdoDb::Fetch($stmt);

		if ($exists > 0)
		{
			// We have found a nonce, invalidate it
			$stmt = ulPdoDb::Prepare('session', 'DELETE FROM ul_nonces WHERE code=? AND action=?');
			if (!ulPdoDb::BindExec(
				$stmt,
				NULL,		// output
				array(		// input
					&$code, 'str',
					&$action, 'str'
				)
			))
			{
				ul_db_fail();
			}

			return true;
		}
		else
		{
			// Invalid nonce
			return false;
		}
	}


	public static function Exists($action)
	{
		// See if there is a nonce like the one requested
		$exists = 0;
		$stmt = ulPdoDb::Prepare('session', 'SELECT COUNT(*) FROM ul_nonces WHERE action=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$exists, 'int'
			),
			array(		// input
				&$action, 'str'
			)
		))
		{
			ul_db_fail();
			return false;
		}

		ulPdoDb::Fetch($stmt);

		return ($exists > 0);
	}

	public static function Clean()
	{
		// We have found a nonce, invalidate it
		$now = ulUtils::nowstring();
		$stmt = ulPdoDb::Prepare('session', 'DELETE FROM ul_nonces WHERE nonce_expires<?');
		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$now, 'str'
			)
		))
		{
			ul_db_fail();
			return false;
		}

		return true;
	}
}
?>