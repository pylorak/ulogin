<?php

class ulNonce
{
	private static function StoreVolatile($action, $code, $expire)
	{
		$now = new DateTime('now');
		$newnonce = array(
			'code' => $code,
			'expire' => ulUtils::date_seconds_add($now, $expire)->format('c')
		);

		$nonces = array();
		if (isset($_SESSION['ulNonces']))
			$nonces = $_SESSION['ulNonces'];

		$nonces[$action] = $newnonce;
		$_SESSION['ulNonces'] = $nonces;
		return true;
	}
	private static function StorePersistent($action, $code, $expire)
	{
		return ulPdoNonceStore::Store($action, $code, $expire);
	}

	private static function VerifyVolatile($action, $code)
	{
		if (!self::ExistsVolatile($action))
			return false;

		$ret = false;
		$now = new DateTime('now');
		$nonces = $_SESSION['ulNonces'];
		$nonce = $nonces[$action];

		// Check if nonce is valid
		$ret = (new DateTime($nonce['expire']) > $now) && ($nonce['code'] == $code);
		if ($ret == true)
		{
			//Nonce is valid, prevent further use
			unset($nonces[$action]);
			$_SESSION['ulNonces'] = $nonces;
		}

		self::Clean();
		return $ret;
	}
	private static function VerifyPersistent($action, $code)
	{
		return ulPdoNonceStore::Verify($action, $code);
	}

	private static function ExistsVolatile($action)
	{
		// Do we have nonces at all?
		if (!isset($_SESSION['ulNonces']))
			return false;

		$nonces = $_SESSION['ulNonces'];

		// Do we have a nonce for this action?
		if (!isset($nonces[$action]))
			return false;

		return true;
	}
	private static function ExistsPersistent($action)
	{
		return ulPdoNonceStore::Exists($action);
	}

	private static function CleanVolatile()
	{
		// Do we have nonces at all?
		if (!isset($_SESSION['ulNonces']))
			return true;

		$now = new DateTime('now');
		$nonces = $_SESSION['ulNonces'];

		// Check nonces if they have expired
		foreach ($nonces as $action => $nonce)
		{
			if (new DateTime($nonce['expire']) < $now)
			{
				// Nonce expired
				unset($nonces[$action]);
			}
		}

		$_SESSION['ulNonces'] = $nonces;
		return true;
	}
	private static function CleanPersistent()
	{
		return ulPdoNonceStore::Clean();
	}


// ------------------------------------------------
//           	PUBLIC INTERFACE
// ------------------------------------------------


	// Creates a new random nonce for the specified action and returns the nonce code.
	public static function Create($action, $expire=UL_NONCE_EXPIRE, $persistent=false)
	{
		$code = ulUtils::RandomBytes(16, true);
		$hashed_code = hash(UL_HMAC_FUNC, $code);

		if ($persistent === true)
			self::StorePersistent($action, $hashed_code, $expire);
		else
			self::StoreVolatile($action, $hashed_code, $expire);

		return $code;
	}

	// Returns true if there is a nonce for the specified action,
	// false otherwise.
	public static function Exists($action)
	{
		if (!self::ExistsVolatile($action))
			return self::ExistsPersistent($action);

		return true;
	}

	// Verifies that the specified nonce code belongs to the specified action.
	// Valid nonces are invalidated so that they can only be used once.
	// Returns true if the action-code pair is valid, false otherwise.
	public static function Verify($action, $code)
	{
		$hashed_code = hash(UL_HMAC_FUNC, $code);
		if (!self::VerifyVolatile($action, $hashed_code))
			return self::VerifyPersistent($action, $hashed_code);

		return true;
	}

	// Removes outdated nonces to save resources.
	// True on success, false otherwise.
	public static function Clean()
	{
		return self::CleanVolatile() && self::CleanPersistent();
	}
}

?>