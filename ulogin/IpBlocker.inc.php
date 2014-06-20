<?php

class ulIpBlocker
{
	// Blocks or unblocks an IP.
	// Set $block to a positive value to block for that many seconds.
	// Set $block to zero or negative to unblock.
	// Returns true on success, false otherwise.
	public static function SetBlock($ip, $block)
	{
		$stmt = NULL;
		$query_ret = true;

		if ($block > 0)
		{
			// Insert new IP, or extend block if it already exists
			$block_expires = ulUtils::date_seconds_add(new DateTime(), $block)->format(UL_DATETIME_FORMAT);
			$stmt = ulPdoDb::Prepare('log', 'INSERT INTO ul_blocked_ips (ip, block_expires) VALUES (?, ?)');
			$query_ret = ulPdoDb::BindExec(
				$stmt,
				NULL,		// output
				array(		// input
					&$ip, 'str',
					&$block_expires, 'str'
				)
			);

			if (!$query_ret && (ulPdoDb::ErrorCode() == '23000'))
			{
				// IP already in the list, so update
				$stmt = ulPdoDb::Prepare('log', 'UPDATE ul_blocked_ips SET block_expires=? WHERE ip=?');
				$query_ret = ulPdoDb::BindExec(
					$stmt,
					NULL,		// output
					array(		// input
						&$block_expires, 'str',
						&$ip, 'str'
					)
				);
			}
		}
		else
		{
			$stmt = ulPdoDb::Prepare('log', 'DELETE FROM ul_blocked_ips WHERE ip=?');
			$query_ret = ulPdoDb::BindExec(
				$stmt,
				NULL,		// output
				array(		// input
					&$ip, 'str'
				)
			);
		}

		if (!$query_ret || ($stmt->rowCount()==0))
		{
			ul_db_fail();
			return false;
		}

		return true;
	}

	// If the ip is blocked, returns a DateTime object
	// telling when to unblock the ip. If block expired,
	// ip is unblocked automatically.
	// If the ip is not blocked, returns a DateTime from the past.
	// Returns false on error.
	public static function IpBlocked($ip)
	{
		$block_expires = NULL;

		$stmt = ulPdoDb::Prepare('log', 'SELECT block_expires FROM ul_blocked_ips WHERE ip=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$block_expires, 'str'
			),
			array(		// input
				&$ip, 'str'
			)
		))
		{
			ul_db_fail();
			return false;
		}

		if (ulPdoDb::Fetch($stmt))
		{
			$block_expires = new DateTime($block_expires);

			if ($block_expires <= date_create('now'))
				self::SetBlock($ip, 0);
		}
		else
		{
			$block_expires = new DateTime('1000 years ago');
		}
		return $block_expires;
	}
}
?>