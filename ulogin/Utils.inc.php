<?php

class ulUtils
{
	public static function BeginsWith($string, $search)
	{
		return (substr($string, 0, strlen($search)) === $search);
	}

	public static function RandomBytes($count, $printable=FALSE)
	{
		$bytes = '';

    // supress warnings when open_basedir restricts access to /dev/urand
		if(@is_readable('/dev/urandom') && ($hRand = @fopen('/dev/urandom', 'rb')) !== FALSE)
		{
			$bytes = fread($hRand, $count);
			fclose($hRand);
		}
    if((strlen($bytes) < $count) && function_exists('mcrypt_create_iv'))
    {
        // Use MCRYPT_RAND on Windows hosts with PHP < 5.3.7, otherwise use MCRYPT_DEV_URANDOM
        // (http://bugs.php.net/55169).
        if ((version_compare(PHP_VERSION, '5.3.7', '<') && strncasecmp(PHP_OS, 'WIN', 3) == 0))
          $bytes = mcrypt_create_iv($count, MCRYPT_RAND);
        else
          $bytes = mcrypt_create_iv($count, MCRYPT_DEV_URANDOM);
    }
    if((strlen($bytes) < $count) && function_exists('openssl_random_pseudo_bytes'))  // OpenSSL slow on Win
    {
        $bytes = openssl_random_pseudo_bytes($count);
    }
    if ((strlen($bytes) < $count) && @class_exists('COM'))
    {
        // Officially deprecated in Windows 7
        // http://msdn.microsoft.com/en-us/library/aa388182%28v=vs.85%29.aspx
        try
        {
            $CAPI_Util = new COM('CAPICOM.Utilities.1');
            if(is_callable(array($CAPI_Util,'GetRandom')))
            {
                $bytes = $CAPI_Util->GetRandom(16,0);
                $bytes = base64_decode($bytes);
            }
        }
        catch (Exception $ex)
        {
        }
    }
		if (strlen($bytes) < $count)
		{
			// This fallback here based on phpass code
			$bytes = '';
			$random_state = microtime();
			if (function_exists('getmypid'))
				$random_state .= getmypid();

			for ($i = 0; $i < $count; $i += 16) {
				$random_state =
					md5(microtime() . $random_state);
				$bytes .=
					pack('H*', md5($random_state));
			}
			$bytes = substr($bytes, 0, $count);
		}

		if ($printable)
			return base64_encode($bytes);
		else
			return $bytes;
	}

	// Faster replacement of PHP's in_array(), operates by doing
	// a binary search. $array must be sorted.
	public static function in_array($elem, $array)
	{
		$top = sizeof($array) -1;
		$bot = 0;

		while($top >= $bot)
		{
			$p = floor(($top + $bot) / 2);
			if ($array[$p] < $elem) $bot = $p + 1;
			elseif ($array[$p] > $elem) $top = $p - 1;
			else return TRUE;
		}

		return FALSE;
	}

	// Returns a PHP DateTime object that is the result of
	// adding a specific number of seconds to another DateTime object.
	public static function date_seconds_add($datetime, $secs)
	{
		// DateTime::getTimestamp/setTimestamp only exist in PHP 5.3, so use following code
		// instead to stay compatible with older PHP versions.
    $unix_ts = $datetime->format('U') + $secs;
    $datetime->setDate(date('Y', $unix_ts), date('n', $unix_ts), date('d', $unix_ts));
    $datetime->setTime(date('G', $unix_ts), date('i', $unix_ts), date('s', $unix_ts));
		return $datetime;
	}

	// Returns a PHP DateTime object that is the result of
	// subtracting a specific number of secnods to another DateTime object.
	public static function date_seconds_sub($datetime, $secs)
	{
		// DateTime::getTimestamp/setTimestamp only exist in PHP 5.3, so use following code
		// instead to stay compatible with older PHP versions.
    $unix_ts = $datetime->format('U') - $secs;
    $datetime->setDate(date('Y', $unix_ts), date('n', $unix_ts), date('d', $unix_ts));
    $datetime->setTime(date('G', $unix_ts), date('i', $unix_ts), date('s', $unix_ts));
    return $datetime;
	}

	// Returns a string with the current date and time
	public static function nowstring()
	{
		return date_format(new DateTime(), UL_DATETIME_FORMAT);
	}

	// Returns a boolean value telling if the current page was requested over HTTPS.
	public static function IsHTTPS()
	{
		return (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on')) || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && ($_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https'));
	}

	// Returns the URL of the current page.
	// If $per_client is set to true, the return value will use the same domain/host name that was specified by the client request.
	// If $per_client is set to false (default), the current domain/host name will be determined from configuration files.
	// If $prot is not NULL, it will be used as the protocol identifier. If $prot is NULL, it will be determined automatically.
	public static function CurrentURL($per_client=false, $prot=NULL)
	{
		$host = NULL;
		if ($per_client)
		{
			$host = $_SERVER['HTTP_HOST'];
		}
		else
		{
			$host = UL_DOMAIN;
			if (empty($host))
				$host = SERVER_NAME;
		}

		if ($prot == NULL)
		{
			if (ulUtils::IsHTTPS())
				$prot = 'https';
			else
				$prot = 'http';
		}

		return $prot . '://' . $host . $_SERVER['REQUEST_URI'];
	}

  // Returns the IP address on the remote side of the HTTP connection as a string.
  // Return value might also be an empty string if the IP address cannot be detemined.
  // The parameter $trustHeaders controls whether the IP address can be read from
  // HTTP headers received from the client. These headers will give more reliable
  // information in case of proxies if the remote user is nice, but is much
  // more easier to spoof for attackers. As a result, for security relevant contexts
  // $trustHeaders should be set to false.
  public static function GetRemoteIP($trustHeaders = false)
  {
    $ip = '';

    if (strlen(UL_PROXY_HEADER)==0)
    {
      if ($trustHeaders)
      {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
        {
          $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'], 2);
          $ip = $ip[0];

          if (self::ValidateIP($ip))
            return $ip;
          else
            $ip = '';
        }

        if (!empty($_SERVER['HTTP_CLIENT_IP']) && self::ValidateIP($_SERVER['HTTP_CLIENT_IP']))
          return $_SERVER['HTTP_CLIENT_IP'];

        if (!empty($_SERVER['HTTP_X_FORWARDED']) && self::ValidateIP($_SERVER['HTTP_X_FORWARDED']))
          return $_SERVER['HTTP_X_FORWARDED'];

        if (!empty($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']) && self::ValidateIP($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']))
          return $_SERVER['HTTP_X_CLUSTER_CLIENT_IP'];

        if (!empty($_SERVER['HTTP_FORWARDED_FOR']) && self::ValidateIP($_SERVER['HTTP_FORWARDED_FOR']))
          return $_SERVER['HTTP_FORWARDED_FOR'];

        if (!empty($_SERVER['HTTP_FORWARDED']) && self::ValidateIP($_SERVER['HTTP_FORWARDED']))
          return $_SERVER['HTTP_FORWARDED'];
      }

      if (empty($ip))
        $ip = $_SERVER['REMOTE_ADDR'];
        
      return $ip;
    }
    else
    {
      if (empty($_SERVER[UL_PROXY_HEADER]))
      {
        // This should really not happen, because if UL_PROXY_HEADER is set
        // it means by definition that all HTTP requests must have this header.
				ul_fail('Unexpected HTTP request.');
        return false;
      }
      $ip = explode(',', $_SERVER[UL_PROXY_HEADER]);
      if ($trustHeaders)
        return $ip[0];
      else
        return end($ip);
    }
  }

  public static function ValidateIP($ip)
  {
    return (false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE));
  }
  
  public static function PreventCaching()
  {
    header("Expires: 0");
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
  }
}

?>
