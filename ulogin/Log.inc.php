<?php

class ulLog
{
	// Inserts a record into the debug log.
  // Returns the log with the new contents.
  // Each log entry is an array member.
  // $msg should be string. If the string is empty,
	//   the call will not log anything, but simply return the
	//   current contents of the log.
  // $type can be anything from 0 (least severe/info)
  //   to 4 (most severe/error).
	public static function DebugLog($msg=NULL, $type = 0)
	{
    if (UL_DEBUG)
    {
      static $_DebugLog = array();
      if (!empty($msg))
      {
        $logEntry = array();
        $logEntry['ts'] = microtime(true);
        $logEntry['type'] = $type;
        $logEntry['msg'] = $msg;
        $_DebugLog[] = $logEntry;
      }
      return $_DebugLog;
    }
    else
    {
      return array();
    }
	}

  // Opens a javascript window showing the current contents of the debug log.
  // Only call this function where outputting javascript code is valid,
  // and call it at the end of your code.
  public static function ShowDebugConsole()
  {
    if (UL_DEBUG)
    {
      ?><script type="text/javascript">
        top.uLoginConsoleRef = window.open("", "uLoginConsoleWindow", "height=150,width=450,location=0,menubar=0,status=0,toolbar=0,scrollbars=1");
        top.uLoginConsoleRef.document.writeln(
          '<html><head><style type=text/css>'
          +'body{background-color:white}'
          +'.logtype0{color:black}'
          +'.logtype1{color:blue}'
          +'.logtype2{color:gold}'
          +'.logtype3{color:orange}'
          +'.logtype4{color:red}'
          +'</style><title>uLogin Debug Console</title>'
          +'</head><body onLoad="self.focus()"><?php
          $log = ulLog::DebugLog();
          foreach ($log as $logEntry)
          {
            $nameFormatTag = 'logtype'.$logEntry['type'];
            $openFormatTag = '<span class="'.$nameFormatTag.'">';
            $closeFormatTag = '</span>';
            $formattedTs = number_format($logEntry['ts'] - $GLOBALS['ul_start_ts'], 4);
            echo('&#8226;&nbsp;'.$openFormatTag.$formattedTs.' '.$logEntry['msg'].$closeFormatTag.'<br/>');
          }
          ?></body></html>');
          top.uLoginConsoleRef.document.close();
      </script><?php
    }
  }

	// Inserts a record into the logins log.
	// Returns true on success, false otherwise.
	public static function Log($action, $user, $ip, $comment='')
	{
		if (UL_LOG == false)
			return true;

		$now = ulUtils::nowstring();
		$stmt = ulPdoDb::Prepare('log', 'INSERT INTO ul_log (timestamp, action, comment, user, ip) VALUES (?, ?, ?, ?, ?)');
		return ulPdoDb::BindExec(
			$stmt,
			NULL,		// output
			array(		// input
				&$now, 'str',
				&$action, 'str',
				&$comment, 'str',
				&$user, 'str',
				&$ip, 'str'
			)
		);
	}

	// Deletes old log records to keep log within defined limits.
	// Returns true on success, false otherwise.
	public static function Clean()
	{
		if (UL_LOG == false)
			return false;

		if (UL_MAX_LOG_AGE > 0)
		{
			$max_log_age = ulUtils::date_seconds_sub(new DateTime(), UL_MAX_LOG_AGE)->format(UL_DATETIME_FORMAT);
			$stmt = ulPdoDb::Prepare('log', 'DELETE FROM ul_log WHERE timestamp<?');
			if (!ulPdoDb::BindExec(
				$stmt,
				NULL,		// output
				array(		// input
					&$max_log_age, 'str'
				)
			))
			{
				return false;
			}
		}

		if (UL_MAX_LOG_RECORDS > 0)
		{
			$log_num_rows = 0;
			$stmt = ulPdoDb::Prepare('log', 'SELECT COUNT(*) FROM ul_log');
			if (!ulPdoDb::BindExec(
				$stmt,
				array(		// output
					&$log_num_rows, 'int'
				),
				NULL		// input
			))
			{
				return false;
			}

			ulPdoDb::Fetch($stmt);

			if ($log_num_rows > UL_MAX_LOG_RECORDS)
			{
				$num_log_delete = $log_num_rows - UL_MAX_LOG_RECORDS;
				$stmt = ulPdoDb::Prepare('log', 'DELETE FROM ul_log ORDER BY timestamp ASC LIMIT ?');
				if (!ulPdoDb::BindExec(
					$stmt,
					NULL,		// output
					array(		// input
						&$num_log_delete, 'int'
					)
				))
				{
					return false;
				}
			}
		}

		return true;
	}

	// Returns the number of times an $action has happened
	// in the past $window seconds for a user.
	// False on error.
	public static function GetFrequencyForUser($username, $action, $window)
	{
		if (UL_LOG == false)
		{
			// We don't have the required information
			return false;
		}

		// Get the number of login attempts to an account
		$user_login_attempts = 0;
		$time_before_window = ulUtils::date_seconds_sub(new DateTime(), $window)->format(UL_DATETIME_FORMAT);
		$stmt = ulPdoDb::Prepare('log', 'SELECT COUNT(*) FROM ul_log WHERE action=? AND timestamp>? AND user=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$user_login_attempts, 'int'
			),
			array(		// input
				&$action, 'str',
				&$time_before_window, 'str',
				&$username, 'str'
			)
		))
		{
			return false;
		}

		ulPdoDb::Fetch($stmt);

		return $user_login_attempts;
	}

	// Returns the number of times an $action has happened
	// in the past $window seconds for an IP.
	// False on error.
	public static function GetFrequencyForIp($ip, $action, $window)
	{
		if (UL_LOG == false)
		{
			// We don't have the required information
			return false;
		}

		// Get the number of login attempts to an account
		$ip_login_attempts = 0;
		$time_before_window = ulUtils::date_seconds_sub(new DateTime(), $window)->format(UL_DATETIME_FORMAT);
		$stmt = ulPdoDb::Prepare('log', 'SELECT COUNT(*) FROM ul_log WHERE action=? AND timestamp>? AND ip=?');
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$ip_login_attempts, 'int'
			),
			array(		// input
				&$action, 'str',
				&$time_before_window, 'str',
				&$ip, 'str'
			)
		))
		{
			return false;
		}

		ulPdoDb::Fetch($stmt);

		return $ip_login_attempts;
	}

	// Gets how many seconds ago did a specific user log
	// in successfully.
	// False on error.
	public static function GetUserLastLoginAgo($username)
	{
		if (UL_LOG == false)
		{
			// We don't have the required information
			return false;
		}

		// Get the number of login attempts to an account
		$last_login = '';
		$stmt = ulPdoDb::Prepare('log', "SELECT timestamp FROM ul_log WHERE user=? AND action='auth-success' ORDER BY timestamp DESC LIMIT 1");
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$last_login, 'str'
			),
			array(		// input
				&$username, 'str'
			)
		))
		{			return false;
		}

		if (!ulPdoDb::Fetch($stmt))
		{
			// No successful login yet or no such user.
			return false;
		}

		return time()-strtotime($last_login);
	}

	// Gets how many seconds ago did a specific IP log
	// in successfully.
	// False on error.
	public static function GetIpLastLoginAgo($ip)
	{
		if (UL_LOG == false)
		{
			// We don't have the required information
			return false;
		}

		// Get the number of login attempts to an account
		$last_login = '';
		$stmt = ulPdoDb::Prepare('log', "SELECT timestamp FROM ul_log WHERE ip=? AND action='auth-success' ORDER BY timestamp DESC LIMIT 1");
		if (!ulPdoDb::BindExec(
			$stmt,
			array(		// output
				&$last_login, 'str'
			),
			array(		// input
				&$ip, 'str'
			)
		))
		{
			return false;
		}

		if (!ulPdoDb::Fetch($stmt))
		{
			// No successful login yet or no such user.
			return false;
		}

		return time()-strtotime($last_login);
	}
}
?>