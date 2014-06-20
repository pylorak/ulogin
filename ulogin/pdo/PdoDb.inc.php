<?php

function ul_db_fail()
{
	ul_fail('DB error '.ulPdoDb::ErrorCode().': '.ulPdoDb::ErrorMsg());
}

class ulPdoDb
{
	private static $dbcon;
	private static $dbmode;
	private static $preparedStmts;
	private static $errorCode;
	private static $errorMsg;

	private static function Error($errinf)
	{
		self::$errorCode = $errinf[0];
		self::$errorMsg = $errinf[2];
		return false;
	}

	private static function Connect($mode)
	{
		if ((self::$dbcon == NULL) || (self::$dbmode != $mode))
		{
			self::$preparedStmts = array();
			self::$dbmode = $mode;
            switch ($mode)
            {
              case 'auth':
				$ul_db_user = UL_PDO_AUTH_USER;
				$ul_db_pwd = UL_PDO_AUTH_PWD;
                break;
              case 'update':
				$ul_db_user = UL_PDO_UPDATE_USER;
				$ul_db_pwd = UL_PDO_UPDATE_PWD;
                break;
              case 'delete':
				$ul_db_user = UL_PDO_DELETE_USER;
				$ul_db_pwd = UL_PDO_DELETE_PWD;
                break;
              case 'log':
				$ul_db_user = UL_PDO_LOG_USER;
				$ul_db_pwd = UL_PDO_LOG_PWD;
                break;
              case 'session':
				$ul_db_user = UL_PDO_SESSIONS_USER;
				$ul_db_pwd = UL_PDO_SESSIONS_PWD;
                break;
              default:
				ul_fail('Invalid database open mode.');
				return NULL;
                break;
            }

			try
			{
				self::$dbcon = new PDO(UL_PDO_CON_STRING, $ul_db_user, $ul_db_pwd, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
			}
			catch(PDOException $e)
			{
				ul_fail('Cannot open database connection.');
				return NULL;
			}

			self::$dbcon->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);

      // Hack to try to avoid "HY000: database is locked" error with sqlite driver.
      if (self::$dbcon->getAttribute(PDO::ATTR_DRIVER_NAME) == 'sqlite')
      {
        self::$dbcon->setAttribute(PDO::ATTR_TIMEOUT, 30);
      }

			if (UL_PDO_CON_INIT_QUERY != '')
			{
				if (self::$dbcon->exec(UL_PDO_CON_INIT_QUERY) === false)
				{
					self::Error(self::$dbcon->errorInfo());
					ul_db_fail();
				}
			}
		}

		return self::$dbcon;
	}

	private static function GetPDOType($str)
	{
		switch($str)
		{
			case 'null':
				return PDO::PARAM_NULL;
				break;
			case 'bool':
				return PDO::PARAM_BOOL;
				break;
			case 'int':
				return PDO::PARAM_INT;
				break;
			case 'str':
				return PDO::PARAM_STR;
				break;
			case 'lob':
				return PDO::PARAM_LOB;
				break;
		}

		ul_fail('Unknown data type $str.');
		return 0;
	}

	public static function Prepare($dbuser, $query, $forcePrepare = false)
	{
		self::Connect($dbuser);

		$stmt = NULL;
		if (!isset(self::$preparedStmts[$query]) || ($forcePrepare == true))
		{
			$stmt = self::$dbcon->prepare($query);
			if (self::$dbcon->errorCode() == '23000')
			{
				return self::Error(self::$dbcon->errorInfo());
			}
			else if (self::$dbcon->errorCode() != '00000')
			{
				self::Error(self::$dbcon->errorInfo());
				ul_db_fail();
				return false;
			}

			self::$preparedStmts[$query] = $stmt;
		}
		else
		{
			$stmt = self::$preparedStmts[$query];
		}

		return $stmt;
	}

	public static function BindExec($stmt, $outParams, $inParams)
	{
		if ($inParams != NULL)
		{
			for ($i = 0; $i < count($inParams); $i+=2)
			{
				if (!$stmt->bindParam(($i>>1)+1, $inParams[$i], self::GetPDOType($inParams[$i+1])))
					return false;
			}
		}

		if (!self::Execute($stmt))
			return false;

		if ($outParams != NULL)
		{
			for ($i = 0; $i < count($outParams); $i+=2)
			{
				if (!$stmt->bindColumn(($i>>1)+1, $outParams[$i], self::GetPDOType($outParams[$i+1])))
					return false;
			}
		}

		return true;
	}

	public static function Execute($stmt)
	{
		if (!$stmt->execute())
			return self::Error($stmt->errorInfo());

		return true;
	}

	public static function Fetch($stmt)
	{
		return $stmt->fetch(PDO::FETCH_BOUND);
	}

	public static function Close()
	{
		self::$preparedStmts = array();
		self::$dbmode = NULL;
		self::$dbcon = NULL;
	}

	public static function InsertId()
	{
		return self::$dbcon->lastInsertId();
	}

	public static function ErrorCode()
	{
		return self::$errorCode;
	}

	public static function ErrorMsg()
	{
		return self::$errorMsg;
	}

	// Returns true if the specified table exists.
	// False othersie
	public static function TableExists($dbuser, $table_name)
	{
		self::Connect($dbuser);

		// Add compatible syntax for sqlite
		$query = self::$dbcon->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite'
				? 'SELECT name FROM sqlite_master WHERE type = "table" AND name = ?'
				: 'SHOW TABLES LIKE ?';

		$stmt = ulPdoDb::Prepare($dbuser, $query);
		if ( false === $stmt)
			ul_db_fail();

		if (!ulPdoDb::BindExec(
			$stmt,
			NULL,	// output
			array(		// input
				&$table_name, 'str'
			)
		))
		{
			return false;
		}

		if (!ulPdoDb::Fetch($stmt))
			return false;

		return true;
	}
}
?>