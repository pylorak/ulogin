<?php
/**
 * @file
 * TODO:
 * 
 * Contributors:
 *  - Harry Kaizen 07-08/2014
 *  - Andreas Bontozoglou (bodozoglou@gmail.com)
 * 
 */
require_once(UL_INC_DIR.'/config/all.inc.php');
// require_once(UL_INC_DIR.'/main.inc.php'); // Check SNE is included

class KeyStats {
	//Stats variables:
	public $hitpersec;
	private $hitsperwindow;

	//Table variables: 
	public $key;
	public $row;
	public $count;

	private $isBlocked;

	//Time intervals: 
	private $tsupdate;
	private $tsreset;

	
	function __construct($AuthResult) {
		error_log("---------------------------------------------------");
		//Key Requested:
		$this->key = &$AuthResult['key'];
		//Entire row inside the database:
		$this->row = $AuthResult;

		//Initialise time since last reset:
		$now = new DateTime($this::nowstring());
		$stats_reset = new DateTime($this->row['stats_reset']);
		$this->tsreset = $this->mdiff($now, $stats_reset);

		//Is it time to reset?
		if ($this->tsreset>SNE_WINDOW) $this->resetstats();

		$this->inkcount();
		$this->updatestats();

		//Should the key be blocked or given access? 13/75
		if ($this->causingproblem()) {
			error_log("Blocked: [". $this->key."]");
			$this->inkblockcount();
			$this->allowedaccess(false);
			//Implement mail feature here:		
			// $this->sendmail();
		} else {
			error_log("Authorised: [". $this->key."]");
			$this->allowedaccess(true);
		}
	}

	//Increments the counter by one on the database for this key 
	//Updates the time since the tstamp was changed (tsupdate)
	//Potential BUG:
	//Check to see if the counter in the php variable is incremented
	//with the variable from the database and that they are both the
	//same 
	public function inkcount() {
		$this->tsupdate = new DateTime($this->row['tstamp']);
		$now = new DateTime($this::nowstring());
		$this->tsupdate = $this->mdiff($now, $this->tsupdate);
		$now = $this::nowstring();

		$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_apikeys SET count=count+1, tstamp=? WHERE key=?');
		if (!ulPdoDb::BindExec($stmt, null, array(&$now, 'str', &$this->key, 'str'))) {
			ul_db_fail();
			return $err;
		}
		echo $this->count;
	}

	//Increments the blockedcount which is the number times the api key
	//has been hit from when it was blocked:
	public function inkblockcount() {
		$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_apikeys SET blockedcount=blockedcount+1 WHERE key=?');
		if (!ulPdoDb::BindExec($stmt, NULL, array(&$this->key, 'str'))) {
			ul_db_fail();
			return $err;
		}
	}

	//Calculates the average interval of hits onto this api key since the last stats
	//reset. (VOID)
	function updatestats() {
		$this->stats_reset = new DateTime($this->row['stats_reset']);
		$this->count = $this->row['count'];
		$now = new DateTime($this::nowstring());
		$this->hitpersec = $this->count/$this->mdiff($now, $this->stats_reset);
		$this->hitsperwindow = $this->count;

		//Logging to the terminal:
		error_log("Time since statsreset: ".$this->mdiff($now, $this->stats_reset));
		error_log("Hit per second: ".$this->hitpersec);
		error_log("Hit per window: ".$this->hitsperwindow);
		error_log("|Count: ".$this->count."|Blocked Count:".$this->row['blockedcount']."|");
	}

	//If any of these conditions are true, the much will return true 
	//e.g. hitpersec<1 => The time interval beween hits has averaged to be less than 1
	//since the last stats reset. 
	function causingproblem() {
		//Conditions Array:
		$conditions = array($this->hitpersec>MAX_RS,
			$this->hitsperwindow>MAX_RI
			/*[Insert another condition]*/
			);

		for ($i = 0; $i < count($conditions); $i++) {
			if ($conditions[$i]) return true;
		}
	}

	//Resets the counter for the requested API key to 0 and changes the value for 
	//reset_stats in the table to the current time. 
	public function resetstats() {
		$now = $this::nowstring();
		//The count will be reset to 0 if the users has not been blocked
		//otherwise the count = blockcount * TransferPenalty
		$blockedcount = $this->row['blockedcount']*TRANSFERPENALTY;

		//Query
		$stmt = ulPdoDb::Prepare('update','UPDATE ul_apikeys SET blockedcount=0, count=?, stats_reset=?, tstamp=? WHERE key=?');
		$d = $this::nowstring();
		if (!ulPdoDb::BindExec($stmt, NULL, array(&$blockedcount, 'int', &$d, 'str', &$now, 'str', &$this->key, 'str'))) {
			ul_db_fail();
			//Query failed  q
			return ulLoginBackend::BACKEND_ERROR;
		}
		$this->row['statsreset'] = $now;
		$this->row['counts'] = $blockedcount; 
		$this->row['blockedcount'] = 0;
		$this->row['tstamp'] = $now;
	}

	//Returns the time and date now including microseconds:
	static function nowstring() {
		$d = date_format(new DateTime(),'d-m-Y H:i:s').substr((string)microtime(), 1, 8);
		return $d;
	}

	//Inserts a table of DB values of the api key
	function allowedaccess($allowed) {
		$keys = array_keys($this->row);
		if ($allowed) echo "<h1>Key Authorised!</h1>";
		else echo "<h1>Key Blocked!</h1>";

		echo "<h2>Variable Dump:</h2>";
		echo '<table style="width=300px">';										

		for ($i = 0; $i < count($keys); $i+=2) { 
			echo "<tr>";
			echo "<td> {$keys[$i]} </td>";
			echo "<td> {$this->row[$keys[$i]]} </td>";
			echo "</tr>";
		}
		echo "</table>";
		echo "{$this->tsreset}";
		return true;
	}

	//Microsecond difference between two dates:
	function mdiff($date1, $date2) {
		$date1sec = strtotime($date1->format('d-m-Y H:i:s.u'));
		$date2sec = strtotime($date2->format('d-m-Y H:i:s.u'));
		//Absolute val of Date 1 in seconds from  (EPOCH Time) - Date 2 in seconds from (EPOCH Time)
		$secdiff = abs($date1sec-$date2sec);
		//Creates variables for the microseconds of date1 and date2
		$micro1 = $date1->format("u");
		$micro2 = $date2->format("u");

		if (($date1sec<$date2sec && $micro1>$micro2)||($date1sec>$date2sec && $micro1<$micro2)){
			$microdiff = abs(1000000 - abs($micro1-$micro2));
			$secdiff = $secdiff - 1;
		} else {
			$microdiff = abs($micro1 - $micro2);
		}

		//Creates the variable that will hold the seconds (?):
		$difference = $secdiff.".".$microdiff;
		return $difference;
	}
}
?>