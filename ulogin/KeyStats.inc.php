<?php
/**
 * @file
 * TODO:
 * 
 *  - Rename to KeyBlocker to match IpBlocker
 * 
 * Contributors:
 *  - 07-08/2014 Harry Kaizen - Core Code (himion0@gmail.com)
 *  - Andreas Bontozoglou     - GitHub integration (bodozoglou@gmail.com)
 * 
 */
require_once(UL_INC_DIR.'/config/all.inc.php');

class ulKeyStats {
	// Stats variables
	public $hitpersec;
	public $hitsperwindow;

	// Key shortcut variables
	protected $key;
	protected $id;
	protected $row;
	protected $count;
	
	// Cache some vars
	// Now
	private $now;
	private $nowstr;
	// Stats reset as DateTime
	private $stats_reset;
	// Last Update timestamp
	private $tsupdate;
	// Time interval Since reset
	private $tsreset;
	
	// True is stats blocked the key
	private $blockedStats=false;

	
	function __construct($AuthResult) {
		error_log("---------------------------------------------------");
		// Key Requested:
		$this->key = &$AuthResult['key'];
		$this->id  = &$AuthResult['id'];
		
		// Entire row inside the database:
		$this->row = $AuthResult;

		//Initialise time since last reset:
		$this->nowstr = self::nowstring();
		$this->now = new DateTime($this->nowstr);
		$this->stats_reset = new DateTime($this->row['stats_reset']);
		$this->tsupdate = new DateTime($this->row['tstamp']);
		$this->tsreset = $this->mdiff($this->now, $this->stats_reset);
		
		$this->count = $this->row['count'];

		//Is it time to reset?
		if ($this->tsreset > KEY_WINDOW || $this->row['stats_reset']=="") $this->ResetStats();

		$this->InkCount();
		$this->UpdateStats();

		//Should the key be blocked or given access? 13/75
		if ($this->CausingProblem()) {
		    $this->blockedStats=true;
		    error_log("Blocked: [". $this->id."]");
		    $this->InkBlockCount();
// 			$this->AllowedAccess(false);
		    //Implement mail feature here:		
		    // $this->sendmail();
		} else {
		    error_log("Authorised: [". $this->id."]");
// 			$this->AllowedAccess(true);
		}
	}

	//Increments the counter by one on the database for this key 
	//Updates the time since the tstamp was changed (tsupdate)
	//Potential BUG:
	//Check to see if the counter in the php variable is incremented
	//with the variable from the database and that they are both the
	//same 
	//
	//TODO: Use ID in WHERE condition
	public function InkCount() {

		$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_apikeys SET count=count+1, tstamp=? WHERE id=?');
		if (!ulPdoDb::BindExec($stmt, null, array(&$this->nowstr, 'str', &$this->id, 'str'))) {
			ul_db_fail();
			return $err;
		}
		$this->count++;
	}

	//Increments the blockedcount which is the number times the api key
	//has been hit from when it was blocked:
	public function InkBlockCount() {
		$stmt = ulPdoDb::Prepare('update', 'UPDATE ul_apikeys SET blockedcount=blockedcount+1 WHERE id=?');
		if (!ulPdoDb::BindExec($stmt, NULL, array(&$this->id, 'str'))) {
			ul_db_fail();
			return $err;
		}
	}

	//Calculates the average interval of hits onto this api key since the last stats
	//reset. (VOID)
	function UpdateStats() {
		$this->hitpersec = $this->count/$this->tsreset;
		$this->hitsperwindow = $this->count;

		//Logging to the terminal:
		error_log("Time since statsreset: ".$this->tsreset);
		error_log("Hit per second: ".$this->hitpersec);
		error_log("Hit per window: ".$this->hitsperwindow);
		error_log("|Count: ".$this->count."|Blocked Count:".$this->row['blockedcount']."|");
	}

	//If any of these conditions are true, the much will return true 
	//e.g. hitpersec<1 => The time interval beween hits has averaged to be less than 1
	//since the last stats reset. 
	function CausingProblem() {
		//Conditions Array:
		$conditions = array(
			$this->hitpersec    > MAX_RS,  // Req/Second
			$this->hitsperwindow> MAX_RI   // Req/Interval
			/*[Insert another condition]*/
			);

		for ($i = 0; $i < count($conditions); $i++) {
			if ($conditions[$i]) return true;
		}
		
		return false;
	}

	//Resets the counter for the requested API key to 0 and changes the value for 
	//reset_stats in the table to the current time. 
	public function ResetStats() {
		error_log("RESET");
		//The count will be reset to 0 if the users has not been blocked
		//otherwise the count = blockcount * TransferPenalty
		$blockedcount = $this->row['blockedcount']*TRANSFER_PENALTY;

		//Query
		$stmt = ulPdoDb::Prepare('update','UPDATE ul_apikeys SET blockedcount=0, count=?, stats_reset=?, tstamp=? WHERE id=?');
		$d = $this::nowstring();
		if (!ulPdoDb::BindExec($stmt, NULL, array(&$blockedcount, 'int', &$d, 'str', &$this->nowstr, 'str', &$this->id, 'str'))) {
			ul_db_fail();
			//Query failed  q
			return ulLoginBackend::BACKEND_ERROR;
		}
		$this->count = $blockedcount; 
	}

	//Returns the time and date now including microseconds:
	static function nowstring() {
		$d = date_format(new DateTime(),'d-m-Y H:i:s').substr((string)microtime(), 1, 8);
		return $d;
	}

	//Inserts a table of DB values of the api key
	function AllowedAccess($allowed) {
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
	
	// Return true if the key is blocked by stats
	// Higher level framework may decide to allow
	// (or ignore) that
	public function isBlockedByStats(){
	    return $this->blockedStats;
	}
}
?>