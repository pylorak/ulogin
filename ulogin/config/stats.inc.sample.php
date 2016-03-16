<?php
// ------------------------------------------------
//	Smart Networked Enviroments : CONFIGURATION (API KEYS)
// ------------------------------------------------

//The window for the stats reset:
define('SNE_WINDOW', 150);

//MAX Interval since last timestamp:
define('SNE_INTARRIVAL', 0.5);

//Maximum allowed requests per second:
define('MAX_RS', 15);

//Max mean requests per window:
//[NOT YET IMPLEMENTED]
define('MAX_RI', 200);

//The percetage of the blocked count that is to be transfered
//from the current window to the next window when the stats are reset. 
//0-1
define('TRANSFERPENALTY', 0.1);
?> 
