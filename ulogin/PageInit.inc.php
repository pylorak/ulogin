<?php

if (php_sapi_name() != 'cli')	// we don't want a session if running in cli
{
	if (UL_SESSION_AUTOSTART === true)
	{
		sses_start();
	}
}

?>