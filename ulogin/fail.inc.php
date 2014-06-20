<?php

function ul_fail($msg, $terminate=true)
{
	if (UL_DEBUG)
	{
    ob_start();
    debug_print_backtrace();
    $trace = ob_get_contents();
    ob_end_clean();
    $trace = str_replace(UL_SITE_ROOT_DIR, '', $trace);
    
		$log_str = 'Error: ' . htmlspecialchars($msg) . '<br/> Stack trace: ' . htmlspecialchars($trace) . '<br/>';
		echo(nl2br('<div style="background-color:darkred; border:2px solid black; color:yellow; padding:5px;">'.$log_str.'</div>'));

    // Optionally, do logging below
    //$log_str = date('F j, Y, H:i:s') . "Error: $msg \r\n Stack trace: $trace \r\n \r\n";
    //error_log($log_str, 3, UL_SITE_LOG_DIR . '/mainlog');
	}

	if ($terminate)
		die(UL_GENERIC_ERROR_MSG);
	else
		echo(UL_GENERIC_ERROR_MSG);
}
?>