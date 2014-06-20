<?php

function ulogin_duosec_autoload($classname)
{
	static $map = NULL;
	if ($map == NULL)
	{
		$map = array();
		$map['ulDuoSecLoginBackend'] = UL_INC_DIR.'/duosec/DuoSecLoginBackend.inc.php';
		$map['Duo'] = UL_INC_DIR.'/duosec/duo_php/duo_web.php';
	}

	if (isset($map[$classname]))
	{
		require_once($map[$classname]);
	}
}

spl_autoload_register('ulogin_duosec_autoload');

?>