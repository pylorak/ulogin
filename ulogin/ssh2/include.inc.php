<?php

function ulogin_ssh2_autoload($classname)
{
	static $map = NULL;
	if ($map == NULL)
	{
		$map = array();
		$map['ulSsh2LoginBackend'] = UL_INC_DIR.'/ssh2/Ssh2LoginBackend.inc.php';
	}

	if (isset($map[$classname]))
	{
		require_once($map[$classname]);
	}
}

spl_autoload_register('ulogin_ssh2_autoload');

?>