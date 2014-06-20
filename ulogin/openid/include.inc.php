<?php

function ulogin_openid_autoload($classname)
{
	static $map = NULL;
	if ($map == NULL)
	{
		$map = array();
		$map['ulOpenIdLoginBackend'] = UL_INC_DIR.'/openid/OpenIdLoginBackend.inc.php';
		$map['LightOpenID'] = UL_INC_DIR.'/openid/lightopenid/openid.php';
	}

	if (isset($map[$classname]))
	{
		require_once($map[$classname]);
	}
}

spl_autoload_register('ulogin_openid_autoload');

?>