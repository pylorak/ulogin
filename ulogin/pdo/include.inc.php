<?php

function ulogin_pdo_autoload($classname)
{
	static $map = NULL;
	if ($map == NULL)
	{
		$map = array();
		$map['ulPdoDb'] = UL_INC_DIR.'/pdo/PdoDb.inc.php';
		$map['ulPdoLoginBackend'] = UL_INC_DIR.'/pdo/PdoLoginBackend.inc.php';
		$map['ulPdoSessionStorage'] = UL_INC_DIR.'/pdo/PdoSessionStorage.inc.php';
		$map['ulPdoNonceStore'] = UL_INC_DIR.'/pdo/PdoNonceStore.inc.php';
	}
	
	if (isset($map[$classname]))
	{
		require_once($map[$classname]);
	}
}

spl_autoload_register('ulogin_pdo_autoload');

?>