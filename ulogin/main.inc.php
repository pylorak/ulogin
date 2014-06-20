<?php

function ulogin_base_autoload($classname)
{
	static $map = NULL;
	if ($map == NULL)
	{
		$map = array();
		$map['uLogin'] = UL_INC_DIR.'/uLogin.inc.php';
		$map['ulPassword'] = UL_INC_DIR.'/Password.inc.php';
		$map['ulUtils'] = UL_INC_DIR.'/Utils.inc.php';
		$map['ulIpBlocker'] = UL_INC_DIR.'/IpBlocker.inc.php';
		$map['ulNonce'] = UL_INC_DIR.'/Nonce.inc.php';
		$map['ulLog'] = UL_INC_DIR.'/Log.inc.php';
		$map['ulLoginBackend'] = UL_INC_DIR.'/LoginBackend.inc.php';
		$map['ulPhpDefaultSessionStorage'] = UL_INC_DIR.'/PhpDefaultSessionStorage.inc.php';
	}

	if (isset($map[$classname]))
	{
		require_once($map[$classname]);
	}
}

if (UL_DEBUG)
{
	error_reporting(E_ALL | E_STRICT);
  $GLOBALS['ul_start_ts'] = microtime(true);
}

require_once(UL_INC_DIR.'/fail.inc.php');
spl_autoload_register('ulogin_base_autoload');
require_once(UL_INC_DIR.'/secure_page.inc.php');

// Add extensions/backends
$extensions = glob(UL_INC_DIR.'/*', GLOB_NOSORT | GLOB_ONLYDIR | GLOB_MARK);
foreach($extensions as $extension)
{
	$file = $extension.'include.inc.php';
	if (file_exists($file))
		require_once($file);
}

require_once(UL_INC_DIR.'/session.inc.php');
require_once(UL_INC_DIR.'/PageInit.inc.php');
?>