<?php

function ulogin_ldap_autoload($classname)
{
	static $map = NULL;
	if ($map == NULL)
	{
		$map = array();
		$map['ulLdapDb'] = UL_INC_DIR.'/ldap/LdapDb.inc.php';
		$map['ulLdapLoginBackend'] = UL_INC_DIR.'/ldap/LdapLoginBackend.inc.php';
	}

	if (isset($map[$classname]))
	{
		require_once($map[$classname]);
	}
}

spl_autoload_register('ulogin_ldap_autoload');

?>