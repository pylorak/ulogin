<?php

if (php_sapi_name() != 'cli')	// skip if we are running from the cli
{
	if (UL_PREVENT_CLICKJACK)
	{
		header('X-Frame-Options: SAMEORIGIN');
	}

	if (UL_HTTPS || (UL_HSTS > 0))
	{
		if(!ulUtils::IsHTTPS())
		{
			header('HTTP/1.1 301 Moved Permanently');
			header('Location: ' . ulUtils::CurrentURL(true, 'https'));
			exit(0);
		}
		else if (UL_HSTS > 0)
		{
			header('Strict-Transport-Security: max-age='.(string)UL_HSTS);
		}
	}
}
?>