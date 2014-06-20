<?php

// This file has the sole purpose of loading all configuration files for uLogin.

function endsWith($haystack, $needle)
{
  $length = strlen($needle);
  if ($length == 0) {
    return true;
  }

  return (substr($haystack, -$length) === $needle);
}

$handle = opendir(dirname(__FILE__));
while (false !== ($file = readdir($handle))) {
  if (!is_dir($file) && endsWith($file, '.inc.php'))
    require_once($file);
}
closedir($handle);
?>
