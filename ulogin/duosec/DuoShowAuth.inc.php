<?php

// ********************************
//	DO NOT MODIFY
// ********************************

$returnUrl = ulUtils::CurrentURL();
$sig_request = Duo::signRequest(UL_DUOSEC_IKEY, UL_DUOSEC_SKEY, UL_DUOSEC_AKEY, $uid);

// ********************************
//	MAKE MODIFICATION BELOW WHERE NOTED
//  If possible, only insert but do not modify
// ********************************

// ********************************
//	Your HTML here
//  doctype, head, title etc.
// ********************************

?>
<script src="<?php echo(UL_DUOSEC_JQUERY_URI);?>"></script>
<script src="<?php echo(UL_DUOSEC_JS_URL);?>"></script>
<script>
Duo.init({
	'host':'<?php echo(UL_DUOSEC_HOST); ?>',
	'post_action':'<?php echo($returnUrl);?>',
	'sig_request':'<?php echo($sig_request); ?>'
});
</script>

<?php
// ********************************
//	Your HTML here
//  header, body, text, etc.
// ********************************
?>

<iframe id="duo_iframe" width="500" height="800" frameborder="0" allowtransparency="true" style="background: transparent;"></iframe>
<form method="POST" id="duo_form">
	<input type="hidden" name="ulDuoSecLoginNonce" value="<?php echo ulNonce::Create('ulDuoSecLogin'); ?>" />
</form>

<?php

// ********************************
//	Your HTML here
//  body, text, footer etc.
// ********************************
