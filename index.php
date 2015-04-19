<?php
define("CSRF_AES_SITE_KEY","GENERATE_SOME_RANDOM_LONG_STRING_ENCRYPTION_KEY"); //hard-coded AES ENCRYPTION KEY FOR CSRF SECURING

require_once 'aes.php';
require_once 'csrf.module.php';

// this token need to be added to form hidden-field
$csrf_token= csrfModule::get_csrf();

//this need to be verified as true after form submitted
var_dump(csrfModule::verify_csrf($csrf_token)); //should return true
?>
