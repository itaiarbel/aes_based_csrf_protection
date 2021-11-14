<?php

use WSCsrf\WSCsrf;

define("CSRF_AES_SITE_KEY", "GENERATE_SOME_RANDOM_LONG_STRING_ENCRYPTION_KEY"); //hard-coded AES ENCRYPTION KEY FOR CSRF SECURING

require_once __DIR__ . '/vendor/autoload.php';

/**
 * function generateToken
 *
 * @return string $token
 */
function generateToken()
{
    // this token need to be added to form hidden-field
    return WSCsrf::getCsrf();
}

/**
 * function verifyToken
 *
 * @param string $token_to_verify
 */
function verifyToken(string $token_to_verify)
{
    //this need to be verified as true after form submitted
    return WSCsrf::verifyCsrf($token_to_verify);
}

$token = generateToken();

die(var_dump([
    'token'             => $token,
    'token_is_valid'    => verifyToken($token),
]));
