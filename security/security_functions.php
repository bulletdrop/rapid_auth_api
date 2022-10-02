<?php

function passed_security_check()
{
    if (ip_is_banned($_SERVER["HTTP_CF_CONNECTING_IP"]))
        return false;

    return true;
}

function replace_bad_chars($string)
{
    error_reporting(0);
    $allowed_chars_keys_s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_\\";

    for ($i = 0; $i <= strlen($string); $i++) {
        if (!in_array($string[$i], str_split($allowed_chars_keys_s))) {
            $string[$i] = "";
        }
    }

    return $string;
}

function get_openssl_key_by_api_key($api_key)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php'; 

    $statement = $pdo->prepare("SELECT openssl_crypting_key FROM dashboard_groups WHERE api_key = ?");
    $statement->execute(array($api_key));   
    while($row = $statement->fetch()) {
        return $row["openssl_crypting_key"];
    }

    return "-1";
}

?>