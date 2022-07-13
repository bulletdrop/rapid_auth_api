<?php

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

$api_key = $_POST["api_key"];
$open_ssl_key = get_openssl_key_by_api_key($api_key);
$gid = get_gid_by_api_key($api_key);
$license_key = open_ssl_decrypt_rapid_auth($_POST["license_key"], $open_ssl_key);

$username = open_ssl_decrypt_rapid_auth($_POST["username"], $open_ssl_key);
$password = open_ssl_decrypt_rapid_auth($_POST["password"], $open_ssl_key);

if (!passed_security_check())
{
    echo open_ssl_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "You are banned from using this API")), $open_ssl_key);
    exit();
}

if (!verify_api_key($api_key))
{
    echo open_ssl_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Invalid API Key")), $open_ssl_key);
    exit();
}

$key_valid = license_key_valid($license_key, $gid);

if (!$key_valid)
{
    echo open_ssl_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Invalid License Key")), $open_ssl_key);
    exit();
}
else
{
    $current_product_array = get_product_array($username, $password, $gid);
    if ($current_product_array == "0")
    {
        update_key_array($username, $password, $gid, "[$key_valid]");
    }
    else
    {
        $current_product_array = json_decode($current_product_array);

        array_push($current_product_array, intval($key_valid));
        $new_product_array =  json_encode($current_product_array);
        
        update_key_array($username, $password, $gid, $new_product_array);
        update_keys_table($key_valid, $gid, get_uuid_by_username_and_gid($username, $gid));

        echo open_ssl_encrypt_rapid_auth(json_encode(array("stauts" => "success", "message" => "License Key Successfully Added")), $open_ssl_key);
    }
}

function get_product_array($username, $password, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT key_array FROM loader_users WHERE username = ? AND `password` = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), encrypt_data($password, $key), $gid));   
    while($row = $statement->fetch()) {
        return $row["key_array"];
    }

    return "-1";
}

function update_key_array($username, $password, $gid, $new_array)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("UPDATE loader_users SET key_array = ? WHERE group_gid = ? AND username = ? AND password = ?;");
    $statement->execute(array("$new_array", $gid, encrypt_data($username, $key), encrypt_data($password, $key)));
}

function update_keys_table($kid, $gid, $uuid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("UPDATE loader_keys SET loader_user_uid = ? WHERE owner_gid = ? AND kid = ?;");
    $statement->execute(array($uuid, $gid, $kid));
}

//Returns false if the key is invalid or the kid if the key is valid
function license_key_valid($license_key, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT kid, `lifetime`, days_left FROM loader_keys WHERE owner_gid = ? AND key_name = ? AND freezed = 0 AND product_freezed = 0 AND loader_user_uid = -1");
    $statement->execute(array($gid, encrypt_data($license_key, $key)));   
    while($row = $statement->fetch()) {
        if ($row["lifetime"] == "1" || $row["days_left"] > 0)
            return $row["kid"];
        else
            return false;
    }

    return false;
}

?>