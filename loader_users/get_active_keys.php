<?php

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

if (!passed_security_check())
{
    echo json_encode(array("status" => "error", "message" => "You are banned from using this API"));
    exit();
}

$api_key = $_POST["api_key"];
$open_ssl_key = get_openssl_key_by_api_key($api_key);
$username = open_ssl_decrypt_rapid_auth($_POST["username"], $open_ssl_key);
$password = open_ssl_decrypt_rapid_auth($_POST["password"], $open_ssl_key);
$gid = get_gid_by_api_key($api_key);

if (!verify_api_key($api_key))
{
    echo open_ssl_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Invalid API Key")), $open_ssl_key);
    exit();
}
else
{
    $active_key_information_array = array();

    $product_array = get_product_array($username, $password, $gid);

    if ($product_array == "0")
    {
        echo open_ssl_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "No active license keys found")), $open_ssl_key);
    }
    else
    {
        foreach (json_decode($product_array) as $product)
        {
            array_push($active_key_information_array, get_key_info_by_gid_and_kid($gid, $product));
        }
        echo open_ssl_encrypt_rapid_auth(json_encode(array("status" => "success", "products" =>$active_key_information_array)), $open_ssl_key);
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

function get_key_info_by_gid_and_kid($gid, $kid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT days_left, `lifetime`, key_name, product_id FROM loader_keys WHERE owner_gid = ? AND kid = ? AND freezed = 0 AND product_freezed = 0 AND days_left > 0");
    $statement->execute(array($gid, $kid));   
    while($row = $statement->fetch()) {
        return array("days_left" => $row["days_left"], "lifetime" => $row["lifetime"], "key_name" => decrypt_data($row["key_name"], $key), "product_name" => get_product_name_by_product_id($row["product_id"], $gid));
    }
    
    return "-1";
}

function get_product_name_by_product_id($product_id, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT products_array FROM dashboard_groups WHERE gid = ?");
    $statement->execute(array($gid));   
    while($row = $statement->fetch()) {
        return json_decode($row["products_array"])[$product_id];
    }
    
    return "-1";
}

?>