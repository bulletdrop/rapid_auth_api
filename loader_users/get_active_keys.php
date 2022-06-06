<?php

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

$api_key = $_POST["api_key"];
$username = $_POST["username"];
$password = $_POST["password"];
$gid = get_gid_by_api_key($api_key);

if (!verify_api_key($api_key))
{
    echo json_encode(array("status" => "error", "message" => "Invalid API Key"));
    exit();
}
else
{
    $active_key_information_array = array();

    foreach (get_product_array($username, $password, $gid) as $product)
    {
        array_push($active_key_information_array, get_key_info_by_gid_and_kid($gid, $product));
    }
    echo json_encode($active_key_information_array);
    
}

function get_product_array($username, $password, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT key_array FROM loader_users WHERE username = ? AND `password` = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), encrypt_data($password, $key), $gid));   
    while($row = $statement->fetch()) {
        return json_decode($row["key_array"]);
    }

    return "-1";
}

function get_key_info_by_gid_and_kid($gid, $kid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT days_left, `lifetime`, key_name, product_id FROM loader_keys WHERE owner_gid = ? AND kid = ? AND freezed = 0 AND product_freezed = 0");
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