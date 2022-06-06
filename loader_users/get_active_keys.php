<?php

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

$api_key = $_POST["api_key"];
$username = $_POST["username"];
$password = $_POST["password"];
$gid = get_gid_by_api_key($api_key);

?>