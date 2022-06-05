<?php

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/backend/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/backend/config.php';

$api_key = $_POST["api_key"];

if (verify_api_key($api_key))
{

}

function check_creds($username, $password)#
{
    
}

function check_hwid_exist()
{

}

function verify_hwid()
{

}




?>