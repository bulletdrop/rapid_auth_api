<?php

function verify_api_key($api_key)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT gid FROM dashboard_groups WHERE api_key =?");
    $statement->execute(array($api_key)); 
    
    if ($statement->rowCount() == 0)
        return false;

    return true;
}

function get_gid_by_api_key($api_key)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT gid FROM dashboard_groups WHERE api_key= ?");
    $statement->execute(array($api_key));   
    while($row = $statement->fetch()) {
        return $row["gid"];
    }
    
    return "-1";
}

?>