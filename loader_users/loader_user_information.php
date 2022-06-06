<?php

function get_uuid_by_username_and_gid($username, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT uuid FROM loader_users WHERE username = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), $gid));
    while($row = $statement->fetch()) {
        return $row["uuid"];
    }
}

?>