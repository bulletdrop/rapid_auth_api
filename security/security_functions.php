<?php

function passed_security_check()
{
    if (ip_is_banned())
        return false;
}

function ip_is_banned()
{
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';
    $statement = $pdo->prepare("SELECT * FROM banned_ips WHERE ip_address = ?");
    $statement->execute(array($_SERVER["REMOTE_ADDR"]));
    while($row = $statement->fetch()) {
        return true;
    }
    return false;
}

?>