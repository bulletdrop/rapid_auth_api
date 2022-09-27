<?php

function get_fail_count_by_ip($ip)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT fail_count FROM fail2ban WHERE ip_address=?");
    $statement->execute(array($ip));   
    while($row = $statement->fetch()) {
        return $row["fail_count"];
    }
    
    return 0;
}

function get_last_fail_date($ip)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT last_fail_date FROM fail2ban WHERE ip_address=?");
    $statement->execute(array($ip));   
    while($row = $statement->fetch()) {
        return $row["last_fail_date"];
    }
    
    return 0;
}

function add_fail($ip)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    if (!ip_exists_in_db($ip))
    {
        $statement = $pdo->prepare("INSERT INTO fail2ban (`ip_address`, `last_fail_date`) VALUES (?, CURDATE());");
        $statement->execute(array($ip));
    }
    else
    {
        $statement = $pdo->prepare("UPDATE fail2ban SET `fail_count` = fail_count + 1, last_fail_date = CURDATE() WHERE ip_address=?;");
        $statement->execute(array($ip));
    }
}

function last_fail_today($ip)
{
    $last_fail_date = get_last_fail_date($ip);
    $today = date("Y-m-d");
    if ($last_fail_date == $today)
    {
        return true;
    }
    else
    {
        return false;
    }
}

function reset_fail_count($ip)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("UPDATE fail2ban SET `fail_count` = 0 WHERE ip_address=?;");
    $statement->execute(array($ip));
}

function ip_is_banned($ip)
{
    if (ip_exists_in_db($ip))
    {
        $fail_count = get_fail_count_by_ip($ip);
        if ($fail_count >= 3)
        {
            if (last_fail_today($ip))
            {
                return true;
            }
            else
            {
                reset_fail_count($ip);
                return false;
            }
            return true;
        }
        else
        {
            return false;
        }
    }
}

function ip_exists_in_db($ip)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT * FROM fail2ban WHERE ip_address=?;");
    $statement->execute(array($ip));
    if ($statement->fetchColumn() == 0)
        return false;
    
    return true;
}

?>