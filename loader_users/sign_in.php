<?php

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

if (!passed_security_check())
{
    echo json_encode(array("status" => "error", "message" => "You are banned from using this API"));
    exit();
}

$api_key = $_POST["api_key"];
$username = $_POST["username"];
$password = $_POST["password"];
$gid = get_gid_by_api_key($api_key);

$hwid = array(
    "windows_username" => $_POST["windows_username"],
    "gpu_name" => $_POST["gpu_name"],
    "gpu_ram" => $_POST["gpu_ram"],
    "drive_count" => $_POST["drive_count"],
    "cpu_name" => $_POST["cpu_name"],
    "cpu_cores" => $_POST["cpu_cores"],
    "os_caption" => $_POST["os_caption"],
    "os_serial_number" => $_POST["os_serial_number"]
);

foreach ($hwid as $item)
{
    if (strlen($item) < 1)
    {
        echo json_encode(array("status" => "error", "message" => "Missing hardware information"));
        exit();
    }
}

switch (false)
{
    case verify_api_key($api_key):
        echo json_encode(array("status" => "error", "message" => "Invalid API key"));
        break;
    case check_creds($username, $password, $gid):
        echo json_encode(array("status" => "error", "message" => "Invalid username or password"));
        break;
    case hwid_exist($username, $password, $gid):
        insert_hwid($username, $password, $gid, $hwid);
        update_last_ip_address($username, $password, $gid);
        echo json_encode(array("status" => "success", "message" => "Successfully signed in"));
        break;
    case verify_hwid($username, $password, $gid, $hwid):
        update_hwid_attempt($username, $password, $gid, $hwid);
        update_last_ip_address($username, $password, $gid);
        echo json_encode(array("status" => "error", "message" => "Invalid hardware ID"));
        break;        
    default:
        if (check_creds($username, $password, $gid))
        {
            update_last_ip_address($username, $password, $gid);
            echo json_encode(array("status" => "success", "message" => "Successfully signed in"));
        }
        else
        {
            echo json_encode(array("status" => "error", "message" => "Unknow error"));  
        }
        break;  
}

function check_creds($username, $password, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT uuid FROM loader_users WHERE username = ? AND password = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), encrypt_data($password, $key), $gid)); 
    
    if ($statement->rowCount() == 0)
        return false;

    return true;
}

function hwid_exist($username, $password, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT active_hwid FROM loader_users WHERE username = ? AND `password` = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), encrypt_data($password, $key), $gid));   
    while($row = $statement->fetch()) {
        if ($row["active_hwid"] == "0")
            return false;
    }
    
    return true;
}

function verify_hwid($username, $password, $gid, $hwid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT windows_username, gpu_name, gpu_ram, drive_count, cpu_name, cpu_cores, os_caption, os_serial_number FROM loader_users WHERE username = ? AND `password` = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), encrypt_data($password, $key), $gid));   
    while($row = $statement->fetch()) 
    {
        switch (false)
        {
            case $row["windows_username"] == encrypt_data($hwid["windows_username"], $key):
                return false;
            case $row["gpu_name"] == encrypt_data($hwid["gpu_name"], $key):
                return false;
            case $row["gpu_ram"] == $hwid["gpu_ram"]:
                return false;
            case $row["drive_count"] == $hwid["drive_count"]:
                return false;
            case $row["cpu_name"] == encrypt_data($hwid["cpu_name"], $key):
                return false;
            case $row["cpu_cores"] == $hwid["cpu_cores"]:
                return false;
            case $row["os_caption"] == encrypt_data($hwid["os_caption"], $key):
                return false;
            case $row["os_serial_number"] == encrypt_data($hwid["os_serial_number"], $key):
                return false;
        }

        return true;
    }
    
    return false;
}

function insert_hwid($username, $password, $gid, $hwid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("UPDATE loader_users SET windows_username = ?, gpu_name = ?, gpu_ram = ?, drive_count = ?, cpu_name = ?, cpu_cores = ?, os_caption = ?, os_serial_number = ?, active_hwid = 1;");
    $statement->execute(array(
        encrypt_data($hwid["windows_username"], $key),
        encrypt_data($hwid["gpu_name"], $key),
        $hwid["gpu_ram"],
        $hwid["drive_count"],
        encrypt_data($hwid["cpu_name"], $key),
        $hwid["cpu_cores"],
        encrypt_data($hwid["os_caption"], $key),
        encrypt_data($hwid["os_serial_number"], $key)
    ));
}

function update_hwid_attempt($username, $password, $gid, $hwid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("UPDATE loader_users SET windows_username_attempt = ?, gpu_name_attempt = ?, gpu_ram_attempt = ?, drive_count_attempt = ?, cpu_name_attempt = ?, cpu_cores_attempt = ?, os_caption_attempt = ?, os_serial_number_attempt = ?, failed_hwid_attempt = 1;");
    $statement->execute(array(
        encrypt_data($hwid["windows_username"], $key),
        encrypt_data($hwid["gpu_name"], $key),
        $hwid["gpu_ram"],
        $hwid["drive_count"],
        encrypt_data($hwid["cpu_name"], $key),
        $hwid["cpu_cores"],
        encrypt_data($hwid["os_caption"], $key),
        encrypt_data($hwid["os_serial_number"], $key)
    ));
}

function update_last_ip_address($username, $passwaord, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("UPDATE loader_users SET last_ip = ? WHERE group_gid = ? AND username = ? AND password = ?;");
    $statement->execute(array($_SERVER["HTTP_CF_CONNECTING_IP"], $gid, encrypt_data($username, $key), encrypt_data($passwaord, $key)));
}

?>