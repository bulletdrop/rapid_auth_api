<?php
error_reporting(0);
include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

if (!passed_security_check())
{
    echo json_encode(array("status" => "error", "message" => "You are banned from using this API"));
    exit();
}

$api_key = $_POST["api_key"];
$open_ssl_key = get_openssl_key_by_api_key($api_key);
$username = rn_cryptor_decrypt_rapid_auth($_POST["username"], $open_ssl_key);
$password = rn_cryptor_decrypt_rapid_auth($_POST["password"], $open_ssl_key);
$gid = get_gid_by_api_key($api_key);

$hwid = array(
    "windows_username" => rn_cryptor_decrypt_rapid_auth($_POST["windows_username"], $open_ssl_key),
    "gpu_name" => rn_cryptor_decrypt_rapid_auth($_POST["gpu_name"], $open_ssl_key),
    "gpu_ram" => rn_cryptor_decrypt_rapid_auth($_POST["gpu_ram"], $open_ssl_key),
    "drive_count" => rn_cryptor_decrypt_rapid_auth($_POST["drive_count"], $open_ssl_key),
    "cpu_name" => rn_cryptor_decrypt_rapid_auth($_POST["cpu_name"], $open_ssl_key),
    "cpu_cores" => rn_cryptor_decrypt_rapid_auth($_POST["cpu_cores"], $open_ssl_key),
    "os_caption" => rn_cryptor_decrypt_rapid_auth($_POST["os_caption"], $open_ssl_key),
    "os_serial_number" => rn_cryptor_decrypt_rapid_auth($_POST["os_serial_number"], $open_ssl_key)
);

if (!verify_api_key($api_key))
{
    echo json_encode(array("status" => "error", "message" => "Invalid API key"));
    exit();
}

foreach ($hwid as $item)
{
    if (strlen($item) < 1)
    {
        echo json_encode(array("status" => "error", "message" => "Missing hardware information"));
        exit();
    }
}

if (strlen($username) < 2 || strlen($password) < 2)
{
    echo json_encode(array("status" => "error", "message" => "Username / Password too short"));
    exit();
}

sign_up($username, $password, $hwid, $gid);

function sign_up($username, $password, $hwid, $gid)
{
    if (check_if_username_allready_taken($username, $gid))
    {
        echo json_encode(array("status" => "error", "message" => "Username already taken"));
        return false;
    }
    
    if (!check_password($password))
    {
        echo json_encode(array("status" => "error", "message" => "Password does not meet requirements"));
        return false;
    }

    if (insert_user_with_hwid($username, $password, $gid, $hwid))
    {
        write_log("User ".$username." signed up\nFor GID: ". $gid, true);
        echo json_encode(array("status" => "success", "message" => "Successfully signed up"));
        return true;
    }
    else
    {
        echo json_encode(array("status" => "error", "message" => "Unknown error"));
        return false;
    }
}

function insert_user_with_hwid($username, $password, $gid, $hwid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    //$statement = $pdo->prepare("UPDATE loader_users SET windows_username = ?, gpu_name = ?, gpu_ram = ?, drive_count = ?, cpu_name = ?, cpu_cores = ?, os_caption = ?, os_serial_number = ?, active_hwid = 1;");
    $statement = $pdo->prepare("INSERT INTO loader_users (username, `password`, group_gid, windows_username, gpu_name, gpu_ram, drive_count, cpu_name, cpu_cores, os_caption, os_serial_number, active_hwid, last_ip)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?);");
    $statement->execute(array(
        encrypt_data($username, $key),
        encrypt_data($password, $key),
        $gid,
        encrypt_data($hwid["windows_username"], $key),
        encrypt_data($hwid["gpu_name"], $key),
        $hwid["gpu_ram"],
        $hwid["drive_count"],
        encrypt_data($hwid["cpu_name"], $key),
        $hwid["cpu_cores"],
        encrypt_data($hwid["os_caption"], $key),
        encrypt_data($hwid["os_serial_number"], $key),
        $_SERVER["HTTP_CF_CONNECTING_IP"]
    ));

    return true;
}


function check_if_username_allready_taken($username, $gid)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

    $statement = $pdo->prepare("SELECT uuid FROM loader_users WHERE username = ? AND group_gid = ?");
    $statement->execute(array(encrypt_data($username, $key), $gid)); 
    
    if ($statement->rowCount() == 0)
        return false;

    return true;
}
?>