<?php
//error_reporting(0);

include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';

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

foreach ($hwid as $item)
{
    if (strlen($item) < 1)
    {
        echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Missing hardware information")), $open_ssl_key);
        exit();
    }
}

switch (false)
{
    case !ip_is_banned($_SERVER["HTTP_CF_CONNECTING_IP"]):
        echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "You are banned from using this API")), $open_ssl_key);
        exit();
        break;
    case verify_api_key($api_key):
        add_fail($_SERVER["HTTP_CF_CONNECTING_IP"]);
        echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Invalid API key")), $open_ssl_key);
        break;
    case check_creds($username, $password, $gid):
        add_fail($_SERVER["HTTP_CF_CONNECTING_IP"]);
        echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Invalid username or password")), $open_ssl_key);
        break;
    case hwid_exist($username, $password, $gid):
        insert_hwid($username, $password, $gid, $hwid);
        update_last_ip_address($username, $password, $gid);
        echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "success", "message" => "Successfully signed in")), $open_ssl_key);
        break;
    case verify_hwid($username, $password, $gid, $hwid):
        add_fail($_SERVER["HTTP_CF_CONNECTING_IP"]);
        update_hwid_attempt($username, $password, $gid, $hwid);
        update_last_ip_address($username, $password, $gid);
        echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Invalid hardware ID")), $open_ssl_key);
        break;        
    default:
        if (check_creds($username, $password, $gid))
        {
            update_last_ip_address($username, $password, $gid);
            echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "success", "message" => "Successfully signed in")), $open_ssl_key);
        }
        else
        {
            add_fail($_SERVER["HTTP_CF_CONNECTING_IP"]);
            echo rn_cryptor_encrypt_rapid_auth(json_encode(array("status" => "error", "message" => "Unknow error")), $open_ssl_key);  
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