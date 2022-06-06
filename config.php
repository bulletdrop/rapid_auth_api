<?php

//Database
$db_host = "localhost";
$db_name = "rapid_auth";
$db_username = "rapid_auth_user";
$db_password = "test1234";

//PDO
$pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_username, $db_password);

//Encryption
$salt = "zd8bPbBxkvpCYke";
$key = "aB2ZUHr6uujeaE6hu9sLwwpwPYFMbCMuTsgzJKKBuAqtRpYnDzHUenGqqV6MrWHRC7xJ6ufx2jD7T962vD3jNYZbjV6ZCyeLyPbpdTsDmchCDsjaPVYGbggpWXCYPbqy";

//Database Input Config Allowed Chars etc.
$allowed_chars_password = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?\\\"'#+-,.;:_=)([]{}$";

$special_chars = "!?\"'#+-,.;:_=)([]{}$";
$lower_case_chars = "abcdefghijklmnopqrstuvwxyz";
$captial_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
$number_chars = "0123456789";


$allowed_chars_keys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

//Password Policy
$password_length = 8;
$needs_lower_char = true;
$needs_capital_char = true;
$needs_special_char = true;
$needs_number = true;

//Discord webhook
$webhook_url = "https://discord.com/api/webhooks/983303814943756318/8b7O-T7W9BXyPf_swEuhSimJn9okmX3ri3PlHtDDyK0FUARxkFaRXy1gxJIZvOqTOzYB";
?>