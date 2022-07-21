<?php
function rn_cryptor_encrypt_rapid_auth($plaintext, $password)
{
    require __DIR__ . '/../../vendor/autoload.php';

    $cryptor = new \RNCryptor\RNCryptor\Encryptor;
    $base64Encrypted = $cryptor->encrypt($plaintext, $password);

    return $base64Encrypted;
}

function rn_cryptor_decrypt_rapid_auth($base64Encrypted, $password)
{
    require __DIR__ . '/../../vendor/autoload.php';

    $cryptor = new \RNCryptor\RNCryptor\Decryptor;
    $plaintext = $cryptor->decrypt($base64Encrypted, $password);

    return $plaintext;
}

?>