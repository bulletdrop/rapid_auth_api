<?php

function open_ssl_encrypt_rapid_auth($plaintext, $password)
{
    $method = 'aes-256-cbc';
    $password = substr(hash('sha256', $password, true), 0, 32);
    
    // IV must be exact 16 chars (128 bit)
    $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
    
    // av3DYGLkwBsErphcyYp+imUW4QKs19hUnFyyYcXwURU=
    $encrypted = base64_encode(openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA, $iv));
    return $encrypted;
}

function open_ssl_decrypt_rapid_auth($encrypted_text, $password)
{
    $method = 'aes-256-cbc';
    $password = substr(hash('sha256', $password, true), 0, 32);
    $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
    $decrypted = openssl_decrypt(base64_decode($encrypted_text), $method, $password, OPENSSL_RAW_DATA, $iv);
    return $decrypted;
}

?>