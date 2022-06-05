<?php

function encrypt_data($string, $key){
    $ciphering = "AES-128-CTR";
  
    // Use OpenSSl Encryption method
    $iv_length = openssl_cipher_iv_length($ciphering);
    $options = 0;
    
    // Non-NULL Initialization Vector for encryption
    $encryption_iv = '1234567891011121';
    
    
    // Use openssl_encrypt() function to encrypt the data
    $encryption = openssl_encrypt($string, $ciphering,
        $key, $options, $encryption_iv);
        
    return $encryption;
}

function decrypt_data($string, $key){
    $ciphering = "AES-128-CTR";
  
    // Use OpenSSl Encryption method
    $iv_length = openssl_cipher_iv_length($ciphering);
    $options = 0;

    // Non-NULL Initialization Vector for decryption
    $decryption_iv = '1234567891011121';
    
    
    // Use openssl_decrypt() function to decrypt the data
    $decryption=openssl_decrypt ($string, $ciphering, 
        $key, $options, $decryption_iv);
    
    return $decryption;
}


?>