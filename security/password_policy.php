<?php

function check_password($password)
{
    include_once $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/includes.php';
    include $_SERVER['DOCUMENT_ROOT'].'/rapid_auth_api/config.php';
    //Checks if the password is long enough
    if (strlen($password) < $password_length)
        return false;
    
    //Checks if the password contains any not allowed char
    $allowed_chars_count = 0;
    foreach (str_split($password) as $char)
    {
        foreach (str_split($allowed_chars_password) as $s_chars)
        {
            if ($char == $s_chars)
                $allowed_chars_count++;
        }
    }

    if ($allowed_chars_count != strlen($password))
        return false;

        
    
    if ($needs_lower_char)
    {
        $has_lower_char = false;

        foreach (str_split($password) as $char)
        {
            foreach (str_split($lower_case_chars) as $s_chars)
            {
                if ($char == $s_chars)
                    $has_lower_char = true;
            }
        }

        if (!$has_lower_char)
            return false;
    }
    
    //Checks if the password contains a captial char (if enabled in config.php)
    if ($needs_capital_char)
    {
        $has_captial_char = false;

        foreach (str_split($password) as $char)
        {
            foreach (str_split($captial_chars) as $s_chars)
            {
                if ($char == $s_chars)
                $has_captial_char = true;
            }
        }

        if (!$has_captial_char)
            return false;
    }
    
    //Checks if the password contains a special char (if enabled in config.php)
    if ($needs_special_char)
    {
        $has_special_char = false;

        foreach (str_split($password) as $char)
        {
            foreach (str_split($special_chars) as $s_chars)
            {
                if ($char == $s_chars)
                    $has_special_char = true;
            }
        }

        if (!$has_special_char)
            return false;
    }

    //Checks if the password contains a number (if enabled in config.php)
    if ($needs_number)
    {
        $has_number = false;

        foreach (str_split($password) as $char)
        {
            foreach (str_split($number_chars) as $s_chars)
            {
                if ($char == $s_chars)
                    $has_number = true;
            }
        }

        if (!$has_number)
            return false;
    }

    return true;   
}

?>