<?php
session_start();

//error reporting for debugging purposes
ini_set('display_error', 1);
ini_set('display_startup_error', 1);
error_reporting(E_ALL);

//CSRF token used for program tricks
if(empty($_SESSION['csrf_token'])){
    $csrf_token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $csrf_token;
}else{
    $csrf_token = $_SESSION['csrf_token'];
}
?>