<?php
require_once __DIR__.'/../../../database/dbconnection.php';
include_once __DIR__.'/../../../config/setting-configuration.php';
require_once __DIR__ . '/../../../src/vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

//main class
class Admin
{
    private $conn;
    private $settings;
    private $smtp_email;
    private $smtp_password; 

    public function __construct()
    {
        $this->settings = new SystemConfig();
        $this->smtp_email = $this->settings->getSmtpEmail();
        $this->smtp_password = $this->settings->getSmtpPassword();

        $database = new Database();
        $this->conn = $database->dbConnection();
    }

    public function sendOtp($otp, $email){
        if ($email == NULL){
            echo "<script>alert('No email found'); window.location.href='../../../';</script>";
            exit;
        }else{
            $stmt = $this->runQuery("SELECT * FROM user WHERE email =:email");
            $stmt->execute(array(":email" => $email));
            $stmt->fetch(PDO::FETCH_ASSOC);

            if($stmt->rowCount() > 0){
                echo "<script>alert('Email already taken. Please try another one.'); window.location.href='../../../';</script>";
                exit;
            }else{
                $_SESSION['OTP'] = $otp;

                $subject = "OTP VERIFICATION";
                $message = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>OTP VERIFICATION</title>
                    <style>
                        body {
                            font-family: Arial, Helvetica, sans-serif;
                            background-color: #f5f5f5;
                            margin: 0;
                            padding: 0;
                        }

                        .container{
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 30px;
                            background-color: #ffffff;
                            border-radius: 4px;
                            box-shadow: 0 2 px 4px rgba(0, 0, 0, 0.1);
                        }

                        h1 {
                            color: #333333;
                            font-size: 24px;
                            margin-bottom: 20px;
                        }

                        p {
                            color: #666666;
                            font-size: 16px;
                            margin-bottom: 10px;
                        }

                        button {
                            display: inline-block;
                            padding: 12px 24px;
                            background-color: #0088cc;
                            color: #ffffff;
                            text-decoration: none;
                            border-radius: 4px;
                            font-size: 16px;
                            margin-top: 20px;
                        }

                        .logo {
                            display: block;
                            text-align: center;
                            margin-bottom: 30px;
                        }
                    </style>
                </head>
                <body>
                        <div class='container'>
                            <div class='logo'>
                                <img src='cid:logo' alt='logo' width='150'>
                            </div>
                            <h1>OTP VERIFICATION</h1>
                            <p>Hello, $email</p>
                            <p>Your OTP is: $otp</p>
                            <p>If you didn't request an OTP, please ignore this email.</p>
                            <p>Thank you!</p>
                        </div>
                </body>
                </html>";

                $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
                echo "<script>alert('We sent the OTP to $email'); window.location.href='../../../verify-otp.php';</script>";
            }
        }
    }

    public function verifyOTP($username, $email, $password, $tokencode, $otp, $csrf_token){
        if($otp == $_SESSION['OTP']){
            unset($_SESSION['OTP']);

            $this->addAdmin($csrf_token, $username, $email, $password);

            $subject = "VERIFICATION SUCCESS";
            $message = "
            <!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>VERIFICATION SUCCESS</title>
                <style>
                    body {
                        font-family: Arial, Helvetica, sans-serif;
                        background-color: #f5f5f5;
                        margin: 0;
                        padding: 0;
                    }

                    .container{
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 30px;
                        background-color: #ffffff;
                        border-radius: 4px;
                        box-shadow: 0 2 px 4px rgba(0, 0, 0, 0.1);
                    }

                    h1 {
                        color: #333333;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }

                    p {
                        color: #666666;
                        font-size: 16px;
                        margin-bottom: 10px;
                    }

                    button {
                        display: inline-block;
                        padding: 12px 24px;
                        background-color: #0088cc;
                        color: #ffffff;
                        text-decoration: none;
                        border-radius: 4px;
                        font-size: 16px;
                        margin-top: 20px;
                    }

                    .logo {
                        display: block;
                        text-align: center;
                        margin-bottom: 30px;
                    }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='logo'>
                        <img src='cid:logo' alt='logo' width='150'>
                    </div>
                    <h1>Welcome</h1>
                    <p>Hello, <strong>$email</strong></strong></p>
                    <p>Welcome to Fhrenzie System</p>
                    <p>If you did not sign up for an account, you can safely ignore this email.</p>
                    <p>Thank you!</p>
                </div>
            </body>
            </html>";

            $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
            echo "<script>alert('Thank You'); window.location.href='../../../';</script>";

            unset($_SESSION['verify_not_username']);
            unset($_SESSION['verify_not_email']);
            unset($_SESSION['verify_not_password']);
        }else if ($otp == NULL){
            echo "<script>alert('No OTP Found'); window.location.href='../../../verify-otp.php';</script>";
            exit;
        }else{
            echo "<script>alert('It appears that the OTP you entered is invalid'); window.location.href='../../../verify-otp.php';</script>";
            exit;
        }
    }

    //method to add new admin user
    public function addAdmin($csrf_token, $username, $email, $password)
    {
        //create a query to check if the email is already exist
        $stmt = $this->conn->prepare("SELECT * FROM user WHERE email = :email");
        $stmt->execute(array(":email" => $email));

        if ($stmt->rowCount() > 0){
            echo "<script>alert('Email already exist.'); window.location.href = '../../../';</script>";
            exit;
        }

        //Validate CSRF token to prevent CSRF attacks
        if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            echo "<script>alert('Invalid CSRF Token.'); window.location.href = '../../../';</script>";
            exit;
        }

        //Unset CSRF token after verification to prevent reuse
        unset($_SESSION['csrf_token']);

        $hash_password = md5($password);

        //Insert new admin user into the 'user' table
        $stmt = $this->runQuery("INSERT INTO user (username, email, password, status) VALUES (:username, :email, :password, :status)");
        $exec = $stmt->execute(array(
            ":username" => $username,
            ":email" => $email,
            ":password" => $hash_password,
            ":status" => "active"
        ));

        if($exec){
            echo "<script>alert('Admin added Successfully.'); window.location.href = '../../../';</script>";
        }else{
            echo "<script>alert('Error adding admin.'); window.location.href = '../../../';</script>";
            exit;

        }
    }

        //method to handle admin Sign in
    public function adminSignin($email, $password, $csrf_token){
        try{
            if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
                echo "<script>alert('Invalid CSRF Token.'); window.location.href = '../../../';</script>";
                exit;
            }
            unset($_SESSION['csrf_token']);

            //fetch user by email
            $stmt = $this->runQuery("SELECT * FROM user WHERE email = :email AND status = :status");
            $stmt->execute(array(":email" => $email, ":status" => "active"));
            $userRow = $stmt->fetch(PDO::FETCH_ASSOC);

            if($stmt->rowCount() == 1){
                if($userRow['status'] == 'active'){
                    if($userRow['password'] == md5($password)){
                        $activity = "Has Successfully signed in";
                        $user_id = $userRow['id'];
                        $this->logs($activity, $user_id);

                        $_SESSION['adminSession'] = $user_id;

                        echo "<script>alert('Welcome!'); window.location.href='../';</script>";
                        exit;
                    }else{
                        echo "<script>alert('Password is incorrect'); window.location.href='../../../';</script>";
                        exit;
                    }
                }else{
                    echo "<script>alert('Entered email is not verify'); window.location.href='../../../';</script>";
                    exit;
                }
            }else{
                echo "<script>alert('No account found'); window.location.href='../../../';</script>";
                exit;
            }

            //Catch and display any database errors
        }catch (PDOException $ex){
            echo $ex->getMessage();
        }
    }

    //Method to handle admin sign-out
    public function adminSignout()
    {
        unset($_SESSION['adminSession']);
        echo "<script>alert('Sign Out Successfully.'); window.location.href = '../../../';</script>";
        exit;
    }

    function send_email($email, $message, $subject, $smtp_email, $smtp_password){
        $mail = new PHPMailer();
        $mail->isSMTP();
        $mail->SMTPDebug = 0;
        $mail->SMTPAuth = true;
        $mail->SMTPSecure = "tls";
        $mail->Host = "smtp.gmail.com";
        $mail->Port = 587;
        $mail->addAddress($email);
        $mail->Username = $smtp_email;
        $mail->Password = $smtp_password;
        $mail->setFrom($smtp_email, "Fhrenzie");
        $mail->Subject = $subject;
        $mail->msgHTML($message);
        $mail->Send();
    }

    //Method to log admin activity into the 'logs' table
    public function logs($activity, $user_id)
    {
        $stmt = $this->conn->prepare("INSERT INTO logs (user_id, activity) VALUES (:user_id, :activity)");
        $stmt->execute(array(":user_id" => $user_id, ":activity" => $activity));

    }

    //Method to check if admin user is logged in
    public function isUserLoggedIn()
    {
        if(isset($_SESSION['adminSession'])){
            return true;
        }
    }

    //Redirect method used when login is required
    public function redirect()
    {
        echo "<script>alert('Admin must log in first.'); window.location.href = '../../';</script>";
        exit;
    }

    //to prepare a SQL statement
    public function runQuery($sql)
    {
        $stmt = $this->conn->prepare($sql);
        return $stmt;
    }
}
    //If sign-up form is submitted, extract input and call addAdmin
if (isset($_POST['btn_signup'])){
    $_SESSION["not_verify_username"] = trim($_POST['username']);
    $_SESSION["not_verify_email"] = trim($_POST['email']);
    $_SESSION["not_verify_password"] = trim($_POST['password']);  
    
    $email = trim($_POST['email']);
    $otp = rand(100000, 999999);

    $addAdmin = new ADMIN();
    $addAdmin->sendOtp($otp, $email);
}

if (isset($_POST['btn-verify'])){
    $csrf_token = trim($_POST['csrf_token']);
    $username = $_SESSION["not_verify_username"];
    $email = $_SESSION["not_verify_email"];
    $password = $_SESSION["not_verify_password"];

    $tokencode = md5(uniqid(rand()));
    $otp = trim($_POST['otp']);

    $adminVerify = new ADMIN();
    $adminVerify->verifyOTP($username, $email, $password, $tokencode, $otp, $csrf_token);
}

    //If sign-in form is submitted, extract input and call adminSignin
if (isset($_POST['btn_signin'])){
    $csrf_token = trim($_POST['csrf_token']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    $adminSignin = new ADMIN();
    $adminSignin->adminSignin($email, $password, $csrf_token);
}
//If logout is triggered, call adminSignout
if(isset($_GET['admin_signout'])){

    $adminSignout = new ADMIN();
    $adminSignout->adminSignout();
}
?>