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
                echo "<script>alert('We sent the OTP to $email.'); window.location.href='../../../verify-otp.php';</script>";
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

    public function forgotPassword($csrf_token, $email, $token)
    {
        $email = filter_var($email, FILTER_VALIDATE_EMAIL);

        if(empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)){
            echo "<script>alert('Please enter valid email address!'); window.location.href='../../../forgot-password.php';</script>";
            exit;
        }

        if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../forgot-password.php';</script>";
            exit;
        }

        unset($_SESSION['csrf_token']);

        $stmt = $this->runQuery("SELECT * FROM user WHERE email =:email");
        $stmt->execute(array(":email" => $email));

        if($stmt->rowCount() > 0){
            // Delete any existing reset tokens for this user
            $delete_stmt = $this->runQuery("DELETE FROM password_resets WHERE email = :email");
            $delete_stmt->bindParam(":email", $email);
            $delete_stmt->execute();
            
            // Insert new reset token
            $insert_stmt = $this->runQuery("INSERT INTO password_resets (email, token, created_at, expires_at) 
                            VALUES (:email, :token, now(), now() +interval 10 minute)");
            $insert_stmt->bindParam(":email", $email);
            $insert_stmt->bindParam(":token", $token);
            
            if($insert_stmt->execute()){
                // Create reset link
                $reset_link = "http://" . $_SERVER['HTTP_HOST'] . 
                                "/ITELEC2/reset-password.php?token=" . $token;
                
                $subject = "Password Reset Request";
                $message = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>Reset Password</title>
                    <style>
                        body { 
                            font-family: system-ui, -apple-system, sans-serif; 
                            background-color: #f7f8fc; 
                            margin: 0; 
                            padding: 50px 20px; 
                            color: #2d3748;
                        }
                        .container { 
                            max-width: 480px; 
                            margin: 0 auto; 
                            background: white; 
                            border-radius: 8px; 
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                        }
                        .header { 
                            padding: 40px 40px 20px 40px; 
                            text-align: center; 
                            border-bottom: 1px solid #e2e8f0;
                        }
                        .title { 
                            margin: 0; 
                            font-size: 24px; 
                            font-weight: 600; 
                            color: #1a202c;
                        }
                        .body { 
                            padding: 30px 40px;
                        }
                        .greeting { 
                            font-size: 16px; 
                            margin-bottom: 20px; 
                            color: #4a5568;
                        }
                        .message { 
                            font-size: 16px; 
                            line-height: 1.6; 
                            margin-bottom: 30px; 
                            color: #4a5568;
                        }
                        .button-container { 
                            text-align: center; 
                            margin: 30px 0;
                        }
                        .button { 
                            display: inline-block; 
                            padding: 12px 24px; 
                            background: #4299e1; 
                            color: white; 
                            text-decoration: none; 
                            border-radius: 6px; 
                            font-weight: 500;
                        }
                        .notice { 
                            background: #fed7d7; 
                            border-left: 4px solid #f56565; 
                            padding: 16px; 
                            margin: 25px 0; 
                            border-radius: 0 4px 4px 0;
                        }
                        .notice-title { 
                            font-weight: 600; 
                            color: #c53030; 
                            margin-bottom: 8px;
                        }
                        .notice-text { 
                            color: #742a2a; 
                            font-size: 14px;
                        }
                        .footer { 
                            padding: 20px 40px 40px 40px; 
                            text-align: center; 
                            color: #718096; 
                            font-size: 14px;
                        }
                        .link { 
                            color: #4299e1; 
                            word-break: break-all; 
                            font-size: 13px;
                        }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <div class='header'>
                            <h1 class='title'>Password Reset</h1>
                        </div>
                        <div class='body'>
                            <p class='greeting'>Hello!</p>
                            <p class='message'>
                                We received a request to reset your password for your Fhrenzie System account. 
                                Click the button below to create a new password.
                            </p>
                            <div class='button-container'>
                                <a href='$reset_link' class='button'>Reset Password</a>
                            </div>
                            <div class='notice'>
                                <div class='notice-title'>Important Security Notice</div>
                                <div class='notice-text'>
                                    This link will expire in 10 minutes. If you didn't request this password reset, 
                                    please ignore this email and your password will remain unchanged.
                                </div>
                            </div>
                            <p class='message'>
                                If the button doesn't work, copy and paste this link into your browser:
                            </p>
                            <p class='link'>$reset_link</p>
                        </div>
                        <div class='footer'>
                            <p>Best regards,<br><strong>Fhrenzie System Team</strong></p>
                            <p style='margin-top: 20px; font-size: 12px;'>
                                This email was sent automatically. Please do not reply.
                            </p>
                        </div>
                    </div>
                </body>
                </html>";

                $this->send_email($email, $message, $subject, $this->smtp_email, $this->smtp_password);
                echo "<script>alert('Password reset instructions have been sent to your email.'); window.location.href='../../../';</script>";
                exit;
            }else{
                echo "<script>alert('Failed to create reset token. Please try again.'); window.location.href='../../../forgot-password.php';</script>";
                exit;
            }
        }else {
            echo "<script>alert('No Account found with that email'); window.location.href='../../../forgot-password.php';</script>";
            exit;
        }
    }

    public function resetPassword($token, $csrf_token, $new_reset_password, $confirm_new_password )
    {
        if(!isset($token) || empty($token)){
            echo "<script>alert('No reset token provided.'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        if(empty($new_reset_password) || empty($confirm_new_password)){
            echo "<script>alert('Please fill in all fields!'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        if($new_reset_password !== $confirm_new_password){
            echo "<script>alert('Passwords do not match.'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        if(!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
            echo "<script>alert('Invalid CSRF Token!'); window.location.href='../../../reset-password.php?token=$token';</script>";
            exit;
        }

        unset($_SESSION['csrf_token']);

        // Set timezone
        date_default_timezone_set('Asia/Manila');

        // Get current time
        $current_time = date('Y-m-d H:i:s');

        $query = "SELECT pr.*, u.email, u.password
                    FROM password_resets pr 
                    JOIN user u ON pr.email = u.email 
                    WHERE pr.token = :token 
                    AND pr.created_at <= now()
                    AND pr.expires_at >= now()
                    LIMIT 1";
        
        $stmt = $this->runQuery($query);
        $stmt->bindParam(":token", $token);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $reset_data = $stmt->fetch(PDO::FETCH_ASSOC);

            if(md5($new_reset_password) == $reset_data['password']){
                echo "<script>alert('New password cannot be same to your old password.'); window.location.href='../../../reset-password.php?token=$token';</script>";
                exit;
            }

            $hashed_password = md5($new_reset_password);

            // Update password
            $update_stmt = $this->runQuery("UPDATE user SET password = :password WHERE email = :email");
            $update_stmt->bindParam(":password", $hashed_password);
            $update_stmt->bindParam(":email", $reset_data['email']);
            
            if($update_stmt->execute()){
                // Delete all reset tokens for this user
                $delete_stmt = $this->runQuery("DELETE FROM password_resets WHERE email = :email");
                $delete_stmt->bindParam(":email", $reset_data['email']);
                $delete_stmt->execute();

                echo "<script>alert('Password has been reset successfully. You can now login with your new password.'); window.location.href='../../../';</script>";
                exit;
            }else{
                echo "<script>alert('Failed to update password. Please try again.'); window.location.href='../../../reset-password.php?token=$token'';</script>";
                exit;
            }
        }else{
            // Check if token exists but expired
            $check_query = "SELECT expires_at FROM password_resets WHERE token = :token";
            $check_stmt = $this->runQuery($check_query);
            $check_stmt->bindParam(":token", $token);
            $check_stmt->execute();
            
            if ($check_stmt->rowCount() > 0) {
                $token_data = $check_stmt->fetch(PDO::FETCH_ASSOC);
                if ($token_data['expires_at'] < $current_time) {
                    echo "<script>alert('Reset token has expired. Please request a new password reset.'); window.location.href='../../../forgot-password.php';</script>";
                    exit;
                } else {
                    echo "<script>alert('Invalid reset token. Please request a new password reset.'); window.location.href='../../../forgot-password.php';</script>";
                    exit;
                }
            } else {
                echo "<script>alert('Invalid reset token. Please request a new password reset.'); window.location.href='../../../forgot-password.php';</script>";
                exit;
            }
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

if(isset($_POST['btn-forgot-password'])){
    $csrf_token = trim($_POST['csrf_token']);
    $email = trim($_POST['email']);

    $token = md5(uniqid(rand()));

    $forgotPassword = new ADMIN();
    $forgotPassword->forgotPassword($csrf_token, $email, $token);
}

if(isset($_POST['btn-reset-password'])){
    $csrf_token = trim($_POST['csrf_token']);
    $token = trim($_POST['token']);
    $new_reset_password = trim($_POST['password']);
    $confirm_new_password = trim($_POST['confirm_password']);

    $resetPassword = new ADMIN();
    $resetPassword->resetPassword($token, $csrf_token, $new_reset_password, $confirm_new_password);
}

//If logout is triggered, call adminSignout
if(isset($_GET['admin_signout'])){

    $adminSignout = new ADMIN();
    $adminSignout->adminSignout();
}
?>