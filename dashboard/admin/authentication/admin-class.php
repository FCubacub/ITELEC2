<?php
require_once __DIR__.'/../../../database/dbconnection.php';
include_once __DIR__.'/../../../config/setting-configuration.php';

//main class
class Admin
{
    private $conn;
    public function __construct()
    {
        $database = new Database();
        $this->conn = $database->dbConnection();
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
        $stmt = $this->runQuery('INSERT INTO user (username, email, password) VALUES(:username, :email, :password)');
        $exec = $stmt->execute(array(
            ":username" => $username,
            ":email" => $email,
            ":password" => $hash_password
        ));

        if($exec){
            echo "<script>alert('Admin added Successfully.'); window.location.href = '../../../';</script>";
            exit;
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
            $stmt = $this->conn->prepare("SELECT * FROM user WHERE email = :email");
            $stmt->execute(array(":email" => $email));
            $userRow = $stmt->fetch(PDO::FETCH_ASSOC);

            //Verify password and proceed if matched
            if ($stmt->rowCount() == 1 && $userRow['password'] == md5($password)){
                $activity = "Has successfully Signed In";
                $user_id = $userRow['id'];
                $this->logs($activity, $user_id);

                //Set session to mark user as logged in
                $_SESSION['adminSession'] = $user_id;
                echo "<script>alert('Welcome.'); window.location.href = '../';</script>";
                exit;
            }else{
                echo "<script>alert('Invalid Credentials.'); window.location.href = '../../../';</script>";
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
    $csrf_token = trim($_POST['csrf_token']);
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    //to get all the values of input user

    //create a connection 
    $addAdmin = new ADMIN();
    $addAdmin->addAdmin($csrf_token, $username, $email, $password);
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