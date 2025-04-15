<?php

class Database 
{
    private $host;
    private $port;
    private $db_name;
    private $username;
    private $password;
    public $conn;
    //declaring variable outside the constructor

    public function __construct() //to construct server connection
    {
        //we will do server name, host, username, password that will be connected to database
        //we have local host or web host server connection here
        
        if($_SERVER['SERVER_NAME'] === 'localhost' || $_SERVER['SERVER_ADDR'] === '127.0.0.1' || $_SERVER['SERVER_NAME'] === '192.168.1.72'){
            $this->host = "localhost";
            $this->port = "3307";
            $this->db_name = "itelec2";
            $this->username = "root";
            $this->password = ""; 
        }
        else{ 
            $this->host = "localhost"; 
            $this->db_name = ""; 
            $this->username = "";
            $this->password = "";

        }
    }
    //function to connect to database
    public function dbConnection()
    {
        $this->conn = null;
        try{
            $this->conn = new PDO("mysql:host=" . $this->host . ";port=". $this->port . ";dbname=" . $this->db_name, $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        }catch (PDOException $exception)
        {
            //catch any PDO exceptions
            echo "Connection error:" . $exception->getMessage();

        }
        return $this->conn;
    }
}
?>