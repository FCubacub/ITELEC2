<?php
require_once 'authentication/admin-class.php';

$admin = new ADMIN();
if(!$admin->isUserLoggedIn())
{
    $admin->redirect('../../');
}

$stmt = $admin->runQuery("SELECT * FROM user WHERE id = :id");
$stmt->execute(array(":id" =>$_SESSION['adminSession']));
$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            min-height: 100vh;
        }
        .navbar {
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .card {
            border: none;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .btn {
            border-radius: 2px;
        }
        .welcome-card {
            background-color: #212529;
            color: white;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light bg-white">
        <div class="container">
            <a class="navbar-brand" href="#">Dashboard</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="#">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Profile</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Settings</a>
                    </li>
                </ul>
                <div class="navbar-nav">
                    <a href="authentication/admin-class.php?admin_signout" class="nav-link">Logout</a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <!-- Welcome Card -->
        <div class="card welcome-card mb-4">
            <div class="card-body p-4">
                <h2 class="card-title">Welcome, <?php echo htmlspecialchars($user_data['username']); ?></h2>
                <p class="card-text opacity-75">Email: <?php echo htmlspecialchars($user_data['email']); ?></p>
            </div>
        </div>

        <!-- Feature Cards -->
        <div class="row">
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">Profile</h5>
                        <p class="card-text text-muted">Update your personal information and profile settings.</p>
                        <a href="#" class="btn btn-outline-dark">Edit Profile</a>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">Security</h5>
                        <p class="card-text text-muted">Manage your password and security settings.</p>
                        <a href="#" class="btn btn-outline-dark">Security Settings</a>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">Preferences</h5>
                        <p class="card-text text-muted">Customize your application preferences.</p>
                        <a href="#" class="btn btn-outline-dark">Preferences</a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics Row -->
        <div class="row mt-2">
            <div class="col-md-3 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h3>24</h3>
                        <p class="card-text text-muted">Total Projects</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h3>12</h3>
                        <p class="card-text text-muted">Completed</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h3>8</h3>
                        <p class="card-text text-muted">In Progress</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="card">
                    <div class="card-body">
                        <h3>4</h3>
                        <p class="card-text text-muted">Pending</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
