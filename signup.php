<?php
include_once 'config/setting-configuration.php';

// Check if user is already logged in
if (isset($_SESSION['adminSession'])) {
    header("Location: dashboard/admin/index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            min-height: 100vh;
            display: flex;
            align-items: center;
            padding: 2rem 0;
        }
        .auth-card {
            background: white;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .form-control {
            border-radius: 2px;
        }
        .form-control:focus {
            box-shadow: none;
            border-color: #212529;
        }
        .btn-dark {
            border-radius: 2px;
        }
        .auth-footer {
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid #eee;
        }
        .form-label {
            font-weight: 500;
        }
        .form-text {
            font-size: 0.75rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 col-lg-4">
                <div class="auth-card p-4">
                    <h2 class="text-center mb-4">Create Account</h2>

                    <form method="post" action="dashboard/admin/authentication/admin-class.php">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" placeholder="Enter Username" required value="<?php echo isset($name) ? htmlspecialchars($name) : ''; ?>">
                        </div>
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" placeholder="Enter Email" required value="<?php echo isset($email) ? htmlspecialchars($email) : ''; ?>">
                        </div>
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" placeholder="Enter Password" required>
                        </div>
                        
                        <!-- <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm Password</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" placeholder="Enter Confirm Password   " required>
                        </div> -->
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-dark" name="btn_signup">Create Account</button>
                        </div>
                    </form>
                    
                    <div class="auth-footer text-center">
                        <p class="mb-0 text-muted">Already have an account? 
                            <a href="index.php" class="text-decoration-none">Login</a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
