<?php
include_once 'config/setting-configuration.php';

if(isset($_SESSION['adminSession'])){
    header("Location: dashboard/admin/");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            height: 100vh;
            display: flex;
            align-items: center;
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
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 col-lg-4">
                <div class="auth-card p-4">
                    <h2 class="text-center mb-4">Reset Password</h2>
                    <p class="text-muted mb-4">Enter your email address and we'll send you a link to reset your password.</p>
                    
                    <form method="post" action="dashboard/admin/authentication/admin-class.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" placeholder="Enter Email" required>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" name="btn-forgot-password" class="btn btn-dark">Send Reset Link</button>
                        </div>
                    </form>
                    
                    <div class="auth-footer text-center">
                        <p class="mb-0 text-muted">Remember your password? 
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
