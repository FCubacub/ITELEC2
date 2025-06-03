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
    <title>Verify OTP</title>
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
        .otp-icon {
            text-align: center;
            margin-bottom: 1rem;
        }
        .otp-icon svg {
            color: #212529;
        }
        .otp-input {
            text-align: center;
            font-size: 1.2rem;
            letter-spacing: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 col-lg-4">
                <div class="auth-card p-4">
                    <div class="otp-icon">
                        <svg width="48" height="48" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2zM5 8h6a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/>
                        </svg>
                    </div>
                    
                    <h2 class="text-center mb-3">Verify OTP</h2>
                    <p class="text-muted text-center mb-4">Enter the verification code sent to your device</p>
                    
                    <form action="dashboard/admin/authentication/admin-class.php" method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        
                        <div class="mb-3">
                            <label for="otp" class="form-label">Verification Code</label>
                            <input type="number" class="form-control otp-input" id="otp" name="otp" placeholder="000000" required maxlength="6">
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" name="btn-verify" class="btn btn-dark">Verify Code</button>
                        </div>
                    </form>
                    
                    <div class="auth-footer text-center">
                        <p class="mb-0 text-muted">Didn't receive the code? 
                            <a href="#" class="text-decoration-none">Resend</a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Auto-focus on OTP input
        document.getElementById('otp').focus();
        
        // Limit input to 6 digits
        document.getElementById('otp').addEventListener('input', function(e) {
            if (e.target.value.length > 6) {
                e.target.value = e.target.value.slice(0, 6);
            }
        });
    </script>
</body>
</html>
