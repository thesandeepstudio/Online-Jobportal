<?php
header("Content-Type: application/json");
require 'db.php';

$data = json_decode(file_get_contents("php://input"), true);
$email = $data['email'] ?? '';
$otp = $data['otp'] ?? '';
$new_pass = $data['new_password'] ?? '';

if (empty($email) || empty($otp) || empty($new_pass)) {
    echo json_encode(["status" => false, "message" => "Missing fields"]);
    exit;
}

try {
    // 1. Check OTP and Expiry
    $stmt = $pdo->prepare("SELECT id, reset_expiry FROM users WHERE email = ? AND reset_code = ?");
    $stmt->execute([$email, $otp]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Check Expiry
        if (strtotime($user['reset_expiry']) < time()) {
            echo json_encode(["status" => false, "message" => "OTP has expired"]);
            exit;
        }

        // 2. Update Password & Clear OTP
        $hashed = password_hash($new_pass, PASSWORD_BCRYPT);
        $update = $pdo->prepare("UPDATE users SET password = ?, reset_code = NULL, reset_expiry = NULL WHERE id = ?");
        $update->execute([$hashed, $user['id']]);

        echo json_encode(["status" => true, "message" => "Password changed successfully!"]);
    } else {
        echo json_encode(["status" => false, "message" => "Invalid OTP"]);
    }

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "Error: " . $e->getMessage()]);
}
?>