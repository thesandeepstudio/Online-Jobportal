<?php
session_start();
header("Content-Type: application/json");
require 'db.php';

$data = json_decode(file_get_contents("php://input"), true);
$email = $data['email'] ?? '';

if (empty($email)) {
    echo json_encode(["status" => false, "message" => "Email required"]);
    exit;
}

try {
    // 1. Check if user exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // 2. Generate 6-digit OTP
        $otp = rand(100000, 999999);
        $expiry = date("Y-m-d H:i:s", strtotime("+10 minutes")); // Valid for 10 mins

        // 3. Save to DB
        $update = $pdo->prepare("UPDATE users SET reset_code = ?, reset_expiry = ? WHERE id = ?");
        $update->execute([$otp, $expiry, $user['id']]);

        // 4. SEND EMAIL (SIMULATION)
        // In a real app, use PHPMailer here.
        // For now, we write to a file so you can see the code.
        $log_message = "[" . date("Y-m-d H:i:s") . "] OTP for $email is: $otp" . PHP_EOL;
        file_put_contents("../otp_log.txt", $log_message, FILE_APPEND);

        // Send actual email (This might fail on localhost without config, hence the log file above)
        $subject = "Password Reset OTP";
        $msg = "Your OTP is: $otp";
        $headers = "From: no-reply@jobportal.com";
        @mail($email, $subject, $msg, $headers); 

        echo json_encode(["status" => true, "message" => "OTP sent! Check your email (or otp_log.txt)."]);
    } else {
        // Security: Don't reveal if email exists or not
        echo json_encode(["status" => false, "message" => "If this email exists, an OTP has been sent."]);
    }

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "Error: " . $e->getMessage()]);
}
?>