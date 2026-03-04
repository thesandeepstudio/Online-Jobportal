<?php
// 1. Headers
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

require 'db.php';

// 2. Get Input
$data = json_decode(file_get_contents("php://input"), true);

$email = $data['email'] ?? '';
$mobile = $data['mobile'] ?? '';
$new_password = $data['new_password'] ?? '';

// 3. Validation
if (empty($email) || empty($mobile) || empty($new_password)) {
    echo json_encode(["status" => false, "message" => "All fields are required"]);
    exit;
}

try {
    // 4. Verify Identity (Check if Email AND Mobile match)
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND mobile = ?");
    $stmt->execute([$email, $mobile]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // 5. Update Password
        $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);
        
        $updateStmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $updateStmt->execute([$hashed_password, $user['id']]);

        echo json_encode(["status" => true, "message" => "Password reset successful! You can now login."]);
    } else {
        echo json_encode(["status" => false, "message" => "Details do not match our records."]);
    }

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "Server Error: " . $e->getMessage()]);
}
?>