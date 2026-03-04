<?php
session_start();
header("Content-Type: application/json");
require 'db.php';

$data = json_decode(file_get_contents("php://input"), true);
$email = $data['email'] ?? '';
$password = $data['password'] ?? '';

if (empty($email) || empty($password)) {
    echo json_encode(["status" => false, "message" => "Email and Password are required"]);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT id, email, password, role FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        
        // --- SECURITY UPDATE: BLOCK ADMIN HERE ---
        if ($user['role'] === 'admin') {
            echo json_encode(["status" => false, "message" => "Admins must login via the Admin Portal."]);
            exit;
        }

        // Normal Login Logic
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['email'] = $user['email'];

        echo json_encode([
            "status" => true,
            "message" => "Login Successful",
            "user" => ["id" => $user['id'], "role" => $user['role']]
        ]);

    } else {
        echo json_encode(["status" => false, "message" => "Invalid Email or Password"]);
    }
} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "Server Error"]);
}
?>