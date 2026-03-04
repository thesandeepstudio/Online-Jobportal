<?php
header("Content-Type: application/json");
require '../db.php'; 

// Auth Check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

// *** CRITICAL FIX: Unlock the session ***
// We verified the user. Now let other requests proceed immediately.
session_write_close();

$data = json_decode(file_get_contents("php://input"), true);
$user_id = $data['user_id'] ?? null;

if (!$user_id) {
    echo json_encode(["status" => false, "message" => "User ID required"]);
    exit;
}

try {
    if ($user_id == $_SESSION['user_id']) {
        echo json_encode(["status" => false, "message" => "You cannot delete yourself!"]);
        exit;
    }

    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$user_id]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(["status" => true, "message" => "User deleted successfully"]);
    } else {
        echo json_encode(["status" => false, "message" => "User not found"]);
    }
} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>