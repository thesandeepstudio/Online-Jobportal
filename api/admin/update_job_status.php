<?php
// Standard header
header("Content-Type: application/json");

// Use the robust db.php (Starts session automatically)
require '../db.php';

// Auth Check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

// Unlock Session immediately so other requests (like reloading the table) don't get stuck
session_write_close();

$data = json_decode(file_get_contents("php://input"), true);
$job_id = $data['job_id'];
$status = $data['status'];

if (!$job_id || !$status) {
    echo json_encode(["status" => false, "message" => "Missing data"]);
    exit;
}

try {
    $stmt = $pdo->prepare("UPDATE jobs SET status = ? WHERE id = ?");
    $stmt->execute([$status, $job_id]);

    echo json_encode(["status" => true, "message" => "Job marked as " . $status]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "Update failed"]);
}
?>