<?php
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

// *** CRITICAL FIX: Unlock the session ***
session_write_close();

$data = json_decode(file_get_contents("php://input"), true);
$job_id = $data['job_id'] ?? null;

if (!$job_id) {
    echo json_encode(["status" => false, "message" => "Job ID required"]);
    exit;
}

try {
    $stmt = $pdo->prepare("DELETE FROM jobs WHERE id = ?");
    $stmt->execute([$job_id]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(["status" => true, "message" => "Job deleted successfully"]);
    } else {
        echo json_encode(["status" => false, "message" => "Job not found"]);
    }
} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>