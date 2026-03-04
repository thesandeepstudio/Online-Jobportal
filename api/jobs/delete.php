<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// 1. Auth Check: User must be logged in and be an 'employer'
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employer') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

// 2. Get Input Data
$data = json_decode(file_get_contents("php://input"), true);
$job_id = $data['job_id'] ?? null;

if (!$job_id) {
    echo json_encode(["status" => false, "message" => "Job ID required"]);
    exit;
}

try {
    // 3. Security: Get the Employer ID of the logged-in user
    // We do this to ensure Employer A cannot delete Employer B's jobs.
    $stmt = $pdo->prepare("SELECT id FROM employers WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $employer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$employer) {
        echo json_encode(["status" => false, "message" => "Employer profile not found"]);
        exit;
    }

    // 4. Delete the Job
    // We use AND employer_id = ? to strictly enforce ownership
    $sql = "DELETE FROM jobs WHERE id = ? AND employer_id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$job_id, $employer['id']]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(["status" => true, "message" => "Job deleted successfully"]);
    } else {
        echo json_encode(["status" => false, "message" => "Job not found or permission denied"]);
    }

} catch (Exception $e) {
    // Note: If you haven't set up ON DELETE CASCADE in MySQL for the applications table, 
    // this might fail if there are existing applications.
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>