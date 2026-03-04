<?php
// 1. Suppress HTML errors breaking JSON
error_reporting(E_ALL);
ini_set('display_errors', 0);

session_start();
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employer') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

$job_id = $_GET['job_id'] ?? null;

if (!$job_id) {
    echo json_encode(["status" => false, "message" => "Job ID is missing"]);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT id FROM employers WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $employer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$employer) {
        echo json_encode(["status" => false, "message" => "Employer not found"]);
        exit;
    }

    // SQL Query
    $sql = "SELECT 
                a.id as app_id, 
                a.status,
                a.applied_at, 
                a.resume_path,
                u.id as user_id, 
                u.email, 
                u.mobile,
                s.first_name, 
                s.last_name, 
                s.skills, 
                s.experience,
                s.profile_pic
            FROM applications a
            JOIN jobseekers s ON a.jobseeker_id = s.id
            JOIN users u ON s.user_id = u.id
            JOIN jobs j ON a.job_id = j.id
            WHERE a.job_id = ? AND j.employer_id = ?
            ORDER BY a.applied_at DESC";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([$job_id, $employer['id']]);
    $applicants = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $applicants]);

} catch (Exception $e) {
    // Return Clean JSON Error
    echo json_encode(["status" => false, "message" => "Server Error: " . $e->getMessage()]);
}
?>