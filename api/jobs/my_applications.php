<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'jobseeker') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // 1. Get Job Seeker ID
    $stmt = $pdo->prepare("SELECT id FROM jobseekers WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $seeker = $stmt->fetch(PDO::FETCH_ASSOC);

    // 2. Fetch Applications with Job & Company Details
    $sql = "SELECT a.id, a.status, a.applied_at, j.title, e.company_name, j.location
            FROM applications a
            JOIN jobs j ON a.job_id = j.id
            JOIN employers e ON j.employer_id = e.id
            WHERE a.jobseeker_id = ?
            ORDER BY a.applied_at DESC";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([$seeker['id']]);
    $apps = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $apps]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>