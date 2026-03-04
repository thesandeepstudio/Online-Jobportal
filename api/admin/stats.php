<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// Check if Admin
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // 1. Count Job Seekers
    $stmt = $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'jobseeker'");
    $seekers = $stmt->fetchColumn();

    // 2. Count Employers
    $stmt = $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'employer'");
    $employers = $stmt->fetchColumn();

    // 3. Count Active Jobs [NEW]
    $stmt = $pdo->query("SELECT COUNT(*) FROM jobs WHERE status = 'active'");
    $active_jobs = $stmt->fetchColumn();

    // Total Users
    $total = $seekers + $employers;

    echo json_encode([
        "status" => true,
        "seekers" => $seekers,
        "employers" => $employers,
        "active_jobs" => $active_jobs, // [NEW]
        "total" => $total
    ]);

} catch (PDOException $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>