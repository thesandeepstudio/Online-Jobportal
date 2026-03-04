<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // [UPDATED] Fetch ALL fields needed for the modal
    $sql = "SELECT j.id, j.title, j.job_type, j.salary, j.description, j.location, j.created_at, e.company_name 
            FROM jobs j 
            JOIN employers e ON j.employer_id = e.id 
            WHERE j.status = 'pending' 
            ORDER BY j.created_at ASC";
            
    $stmt = $pdo->query($sql);
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $jobs]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>