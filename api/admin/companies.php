<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// Auth Check: Admin Only
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // Added 'u.id as user_id' so we can delete the account if needed
    $sql = "SELECT 
                e.id, 
                e.user_id, 
                e.company_name, 
                e.industry, 
                e.location, 
                e.company_size,
                u.email, 
                u.mobile, 
                u.created_at,
                (SELECT COUNT(*) FROM jobs j WHERE j.employer_id = e.id) as job_count
            FROM employers e
            JOIN users u ON e.user_id = u.id
            ORDER BY e.company_name ASC";
            
    $stmt = $pdo->query($sql);
    $companies = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $companies]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>