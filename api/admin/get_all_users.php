<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// Auth Check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // Select ALL users, joining with profile tables to get names
    // CRITICAL: WHERE u.role != 'admin' hides the admin account
    $sql = "SELECT u.id, u.email, u.role, u.created_at, u.mobile,
            CASE 
                WHEN u.role = 'jobseeker' THEN CONCAT(j.first_name, ' ', j.last_name)
                WHEN u.role = 'employer' THEN e.company_name
                ELSE 'User'
            END AS name
            FROM users u
            LEFT JOIN jobseekers j ON u.id = j.user_id
            LEFT JOIN employers e ON u.id = e.user_id
            WHERE u.role != 'admin' 
            ORDER BY u.created_at DESC";
    
    $stmt = $pdo->query($sql);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $users]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>