<?php
// 1. Suppress PHP Error display (Logs them instead of printing to screen)
error_reporting(E_ALL);
ini_set('display_errors', 0);

// 2. Start Output Buffering
ob_start();

session_start();
header("Content-Type: application/json");
require '../db.php';

// 3. Clear Buffer (Removes any accidental whitespace/warnings)
ob_clean(); 

// Auth Check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // 4. Fetch Data (Strictly Job Seekers)
    $sql = "SELECT 
                j.id, 
                j.user_id,
                j.first_name, 
                j.last_name, 
                j.skills, 
                j.experience, 
                j.education,
                j.profile_pic,
                u.email, 
                u.mobile, 
                u.created_at
            FROM jobseekers j
            JOIN users u ON j.user_id = u.id
            WHERE u.role = 'jobseeker' 
            AND u.role != 'admin'
            ORDER BY u.created_at DESC";
            
    $stmt = $pdo->query($sql);
    $seekers = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $seekers]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>