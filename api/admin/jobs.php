<?php
// 1. Clean Output Buffer to remove any previous PHP warnings/notices
ob_start();

// 2. Include DB (This safely starts the session now)
require '../db.php';

// 3. Set JSON Header explicitly
header("Content-Type: application/json");

// 4. Clear Buffer again just before outputting JSON
ob_clean();

// 5. Auth Check
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // Fetch Data
    $sql = "SELECT 
                j.id, 
                j.title, 
                j.job_type, 
                j.category,
                j.salary,
                j.description,
                j.status, 
                j.created_at, 
                j.location, 
                e.company_name
            FROM jobs j 
            JOIN employers e ON j.employer_id = e.id 
            ORDER BY j.created_at DESC";
            
    $stmt = $pdo->query($sql);
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Data Normalization
    foreach ($jobs as &$job) {
        $job['status'] = strtolower($job['status'] ?? 'pending');
        $job['category'] = $job['category'] ?? 'General';
        $job['location'] = $job['location'] ?? 'Remote';
    }

    echo json_encode(["status" => true, "data" => $jobs]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>