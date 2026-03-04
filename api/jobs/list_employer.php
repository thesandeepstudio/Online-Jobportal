<?php
// 1. Suppress errors from printing to the screen (corrupting JSON)
error_reporting(E_ALL);
ini_set('display_errors', 0);

// 2. Buffer output
ob_start();

// 3. Include DB (Starts session safely)
require '../db.php';

// 4. Set Header
header("Content-Type: application/json");

// 5. Clean Buffer (Removes any accidental whitespace or warnings)
ob_clean();

// 6. Auth Check
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employer') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

try {
    // Get Employer ID
    $stmt = $pdo->prepare("SELECT id FROM employers WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $employer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$employer) {
        echo json_encode(["status" => false, "message" => "Employer not found"]);
        exit;
    }

    // Get Jobs
    $sql = "SELECT j.*, 
            (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id) as applicant_count 
            FROM jobs j 
            WHERE j.employer_id = ? 
            ORDER BY j.created_at DESC";
            
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$employer['id']]);
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Count Total Applicants
    $sqlCount = "SELECT COUNT(*) 
                 FROM applications a 
                 JOIN jobs j ON a.job_id = j.id 
                 WHERE j.employer_id = ?";
    $stmtCount = $pdo->prepare($sqlCount);
    $stmtCount->execute([$employer['id']]);
    $totalApplicants = $stmtCount->fetchColumn();

    // Data Normalization (Fix status casing)
    foreach ($jobs as &$job) {
        $job['status'] = strtolower($job['status'] ?? 'pending');
    }

    echo json_encode([
        "status" => true, 
        "data" => $jobs,
        "total_applicants" => $totalApplicants
    ]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "Server Error"]);
}
?>