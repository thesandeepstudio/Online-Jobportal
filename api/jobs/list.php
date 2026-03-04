<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// Auth Check (Need user_id to check application status)
$user_id = $_SESSION['user_id'] ?? 0;

try {
    // 1. Get Job Seeker ID (if logged in)
    $seeker_id = 0;
    if ($user_id) {
        $stmt = $pdo->prepare("SELECT id FROM jobseekers WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $seeker = $stmt->fetch();
        if ($seeker) $seeker_id = $seeker['id'];
    }

    // 2. Fetch Active Jobs + My Application Status
    // We use a subquery to see if *this* user applied to *this* job
    $sql = "SELECT 
                j.id, 
                j.title, 
                j.category, 
                j.job_type, 
                j.salary, 
                j.description,
                j.location, 
                j.created_at, 
                e.company_name,
                (SELECT status FROM applications a WHERE a.job_id = j.id AND a.jobseeker_id = ?) as my_status
            FROM jobs j 
            JOIN employers e ON j.employer_id = e.id 
            WHERE j.status = 'active' 
            ORDER BY j.created_at DESC";
            
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$seeker_id]);
    $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["status" => true, "data" => $jobs]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>