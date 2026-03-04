<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// 1. Check Auth: Must be logged in AND be an Employer
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employer') {
    echo json_encode(["status" => false, "message" => "Unauthorized. Employers only."]);
    exit;
}

// 2. Get JSON Input
$data = json_decode(file_get_contents("php://input"), true);

try {
    // 3. Get the Employer ID based on User ID
    // (Because 'jobs' table links to 'employers' table, not 'users' table directly)
    $stmt = $pdo->prepare("SELECT id FROM employers WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $employer = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$employer) {
        echo json_encode(["status" => false, "message" => "Employer profile not found."]);
        exit;
    }

    // 4. Insert Job
    $sql = "INSERT INTO jobs (employer_id, title, category, job_type, salary, description, location) 
            VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        $employer['id'],
        $data['title'],
        $data['category'],
        $data['job_type'],
        $data['salary'],
        $data['description'],
        $data['location']
    ]);

    echo json_encode(["status" => true, "message" => "Job Posted Successfully!"]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>