<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

// Auth Check
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'jobseeker') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

// Check if job_id was sent via POST form data
$job_id = $_POST['job_id'] ?? null;

if (!$job_id) {
    echo json_encode(["status" => false, "message" => "Job ID is required"]);
    exit;
}

try {
    // 1. Get JobSeeker ID
    $stmt = $pdo->prepare("SELECT id FROM jobseekers WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $seeker = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$seeker) {
        echo json_encode(["status" => false, "message" => "Profile not found"]);
        exit;
    }

    // 2. Check if already applied
    $check = $pdo->prepare("SELECT status FROM applications WHERE job_id = ? AND jobseeker_id = ?");
    $check->execute([$job_id, $seeker['id']]);
    $existing = $check->fetch(PDO::FETCH_ASSOC);

    if ($existing) {
        if ($existing['status'] === 'rejected') {
            echo json_encode(["status" => false, "message" => "Application Rejected: You cannot re-apply for this job."]);
        } elseif ($existing['status'] === 'hired') {
            echo json_encode(["status" => false, "message" => "You are already HIRED for this job!"]);
        } else {
            echo json_encode(["status" => false, "message" => "You have already applied (Status: " . ucfirst($existing['status']) . ")"]);
        }
        exit;
    }

    // 3. Handle Resume File Upload
    $resume_path = null;
    if (isset($_FILES['resume']) && $_FILES['resume']['error'] === UPLOAD_ERR_OK) {
        $uploadDir = '../uploads/resumes/';
        // Create directory if it doesn't exist
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }

        $fileName = time() . '_' . basename($_FILES['resume']['name']);
        $targetPath = $uploadDir . $fileName;

        if (move_uploaded_file($_FILES['resume']['tmp_name'], $targetPath)) {
            $resume_path = 'uploads/resumes/' . $fileName; // Store relative path
        } else {
            echo json_encode(["status" => false, "message" => "Failed to save the uploaded resume."]);
            exit;
        }
    } else {
        echo json_encode(["status" => false, "message" => "A resume file is required to apply."]);
        exit;
    }

    // 4. Insert Application with Resume
    $sql = "INSERT INTO applications (job_id, jobseeker_id, resume_path) VALUES (?, ?, ?)";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$job_id, $seeker['id'], $resume_path]);

    echo json_encode(["status" => true, "message" => "Application Submitted Successfully!"]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error: " . $e->getMessage()]);
}
?>