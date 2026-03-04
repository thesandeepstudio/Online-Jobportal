<?php
// 1. Prevent HTML errors breaking JSON
error_reporting(E_ALL);
ini_set('display_errors', 0);

session_start();
header("Content-Type: application/json");
require '../db.php';

// 2. Auth Check
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employer') {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);
$app_id = $data['app_id'] ?? null;
$status = $data['status'] ?? null;
$custom_msg = $data['message'] ?? null;

if (!$app_id || !in_array($status, ['interview', 'hired', 'rejected'])) {
    echo json_encode(["status" => false, "message" => "Invalid data"]);
    exit;
}

try {
    $pdo->beginTransaction();

    // 3. Get Details & Verify Ownership
    $check = $pdo->prepare("SELECT a.id, a.job_id, j.title, s.user_id as seeker_id 
                            FROM applications a 
                            JOIN jobs j ON a.job_id = j.id 
                            JOIN employers e ON j.employer_id = e.id 
                            JOIN jobseekers s ON a.jobseeker_id = s.id
                            WHERE a.id = ? AND e.user_id = ?");
    $check->execute([$app_id, $_SESSION['user_id']]);
    $appData = $check->fetch(PDO::FETCH_ASSOC);

    if (!$appData) {
        echo json_encode(["status" => false, "message" => "Permission denied"]);
        $pdo->rollBack();
        exit;
    }

    $jobId = $appData['job_id'];

    // 4. UPDATE TARGET APPLICATION STATUS
    $stmt = $pdo->prepare("UPDATE applications SET status = ? WHERE id = ?");
    $stmt->execute([$status, $app_id]);

    // 5. NOTIFICATION & AUTOMATION LOGIC
    $title = "Application Update";
    $msg = "Status: $status";

    if ($status === 'interview') {
        $title = "Interview Scheduled 📅";
        $msg = "You have been selected for an INTERVIEW for <b>{$appData['title']}</b>.";
        if ($custom_msg) $msg .= "<br><b>Details:</b> $custom_msg";
    } 
    elseif ($status === 'hired') {
        $title = "Congratulations! 🎉";
        $msg = "You have been <b>HIRED</b> for <b>{$appData['title']}</b>!";
        if ($custom_msg) $msg .= "<br><b>Joining Details:</b> $custom_msg";

        // --- A. AUTOMATICALLY REJECT OTHERS ---
        $rejectOthers = $pdo->prepare("UPDATE applications SET status = 'rejected' WHERE job_id = ? AND id != ?");
        $rejectOthers->execute([$jobId, $app_id]);

        // --- B. AUTOMATICALLY CLOSE JOB POST ---
$closeJob = $pdo->prepare("UPDATE jobs SET status = 'closed' WHERE id = ?");
$closeJob->execute([$jobId]);
    } 
    elseif ($status === 'rejected') {
        $msg = "Your application for <b>{$appData['title']}</b> was not successful.";
    }

    // 6. Insert Notification
    $notif = $pdo->prepare("INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)");
    $notif->execute([$appData['seeker_id'], $title, $msg]);

    $pdo->commit();
    echo json_encode(["status" => true, "message" => "Status updated successfully"]);

} catch (Exception $e) {
    $pdo->rollBack();
    echo json_encode(["status" => false, "message" => "Server Error: " . $e->getMessage()]);
}
?>