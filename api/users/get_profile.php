<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

$user_id = $_GET['id'] ?? null;

if (!$user_id) {
    echo json_encode(["status" => false, "message" => "ID required"]);
    exit;
}

try {
    // FIXED: Added 'j.profile_pic' to the list
    $sql = "SELECT u.email, u.mobile, 
                   j.first_name, j.last_name, 
                   j.skills, 
                   COALESCE(j.experience, 'Fresher') as experience, 
                   COALESCE(j.education, 'N/A') as education, 
                   j.bio,
                   j.profile_pic
            FROM users u
            LEFT JOIN jobseekers j ON u.id = j.user_id
            WHERE u.id = ?";
            
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$user_id]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($profile) {
        echo json_encode(["status" => true, "data" => $profile]);
    } else {
        echo json_encode(["status" => false, "message" => "User not found"]);
    }

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>