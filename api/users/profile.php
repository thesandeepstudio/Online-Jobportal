<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

$user_id = $_SESSION['user_id'];

// --- GET ---
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    try {
        $stmt = $pdo->prepare("SELECT users.email, jobseekers.* 
                               FROM users 
                               LEFT JOIN jobseekers ON users.id = jobseekers.user_id 
                               WHERE users.id = ?");
        $stmt->execute([$user_id]);
        echo json_encode(["status" => true, "data" => $stmt->fetch(PDO::FETCH_ASSOC)]);
    } catch (Exception $e) { echo json_encode(["status" => false]); }
    exit;
}

// --- POST (With File Upload) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // We use $_POST because FormData sends standard multipart form data
    $first = $_POST['first_name'];
    $last = $_POST['last_name'];
    $skills = $_POST['skills'];
    $exp = $_POST['experience'];
    $edu = $_POST['education'];
    $bio = $_POST['bio'];
    
    $profile_pic_path = null;

    // Handle File Upload
    if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
        $uploadDir = '../uploads/';
        if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);

        $fileName = time() . '_' . basename($_FILES['profile_pic']['name']);
        $targetPath = $uploadDir . $fileName;

        if (move_uploaded_file($_FILES['profile_pic']['tmp_name'], $targetPath)) {
            $profile_pic_path = 'uploads/' . $fileName; // Store relative path for DB
        }
    }

    try {
        $check = $pdo->prepare("SELECT id FROM jobseekers WHERE user_id = ?");
        $check->execute([$user_id]);

        if ($check->rowCount() > 0) {
            // Update
            $sql = "UPDATE jobseekers SET first_name=?, last_name=?, skills=?, experience=?, education=?, bio=?";
            $params = [$first, $last, $skills, $exp, $edu, $bio];

            if ($profile_pic_path) {
                $sql .= ", profile_pic=?";
                $params[] = $profile_pic_path;
            }

            $sql .= " WHERE user_id=?";
            $params[] = $user_id;

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

        } else {
            // Insert
            $sql = "INSERT INTO jobseekers (user_id, first_name, last_name, skills, experience, education, bio, profile_pic) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$user_id, $first, $last, $skills, $exp, $edu, $bio, $profile_pic_path]);
        }

        echo json_encode(["status" => true, "message" => "Profile Saved!"]);

    } catch (Exception $e) {
        echo json_encode(["status" => false, "message" => "Error: " . $e->getMessage()]);
    }
}
?>