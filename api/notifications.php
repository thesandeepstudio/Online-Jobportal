<?php
session_start();
header("Content-Type: application/json");
require 'db.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

$user_id = $_SESSION['user_id'];

// 1. Fetch Notifications
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    try {
        $stmt = $pdo->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
        $stmt->execute([$user_id]);
        $notifs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Count unread
        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
        $countStmt->execute([$user_id]);
        $unread = $countStmt->fetchColumn();

        echo json_encode(["status" => true, "data" => $notifs, "unread_count" => $unread]);
    } catch (Exception $e) {
        echo json_encode(["status" => false]);
    }
}

// 2. Mark as Read
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ?");
    $stmt->execute([$user_id]);
    echo json_encode(["status" => true]);
}
?>