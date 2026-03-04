<?php
session_start();
header("Content-Type: application/json");
require '../db.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["status" => false, "message" => "Unauthorized"]);
    exit;
}

$user_id = $_SESSION['user_id'];

// --- 1. POST REQUEST: MARK ALL AS READ ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ?");
        $stmt->execute([$user_id]);
        echo json_encode(["status" => true, "message" => "Marked all as read"]);
    } catch (Exception $e) {
        echo json_encode(["status" => false, "message" => "DB Error"]);
    }
    exit;
}

// --- 2. GET REQUEST: FETCH NOTIFICATIONS ---
try {
    // Fetch latest 10
    $stmt = $pdo->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
    $stmt->execute([$user_id]);
    $notifs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Count unread
    $stmtCount = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
    $stmtCount->execute([$user_id]);
    $unread = $stmtCount->fetchColumn();

    echo json_encode(["status" => true, "data" => $notifs, "unread" => $unread]);

} catch (Exception $e) {
    echo json_encode(["status" => false, "message" => "DB Error"]);
}
?>