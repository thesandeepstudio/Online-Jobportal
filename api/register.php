<?php
// 1. Headers to allow API access
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

require 'db.php';

// 2. Get JSON Input
$input = file_get_contents("php://input");
$data = json_decode($input, true);

if (!$data) {
    echo json_encode(["status" => false, "message" => "No data received"]);
    exit;
}

$role = $data['role'] ?? '';
$email = $data['email'] ?? '';
$password = $data['password'] ?? '';
$mobile = $data['mobile'] ?? '';

// --- VALIDATION START ---

// A. Check Empty Fields
if (empty($role) || empty($email) || empty($password)) {
    echo json_encode(["status" => false, "message" => "Missing required fields"]);
    exit;
}

// B. Validate Email Format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(["status" => false, "message" => "Invalid email format. Please use a valid address."]);
    exit;
}

// C. STRONG PASSWORD VALIDATION (Backend)
if (strlen($password) < 8) {
    echo json_encode(["status" => false, "message" => "Password must be at least 8 characters long."]);
    exit;
}
if (!preg_match('/[A-Z]/', $password)) {
    echo json_encode(["status" => false, "message" => "Password must contain at least one uppercase letter."]);
    exit;
}
if (!preg_match('/[0-9]/', $password)) {
    echo json_encode(["status" => false, "message" => "Password must contain at least one number."]);
    exit;
}
if (!preg_match('/[\W]/', $password)) { // \W checks for non-alphanumeric chars (symbols)
    echo json_encode(["status" => false, "message" => "Password must contain at least one special character."]);
    exit;
}
// Check if password contains the email username
$username = explode('@', $email)[0];
if (strpos(strtolower($password), strtolower($username)) !== false) {
    echo json_encode(["status" => false, "message" => "Password cannot contain your email username."]);
    exit;
}

// --- VALIDATION END ---

try {
    // 4. Check if Email already exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->rowCount() > 0) {
        echo json_encode(["status" => false, "message" => "Email already registered"]);
        exit;
    }

    // 5. Start Transaction
    $pdo->beginTransaction();

    // 6. Insert into Users Table
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    
    $sql_user = "INSERT INTO users (email, password, role, mobile) VALUES (?, ?, ?, ?)";
    $stmt_user = $pdo->prepare($sql_user);
    $stmt_user->execute([$email, $hashed_password, $role, $mobile]);
    
    // Get the ID of the new user
    $user_id = $pdo->lastInsertId();

    // 7. Insert into Specific Role Table
    if ($role === 'jobseeker') {
        $first_name = $data['first_name'] ?? '';
        $last_name = $data['last_name'] ?? '';

        $sql_job = "INSERT INTO jobseekers (user_id, first_name, last_name) VALUES (?, ?, ?)";
        $stmt_job = $pdo->prepare($sql_job);
        $stmt_job->execute([$user_id, $first_name, $last_name]);

    } elseif ($role === 'employer') {
        $company_name = $data['company_name'] ?? '';
        $company_size = $data['company_size'] ?? '';
        $industry = $data['industry'] ?? '';
        $location = $data['location'] ?? '';

        $sql_emp = "INSERT INTO employers (user_id, company_name, company_size, industry, location) VALUES (?, ?, ?, ?, ?)";
        $stmt_emp = $pdo->prepare($sql_emp);
        $stmt_emp->execute([$user_id, $company_name, $company_size, $industry, $location]);
    }

    // 8. Commit Transaction
    $pdo->commit();

    echo json_encode(["status" => true, "message" => "Account created successfully!"]);

} catch (Exception $e) {
    $pdo->rollBack();
    echo json_encode(["status" => false, "message" => "Server Error: " . $e->getMessage()]);
}
?>