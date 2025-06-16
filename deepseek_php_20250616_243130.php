<?php
require_once 'config.php';

// Get user input
$username = $conn->real_escape_string($_POST['username']);
$password = $_POST['password'];

// Find user in database
$sql = "SELECT id, username, password, is_admin, is_banned FROM users WHERE username = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    
    // Verify password
    if (password_verify($password, $user['password'])) {
        // Check if user is banned
        if ($user['is_banned']) {
            header("Location: index.html?error=Your account has been banned by admin");
            exit();
        }
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = $user['is_admin'];
        
        // Redirect to chat page
        header("Location: chat.php");
        exit();
    }
}

// If we get here, login failed
header("Location: index.html?error=Invalid username or password");
exit();
?>