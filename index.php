<?php
/**
 * Revolt Roleplay - Railway Optimized Proxy
 * This script handles HWID authorization from the launcher and verification from the MTA server.
 */

header('Content-Type: application/json');

// 1. Settings
define('SHARED_SECRET', 'RevoltRP_Exclusive_Security_2024!');
// Use /tmp/ in Railway to ensure write permissions
define('AUTH_STORAGE', '/tmp/auth_list.json'); 
define('EXPIRY_TIME', 120);

// Ensure file exists
if (!file_exists(AUTH_STORAGE)) {
    file_put_contents(AUTH_STORAGE, json_encode([]));
}

// 2. Handle Pulse from Launcher (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);

    if (!$data || count($data) < 2) {
        die(json_encode(['success' => false, 'message' => 'INVALID_FORMAT']));
    }

    $hwid = strtoupper(trim($data[0]));
    $key = trim($data[1]);

    if ($key !== SHARED_SECRET) {
        die(json_encode(['success' => false, 'message' => 'INVALID_KEY']));
    }

    $list = json_decode(file_get_contents(AUTH_STORAGE), true) ?: [];
    $list[$hwid] = time();

    // Cleanup old entries
    foreach ($list as $id => $time) {
        if (time() - $time > EXPIRY_TIME) unset($list[$id]);
    }

    file_put_contents(AUTH_STORAGE, json_encode($list));
    echo json_encode(['success' => true, 'message' => 'AUTH_SUCCESS']);
    exit;
}

// 3. Handle Check from MTA Server (GET)
if (isset($_GET['check'])) {
    $hwidToCheck = strtoupper(trim($_GET['check']));
    $list = json_decode(file_get_contents(AUTH_STORAGE), true) ?: [];
    
    if (isset($list[$hwidToCheck]) && (time() - $list[$hwidToCheck] <= EXPIRY_TIME)) {
        unset($list[$hwidToCheck]); // One-time use for security
        file_put_contents(AUTH_STORAGE, json_encode($list));
        die("AUTHORIZED");
    }
    die("DENIED");
}

// Status page (for debugging)
echo json_encode(['status' => 'online', 'service' => 'Revolt Auth Proxy']);
