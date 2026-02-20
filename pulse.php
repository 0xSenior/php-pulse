<?php
/**
 * Revolt Roleplay - Secure PHP Proxy Handshake
 * This file acts as a bridge between the Launcher and the MTA Server.
 */

header('Content-Type: application/json');

// 1. الإعدادات الأساسية
define('SHARED_SECRET', 'RevoltRP_Exclusive_Security_2024!');
define('AUTH_STORAGE', 'auth_list.json'); // ملف لتخزين الأجهزة المصرح بها
define('EXPIRY_TIME', 120); // مدة صلاحية التصريح (ثانية)

// 2. معالجة الطلبات القادمة من اللانشر (POST)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);

    if (!$data || !isset($data[0]) || !isset($data[1])) {
        die(json_encode(['success' => false, 'message' => 'INVALID_FORMAT']));
    }

    $hwid = strtoupper(trim($data[0]));
    $key = trim($data[1]);

    if ($key !== SHARED_SECRET) {
        die(json_encode(['success' => false, 'message' => 'INVALID_KEY']));
    }

    // قراءة القائمة الحالية
    $list = [];
    if (file_exists(AUTH_STORAGE)) {
        $list = json_decode(file_get_contents(AUTH_STORAGE), true) ?: [];
    }

    // إضافة الجهاز الجديد مع وقت التسجيل
    $list[$hwid] = time();

    // تنظيف القائمة من الأجهزة القديمة
    $currentTime = time();
    foreach ($list as $id => $timestamp) {
        if ($currentTime - $timestamp > EXPIRY_TIME) {
            unset($list[$id]);
        }
    }

    // حفظ القائمة
    file_put_contents(AUTH_STORAGE, json_encode($list));

    echo json_encode(['success' => true, 'message' => 'AUTH_SUCCESS', 'hwid' => $hwid]);
    exit;
}

// 3. معالجة طلبات التحقق القادمة من السيرفر (GET)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['check'])) {
    $hwidToCheck = strtoupper(trim($_GET['check']));
    
    if (file_exists(AUTH_STORAGE)) {
        $list = json_decode(file_get_contents(AUTH_STORAGE), true) ?: [];
        
        if (isset($list[$hwidToCheck])) {
            $timestamp = $list[$hwidToCheck];
            if (time() - $timestamp <= EXPIRY_TIME) {
                // التصريح صالح
                unset($list[$hwidToCheck]); // مسحه لمنع إعادة الاستخدام
                file_put_contents(AUTH_STORAGE, json_encode($list));
                die("AUTHORIZED");
            }
        }
    }
    
    die("DENIED");
}

echo json_encode(['success' => false, 'message' => 'ACCESS_DENIED']);
