<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function respond(int $status, array $payload): void
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(405, ['ok' => false, 'error' => 'Метод не поддерживается']);
}

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host = $_SERVER['HTTP_HOST'] ?? '';
if ($origin !== '' && $host !== '') {
    $parts = parse_url($origin);
    $originHost = $parts['host'] ?? '';
    if (isset($parts['port'])) {
        $originHost .= ':' . $parts['port'];
    }
    if ($originHost === '' || strcasecmp($originHost, $host) !== 0) {
        respond(403, ['ok' => false, 'error' => 'Недопустимый источник запроса']);
    }
}

$contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
$raw = file_get_contents('php://input') ?: '';
if (strlen($raw) > 4096) {
    respond(413, ['ok' => false, 'error' => 'Слишком длинная заявка']);
}

$data = [];
if (stripos($contentType, 'application/json') !== false) {
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        respond(400, ['ok' => false, 'error' => 'Проверьте данные формы']);
    }
    $data = $decoded;
} else {
    $data = $_POST;
}

$honeypot = trim((string) ($data['website'] ?? ''));
if ($honeypot !== '') {
    respond(201, ['ok' => true]);
}

$email = trim((string) ($data['email'] ?? ''));
$email = preg_replace('/\s+/u', '', $email) ?? '';
$consent = $data['consent'] ?? false;
$consentOk = in_array($consent, [true, 1, '1', 'true', 'on', 'yes'], true);

if ($email === '' || strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    respond(400, ['ok' => false, 'error' => 'Укажите корректный адрес электронной почты.']);
}

if (!$consentOk) {
    respond(400, ['ok' => false, 'error' => 'Нужно согласие на обработку персональных данных.']);
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
    $ip = '';
}

$dir = dirname(__DIR__) . '/data';
$file = $dir . '/opening-requests.csv';

if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
    respond(503, ['ok' => false, 'error' => 'Не удалось сохранить адрес. Попробуйте позже.']);
}

$timestamp = gmdate('Y-m-d\TH:i:s\Z');
$handle = fopen($file, 'cb');
if ($handle === false) {
    respond(503, ['ok' => false, 'error' => 'Не удалось сохранить адрес. Попробуйте позже.']);
}

try {
    if (!flock($handle, LOCK_EX)) {
        respond(503, ['ok' => false, 'error' => 'Не удалось сохранить адрес. Попробуйте позже.']);
    }
    $stat = fstat($handle);
    $empty = !$stat || $stat['size'] === 0;
    fseek($handle, 0, SEEK_END);
    if ($empty) {
        fputcsv($handle, ['timestamp_utc', 'email', 'consent', 'ip'], ',', '"', '\\');
    }
    fputcsv($handle, [$timestamp, $email, 'yes', $ip], ',', '"', '\\');
    fflush($handle);
} finally {
    flock($handle, LOCK_UN);
    fclose($handle);
}

respond(201, ['ok' => true]);
