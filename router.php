<?php
declare(strict_types=1);

// Only for local `php -S localhost:8080 router.php`. Apache on REG.RU uses data/.htaccess.
if (PHP_SAPI !== 'cli-server') {
    http_response_code(404);
    exit;
}

$uri = urldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');
if (preg_match('#^/data(/|$)#', $uri) === 1) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Forbidden';
    return true;
}

if ($uri === '/' || $uri === '') {
    $uri = '/index.html';
}
$file = __DIR__ . $uri;
if (is_file($file)) {
    return false;
}

http_response_code(404);
echo 'Not found';
return true;
