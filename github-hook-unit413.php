<?php
// GitHub Webhook for scouts.saintabanoub.com
// Path: /var/www/saintabanoub.com/scouts.saintabanoub.com/github-hook-unit413.php
// Purpose: verify signature and trigger deploy script

$secret = trim(@file_get_contents('/etc/github_webhook_secret_unit413'));
if (!$secret) {
    http_response_code(500);
    echo "❌ Secret not configured.";
    exit;
}

function hash_equals_safe($a, $b) {
    if (function_exists('hash_equals')) {
        return hash_equals($a, $b);
    }
    if (strlen($a) !== strlen($b)) {
        return false;
    }
    $res = 0;
    for ($i = 0; $i < strlen($a); $i++) {
        $res |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $res === 0;
}

$signature = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
$event     = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
$delivery  = $_SERVER['HTTP_X_GITHUB_DELIVERY'] ?? '';

$raw = file_get_contents('php://input');
$calc = 'sha256=' . hash_hmac('sha256', $raw, $secret);

// Verify signature
if (!hash_equals_safe($calc, $signature)) {
    http_response_code(401);
    echo "❌ Invalid signature.";
    exit;
}

// Parse payload
$payload = json_decode($raw, true);
if (!$payload) {
    http_response_code(400);
    echo "❌ Invalid JSON payload.";
    exit;
}

// Only act on push to main branch
if ($event !== 'push') {
    echo "ℹ️ Ignoring event: $event";
    exit;
}
$ref = $payload['ref'] ?? '';
if ($ref !== 'refs/heads/main') {
    echo "ℹ️ Ignoring ref: $ref";
    exit;
}

// Run deploy script (via sudoers whitelist for www-data)
$cmd = 'sudo /usr/local/bin/deploy-unit413.sh';
exec($cmd . ' 2>&1', $output, $code);

header('Content-Type: application/json');
echo json_encode([
    'ok'       => $code === 0,
    'code'     => $code,
    'output'   => $output,
    'delivery' => $delivery,
]);
