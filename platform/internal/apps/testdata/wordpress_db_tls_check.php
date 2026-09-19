<?php
// QEMU driver-level check: actual WordPress wpdb and mysqli, default/no plugin
// hooks. This does not bootstrap a complete WordPress installation or HTTP UI.
define('WP_DEBUG', false);
define('WP_SETUP_CONFIG', true);
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
function is_multisite() { return false; }
function absint($value) { return abs((int) $value); }
function apply_filters($hook, $value, ...$arguments) { return $value; }
function has_filter(...$arguments) { return false; }
function add_filter(...$arguments) { return true; }
function _doing_it_wrong(...$arguments) { throw new RuntimeException('Unexpected WordPress API misuse'); }

$fixture = json_decode(stream_get_contents(STDIN), true, 8, JSON_THROW_ON_ERROR);
define('DB_USER', 'qemu_tls');
define('DB_PASSWORD', $fixture['password']);
define('DB_NAME', 'qemu_wordpress');
define('DB_HOST', $fixture['host'] . ':' . $fixture['port']);
require $fixture['wpdb'];
require $fixture['dropin'];
$tlsWarning = false;
set_error_handler(function ($severity, $message) use (&$tlsWarning) {
    if (stripos($message, 'certificate') !== false || stripos($message, 'SSL') !== false) { $tlsWarning = true; }
    return true;
});
$connected = $wpdb->db_connect(false);
if ($connected !== $fixture['accept']) {
    fwrite(STDERR, 'Unexpected connection verdict; mysqli code ' . mysqli_connect_errno() . "\n");
    exit(1);
}
if (!$connected) {
    if ($wpdb->ready || $wpdb->dbh !== null) { exit(2); }
    if ($fixture['tls_error'] && mysqli_connect_errno() !== 2026
        && !(in_array(mysqli_connect_errno(), [2002, 2006], true) && $tlsWarning)) {
        fwrite(STDERR, 'Rejection was not a TLS error: ' . mysqli_connect_errno() . "\n");
        exit(3);
    }
    echo "rejected\n";
    exit(0);
}
if ($wpdb->get_var('SELECT 7') !== '7'
    || $wpdb->get_var('SELECT @@character_set_connection') !== 'utf8mb4'
    || $wpdb->get_var('SELECT DATABASE()') !== 'qemu_wordpress') {
    fwrite(STDERR, "WordPress query/initialization failed\n");
    exit(4);
}
if (!$wpdb->close() || !$wpdb->check_connection(false)
    || $wpdb->get_var('SELECT 8') !== '8') {
    fwrite(STDERR, "WordPress reconnect failed\n");
    exit(5);
}
$wpdb->close();
echo "connected, queried, charset initialized, reconnected\n";
