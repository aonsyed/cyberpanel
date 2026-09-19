<?php
// CyberPanel managed database TLS drop-in, version 1.
// Only this executable drop-in belongs in wp-content. Material is outside it.

final class CyberPanel_TLS_WPDB extends wpdb {
    private const MATERIAL_DIRECTORY = '__CYBERPANEL_PRIVATE_DIRECTORY_BASE64__';
    private bool $cyberpanelInitialized = false;

    public function close() {
        $closed = parent::close();
        if ($closed) { $this->cyberpanelInitialized = false; }
        return $closed;
    }

    public function db_connect($allow_bail = true) {
        $this->ready = false;
        $this->is_mysql = true;
        mysqli_report(MYSQLI_REPORT_OFF);
        $connection = null;
        try {
            $materialDirectory = base64_decode(self::MATERIAL_DIRECTORY, true);
            if (!$materialDirectory || $materialDirectory[0] !== '/' || str_contains($materialDirectory, "\0")) {
                throw new RuntimeException('Invalid private material directory');
            }
            $configuration = json_decode(
                file_get_contents($materialDirectory . '/.cyberpanel-db-tls.json'),
                true,
                8,
                JSON_THROW_ON_ERROR
            );
            if (!is_array($configuration)
                || array_diff(array_keys($configuration), ['version', 'host', 'port', 'mutual'])
                || ($configuration['version'] ?? null) !== 1
                || !is_string($configuration['host'] ?? null)
                || !is_int($configuration['port'] ?? null)
                || $configuration['port'] < 1 || $configuration['port'] > 65535
                || !is_bool($configuration['mutual'] ?? null)) {
                throw new RuntimeException('Invalid database TLS configuration');
            }
            $endpoint = $this->parse_db_host($this->dbhost);
            if (!$endpoint || $endpoint[2] !== null
                || $endpoint[0] !== $configuration['host']
                || (int) ($endpoint[1] ?? 3306) !== $configuration['port']
                || str_starts_with($endpoint[0], 'p:')) {
                throw new RuntimeException('Database TLS endpoint mismatch');
            }
            $connection = mysqli_init();
            if (!$connection) {
                throw new RuntimeException('Database connection initialization failed');
            }
            // mysqlnd verifies both certificate and peer name when a CA is
            // supplied. Its legacy MYSQLI_OPT_SSL_VERIFY_SERVER_CERT option
            // is not supported by mysqli_options; never use the DONT_VERIFY flag.
            $mutual = $configuration['mutual'];
            if (!mysqli_ssl_set(
                $connection,
                $mutual ? $materialDirectory . '/.cyberpanel-db-client.key' : null,
                $mutual ? $materialDirectory . '/.cyberpanel-db-client.pem' : null,
                $materialDirectory . '/.cyberpanel-db-ca.pem',
                null,
                null
            )) {
                throw new RuntimeException('Database TLS setup failed');
            }
            $host = $endpoint[0];
            if ($endpoint[3] && extension_loaded('mysqlnd')) {
                $host = '[' . $host . ']';
            }
            // No caller flags may disable peer verification or introduce
            // plaintext fallback. Never connect through a local socket here.
            if (!@mysqli_real_connect($connection, $host, $this->dbuser, $this->dbpassword,
                null, $configuration['port'], null, MYSQLI_CLIENT_SSL)) {
                throw new RuntimeException('Verified database TLS connection failed');
            }
            $result = mysqli_query($connection, "SHOW SESSION STATUS LIKE 'Ssl_cipher'");
            $cipher = $result ? mysqli_fetch_row($result) : null;
            if ($result) { mysqli_free_result($result); }
            if (!$cipher || !is_string($cipher[1]) || $cipher[1] === '') {
                throw new RuntimeException('Database did not negotiate TLS');
            }
            $this->dbh = $connection;
            if (!$this->cyberpanelInitialized) { $this->init_charset(); }
            $this->set_charset($connection);
            $this->ready = true;
            $this->set_sql_mode();
            $this->select($this->dbname, $connection);
            if (!$this->ready) { throw new RuntimeException('Database selection failed'); }
            $this->cyberpanelInitialized = true;
            return true;
        } catch (Throwable $failure) {
            if ($connection instanceof mysqli) {
                try { mysqli_close($connection); } catch (Throwable $ignored) {}
            }
            $this->dbh = null;
            $this->ready = false;
            $this->last_error = 'CyberPanel could not establish a verified database TLS connection.';
            if ($allow_bail) { $this->bail($this->last_error, 'db_connect_fail'); }
            return false;
        }
    }
}

$wpdb = new CyberPanel_TLS_WPDB(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
