<?php
// TARGET-01: Web Vulnerável (DVWA-like)
// Vulns: LFI, SQLi no login
// Flag: flag{web_master} em /var/secret/flag.txt

$flag = "flag{web_master_2026}";
file_put_contents("/var/secret/flag.txt", $flag);

// Mini framework web vulnerável
session_start();

$db = new SQLite3('/tmp/target01.db');
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
$db->exec("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')");
$db->exec("INSERT OR IGNORE INTO users VALUES (2, 'guest', 'guest', 'user')");
$db->exec("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, key TEXT, value TEXT)");
$db->exec("INSERT OR IGNORE INTO secrets VALUES (1, 'db_password', 'MySQL_R00t_2026!')");
$db->exec("INSERT OR IGNORE INTO secrets VALUES (2, 'ssh_key_location', '/home/admin/.ssh/id_rsa')");

$page = $_GET['page'] ?? 'home';
$action = $_GET['action'] ?? '';

// === ROUTING ===
switch($page) {
    case 'home':
        echo "<html><head><title>SecureCorp Portal</title></head><body>";
        echo "<h1>SecureCorp Employee Portal</h1>";
        echo "<p>Welcome to the SecureCorp internal portal.</p>";
        echo "<ul>";
        echo "<li><a href='?page=login'>Login</a></li>";
        echo "<li><a href='?page=dashboard'>Dashboard</a></li>";
        echo "<li><a href='?page=reports'>Reports</a></li>";
        echo "<li><a href='?page=api'>API Docs</a></li>";
        echo "</ul>";
        echo "<!-- TODO: remove debug page at ?page=debug -->";
        echo "</body></html>";
        break;

    case 'login':
        echo "<html><head><title>Login</title></head><body>";
        echo "<h2>Employee Login</h2>";
        echo "<form method='POST'>";
        echo "<input name='username' placeholder='Username'><br>";
        echo "<input name='password' type='password' placeholder='Password'><br>";
        echo "<button type='submit'>Login</button>";
        echo "</form>";
        
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $user = $_POST['username'] ?? '';
            $pass = $_POST['password'] ?? '';
            // VULN: SQL Injection
            $result = $db->query("SELECT * FROM users WHERE username='$user' AND password='$pass'");
            $row = $result->fetchArray();
            if ($row) {
                $_SESSION['user'] = $row['username'];
                $_SESSION['role'] = $row['role'];
                echo "<p style='color:green'>Welcome, {$row['username']}! Role: {$row['role']}</p>";
                echo "<p><a href='?page=dashboard'>Go to Dashboard</a></p>";
            } else {
                echo "<p style='color:red'>Invalid credentials</p>";
            }
        }
        echo "</body></html>";
        break;

    case 'dashboard':
        if (!isset($_SESSION['user'])) {
            echo "<p>Please <a href='?page=login'>login</a> first.</p>";
            break;
        }
        echo "<html><head><title>Dashboard</title></head><body>";
        echo "<h2>Welcome, {$_SESSION['user']}!</h2>";
        echo "<p>Role: {$_SESSION['role']}</p>";
        if ($_SESSION['role'] === 'admin') {
            echo "<h3>Admin Panel</h3>";
            echo "<ul>";
            echo "<li><a href='?page=dashboard&action=view_secrets'>View Secrets</a></li>";
            echo "<li><a href='?page=dashboard&action=system_info'>System Info</a></li>";
            echo "</ul>";
            
            if ($action === 'view_secrets') {
                echo "<h3>Database Secrets</h3>";
                $secrets = $db->query("SELECT * FROM secrets");
                echo "<table border=1><tr><th>Key</th><th>Value</th></tr>";
                while ($s = $secrets->fetchArray()) {
                    echo "<tr><td>{$s['key']}</td><td>{$s['value']}</td></tr>";
                }
                echo "</table>";
            }
            if ($action === 'system_info') {
                echo "<h3>System Info</h3>";
                echo "<pre>";
                echo "Hostname: " . gethostname() . "\n";
                echo "PHP: " . phpversion() . "\n";
                echo "User: " . get_current_user() . "\n";
                echo "</pre>";
            }
        }
        echo "</body></html>";
        break;

    case 'reports':
        // VULN: Local File Inclusion
        $report = $_GET['file'] ?? 'summary.txt';
        // No sanitization — LFI!
        $content = file_get_contents($report);
        if ($content) {
            echo "<html><head><title>Report</title></head><body>";
            echo "<h2>Report: " . htmlspecialchars($report) . "</h2>";
            echo "<pre>" . htmlspecialchars($content) . "</pre>";
            echo "</body></html>";
        } else {
            echo "<p>Report not found: " . htmlspecialchars($report) . "</p>";
        }
        break;

    case 'api':
        echo "<html><head><title>API</title></head><body>";
        echo "<h2>SecureCorp API v2.1</h2>";
        echo "<pre>";
        echo "GET /api/users     - List users\n";
        echo "GET /api/status    - System status\n";
        echo "POST /api/upload   - Upload file\n";
        echo "</pre>";
        echo "<!-- Internal API at 10.0.0.40:3306 uses creds from secrets table -->";
        echo "</body></html>";
        break;

    case 'debug':
        // VULN: Debug page exposed
        echo "<html><head><title>Debug</title></head><body>";
        echo "<h2>Debug Panel</h2>";
        echo "<p>PHP Version: " . phpversion() . "</p>";
        echo "<p>Server: " . $_SERVER['SERVER_SOFTWARE'] . "</p>";
        echo "<p>Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "</p>";
        echo "<h3>Environment Variables</h3><pre>";
        print_r($_ENV);
        echo "</pre>";
        echo "<h3>POST Data</h3><pre>";
        print_r($_POST);
        echo "</pre>";
        echo "</body></html>";
        break;

    default:
        echo "<p>Page not found</p>";
}
?>
