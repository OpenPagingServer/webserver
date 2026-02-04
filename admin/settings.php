<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', '/tmp/php-debug.log');
error_reporting(E_ALL);

session_start();
require_once '/var/www/html/config.php';

$is_insecure = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on');
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $is_insecure = false;
}

if (!isset($_SESSION['user_id'])) {
    header("Location: /");
    exit;
}

$stmt = $pdo->prepare("SELECT role FROM users WHERE id = :id LIMIT 1");
$stmt->execute(['id' => $_SESSION['user_id']]);
$userRole = $stmt->fetchColumn();
$isAdmin = ($userRole === 'admin' || $userRole === 'tempadmin');
if (!$isAdmin) {
    http_response_code(403);
    header('Content-Type: text/html; charset=UTF-8');
    readfile('/var/www/html/.errors/403.html');
    exit;
}
$username = $_SESSION['username'] ?? 'User';

$stmt = $pdo->query("SELECT path, webpath, webroles, webinterface, webname, webicon FROM enabledmodules WHERE status = 1 ORDER BY path ASC");
$modules = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->query("SELECT parameter, value FROM systemsettings");
$settings = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $settings[$row['parameter']] = $row['value'];
}

function is_port_in_use($port) {
    $connection = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1);
    if (is_resource($connection)) {
        fclose($connection);
        return true;
    }
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_login_settings'])) {
    $enabled = isset($_POST['login_banner_enabled']) ? '1' : '0';
    $title = $_POST['login_banner_title'] ?? '';
    $message = $_POST['login_banner_message'] ?? '';

    $stmt = $pdo->prepare("UPDATE systemsettings SET value = :value WHERE parameter = :parameter");
    $stmt->execute(['value' => $enabled, 'parameter' => 'login_banner_enabled']);
    $stmt->execute(['value' => $title, 'parameter' => 'login_banner_title']);
    $stmt->execute(['value' => $message, 'parameter' => 'login_banner_message']);
    
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
        echo json_encode(['status' => 'success']);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_sip_settings'])) {
    $sip_enabled = isset($_POST['sip']) ? '1' : '0';
    $udp_tcp_enabled = isset($_POST['enable_insecure_sip']) ? '1' : '0';
    $udp_tcp_port = $_POST['insecure_sip_port'] ?? '5060';
    $tls_enabled = isset($_POST['enable_secure_sip']) ? '1' : '0';
    $tls_port = $_POST['secure_sip_port'] ?? '5061';

    $old_udp_port = $settings['insecure_sip_port'] ?? '5060';
    $old_tls_port = $settings['secure_sip_port'] ?? '5061';

    $errors = [];
    if ($udp_tcp_enabled && $udp_tcp_port != $old_udp_port) {
        if (is_port_in_use($udp_tcp_port)) {
            $errors[] = "Port $udp_tcp_port is already in use.";
        }
    }
    if ($tls_enabled && $tls_port != $old_tls_port) {
        if (is_port_in_use($tls_port)) {
            $errors[] = "Port $tls_port is already in use.";
        }
    }

    if (!empty($errors)) {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
            echo json_encode(['status' => 'error', 'message' => implode(' ', $errors)]);
            exit;
        }
    } elseif (($udp_tcp_enabled && ($udp_tcp_port < 1 || $udp_tcp_port > 65535)) || 
        ($tls_enabled && ($tls_port < 1 || $tls_port > 65535))) {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
            echo json_encode(['status' => 'error', 'message' => 'Invalid port range.']);
            exit;
        }
    } else {
        $stmt = $pdo->prepare("UPDATE systemsettings SET value = :value WHERE parameter = :parameter");
        $stmt->execute(['value' => $sip_enabled, 'parameter' => 'sip']);
        $stmt->execute(['value' => $udp_tcp_enabled, 'parameter' => 'enable_insecure_sip']);
        $stmt->execute(['value' => $udp_tcp_port, 'parameter' => 'insecure_sip_port']);
        $stmt->execute(['value' => $tls_enabled, 'parameter' => 'enable_secure_sip']);
        $stmt->execute(['value' => $tls_port, 'parameter' => 'secure_sip_port']);

        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
            echo json_encode(['status' => 'success']);
            exit;
        }
    }
}

$loginBannerEnabled = ($settings['login_banner_enabled'] ?? '0') === '1';
$loginBannerTitle = $settings['login_banner_title'] ?? '';
$loginBannerMessage = $settings['login_banner_message'] ?? '';

$udpTcpEnabled = ($settings['enable_insecure_sip'] ?? '0') === '1';
$udpTcpPort = $settings['insecure_sip_port'] ?? '5060';
$tlsEnabled = ($settings['enable_secure_sip'] ?? '0') === '1';
$tlsPort = $settings['secure_sip_port'] ?? '5061';

function is_private_ip($ip) {
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
}

function get_network_info() {
    $info = [];
    $ipv4 = shell_exec("ip -4 addr show | grep inet | awk '{print $2}' | cut -d/ -f1");
    $ipv6 = shell_exec("ip -6 addr show | grep inet6 | awk '{print $2}' | cut -d/ -f1");
    $ipv4_list = array_filter(array_map('trim', explode("\n", (string)$ipv4)));
    $ipv6_list = array_filter(array_map('trim', explode("\n", (string)$ipv6)));
    $ipv4_list = array_values(array_diff($ipv4_list, ['127.0.0.1']));
    $ipv6_list = array_values(array_diff($ipv6_list, ['::1']));
    $private = [];
    $public = [];
    foreach ($ipv4_list as $ip) {
        if (is_private_ip($ip)) {
            $private[] = $ip;
        } else {
            $public[] = $ip;
        }
    }
    $dns_raw = @file_get_contents('/etc/resolv.conf');
    preg_match_all('/^nameserver\s+([^\s]+)/m', (string)$dns_raw, $dns_matches);
    $dns = $dns_matches[1] ?? [];
    $gateway = trim((string)shell_exec("ip route | grep default | awk '{print $3}'"));
    $public_ip_api = @file_get_contents('https://api.ipify.org');
    $public_ip_api = $public_ip_api ? trim($public_ip_api) : null;
    $info['private_ipv4'] = $private;
    $info['public_ipv4'] = $public;
    $info['public_detected'] = $public_ip_api;
    $info['dns'] = $dns;
    $info['gateway'] = $gateway ?: 'Unknown';
    $info['ipv6'] = $ipv6_list;
    return $info;
}

function get_system_info() {
    $info = [];
    $info['os'] = php_uname('s') . ' ' . php_uname('r');
    $info['hostname'] = php_uname('n');
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $info['cpu'] = "Information unavailable on Windows";
        $info['uptime'] = "Information unavailable on Windows";
    } else {
        $cpu = shell_exec("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2");
        $info['cpu'] = $cpu ? trim($cpu) : "Unknown CPU";
        $uptime = shell_exec("uptime -p");
        $info['uptime'] = $uptime ? trim($uptime) : "Unknown";
        $mem = shell_exec("free -m | grep Mem | awk '{print $2}'");
        $info['ram'] = $mem ? trim($mem) . " MB" : "Unknown";
    }
    $info['php_version'] = PHP_VERSION;
    return $info;
}

$sysInfo = get_system_info();
$netInfo = get_network_info();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Server Settings - Open Paging Server</title>
<link href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700&display=swap" rel="stylesheet" />
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" />
<style>
body, html { margin:0; padding:0; font-family:"Roboto",sans-serif; font-weight:300; background-color:#FFF; height:100%; }
strong { font-weight:700; }
#sidebar { width:220px; background-color:#1976D2; color:#FFF; height:100vh; position:fixed; top:0; left:0; display:flex; flex-direction:column; box-shadow:2px 0 8px rgba(0,0,0,0.2); transition:transform 0.3s ease; z-index:1200; }
@media (max-width:767px){ #sidebar{ transform:translateX(-100%); } #sidebar.open{ transform:translateX(0); } }
#sidebar h2 { text-align:center; padding:20px 0; margin:0; font-weight:500; background-color:#1565C0; font-size:1.2em; color:#FFF; }
#sidebar a,.logout-btn,.logout-btn-mobile,.admin-only{ color:#FFF; padding:12px 20px; display:block; border-bottom:1px solid rgba(255,255,255,0.1); text-decoration:none; transition:background 0.3s; font-size:0.9em; text-align:left; box-sizing:border-box; }
#sidebar a i,.logout-btn i,.logout-btn-mobile i,.admin-only i { margin-right:8px; width:20px; }
#sidebar a:hover,#sidebar a.active{ background-color:#1565C0; }
.logout-btn{ background-color:#C62828; border:none; cursor:pointer; margin-top:auto; transition:background-color 0.3s; }
.logout-btn:hover{ background-color:#B71C1C; }
.logout-btn:active{ background-color:#A51B1B; }
.logout-btn-mobile{ background-color:#C62828; border:none; cursor:pointer; transition:background-color 0.3s; display:none; }
.logout-btn-mobile:hover{ background-color:#B71C1C; }
@media(max-width:767px){ .logout-btn{ display:none; } .logout-btn-mobile{ display:block; } }
#mobile-header{ display:flex; background-color:#1565C0; color:#FFF; padding:calc(12px + env(safe-area-inset-top)) 16px 12px 16px; align-items:center; justify-content:space-between; position:fixed; top:0; left:0; right:0; z-index:1100; }
#mobile-header h2{ margin:0; font-size:1.1em; font-weight:400; color:#FFF; }
#mobile-header .hamburger{ font-size:1.5em; cursor:pointer; }
#overlay{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.3); z-index:900; }
#overlay.active{ display:block; }
#content{ margin-left:220px; padding:24px; height:100vh; overflow-y:auto; width:calc(100% - 220px); box-sizing:border-box; transition:margin-left 0.3s ease; }
@media(max-width:767px){ #content{ margin-left:0; width:100%; padding-top:70px; } }
#content h2{ color:#1976D2; margin-bottom:16px; font-weight:400; }
#content h1{ font-weight:400; }
.info-card{ background:#FFF; padding:16px; border:1px solid #EEE; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,0.1); margin-bottom:16px; }
.info-row { display:flex; justify-content:space-between; padding:10px 0; border-bottom:1px solid #f0f0f0; align-items: center; }
.info-row:last-child { border-bottom:none; }
.info-label { font-weight:500; color:#555; }
.server-image { width:300px; height:auto; margin:0 auto 24px auto; display:block; border-radius:12px; }

.tabs-container { margin-bottom: 20px; border-bottom: 1px solid #DDD; }
.tabs-desktop { display: flex; gap: 10px; }
.tab-link { padding: 10px 20px; cursor: pointer; border: 1px solid transparent; border-bottom: none; border-radius: 5px 5px 0 0; background: #f5f5f5; color: #555; transition: 0.3s; }
.tab-link.active { background: #1976D2; color: #FFF; border-color: #1976D2; }
.tabs-mobile { display: none; width: 100%; padding: 10px; border-radius: 5px; border: 1px solid #CCC; margin-bottom: 15px; font-size: 16px; }
.tab-content { display: none; }
.tab-content.active { display: block; }

.switch { position: relative; display: inline-block; width: 36px; height: 14px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 14px; }
.slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: -2px; bottom: -3px; background-color: white; transition: .4s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
input:checked + .slider { background-color: #90caf9; }
input:checked + .slider:before { transform: translateX(20px); background-color: #1976D2; }

.port-error-text { color: #F44336; font-size: 0.8em; margin-top: 4px; display: none; }
.invalid-port { border-color: #F44336 !important; background-color: rgba(244, 67, 54, 0.05) !important; }

@media(max-width:767px){
    .tabs-desktop { display: none; }
    .tabs-mobile { display: block; }
}

@media(min-width:768px){ #mobile-header{ display:none; } }
@media(prefers-color-scheme:dark){
body,html{ background-color:#121212; color:#E0E0E0; }
#sidebar{ background-color:#424242; }
#sidebar h2{ background-color:#303030; color:#FFF; }
#sidebar a,.logout-btn,.logout-btn-mobile,.admin-only{ color:#E0E0E0; }
#sidebar a.active,#sidebar a:hover{ background-color:#505050; }
#mobile-header{ background-color:#424242; }
#mobile-header h2{ color:#FFF; }
#content{ background-color:#121212; }
.info-card{ border:1px solid #333; background-color:#1E1E1E; }
h2,h3{ color:#BB86FC; }
.info-label { color:#BBB; }
.info-row { border-bottom:1px solid #333; }
.tabs-container { border-bottom-color: #333; }
.tab-link { background: #333; color: #BBB; }
.tab-link.active { background: #BB86FC; color: #000; }
.tabs-mobile { background: #1E1E1E; color: #E0E0E0; border-color: #444; }
input:checked + .slider { background-color: #3d2b52; }
input:checked + .slider:before { background-color: #BB86FC; }
.port-error-text { color: #ff5252; }
.invalid-port { border-color: #ff5252 !important; }
}

.login-settings input[type="text"],
.login-settings input[type="number"],
.login-settings select,
.login-settings textarea {
    width:100%;
    padding:10px;
    border-radius:6px;
    border:1px solid #CCC;
    font-family:inherit;
    font-size:14px;
    box-sizing:border-box;
}

.login-settings textarea {
    resize:vertical;
    min-height:80px;
}

.login-settings input:disabled,
.login-settings select:disabled,
.login-settings textarea:disabled {
    background:rgba(0,0,0,0.05);
    color:#999;
    cursor:not-allowed;
}

.login-settings button {
    background:#1976D2;
    color:#FFF;
    border:none;
    padding:10px 16px;
    border-radius:6px;
    font-size:14px;
    cursor:pointer;
}

.login-settings button:hover {
    background:#1565C0;
}

@media(prefers-color-scheme:dark){
    .login-settings input[type="text"],
    .login-settings input[type="number"],
    .login-settings select,
    .login-settings textarea {
        background:#1E1E1E;
        border:1px solid #444;
        color:#E0E0E0;
    }

    .login-settings input:disabled,
    .login-settings select:disabled,
    .login-settings textarea:disabled {
        background:#2A2A2A;
        color:#777;
    }

    .login-settings button {
        background:#BB86FC;
        color:#000;
    }

    .login-settings button:hover {
        background:#A370F7;
    }
}

#save-status, #sip-save-status { margin-left: 10px; font-size: 0.85em; transition: opacity 0.5s; }
</style>
</head>
<body>
<div id="mobile-header">
    <span class="hamburger" onclick="toggleSidebar()"><i class="fa-solid fa-bars"></i></span>
    <h2>Open Paging Server</h2>
</div>
<div id="overlay" onclick="closeSidebar()"></div>
<div id="sidebar">
    <h2>Open Paging Server</h2>
    <a href="/dashboard.php"><i class="fa-solid fa-house"></i> Dashboard</a>
    <a href="/messages.php"><i class="fa-solid fa-message"></i> Messages</a>
    <a href="/history.php"><i class="fa-solid fa-clock-rotate-left"></i> History</a>

    <?php foreach ($modules as $mod):
        if ($mod['webinterface'] != 1) continue;
        $allowedRoles = array_map('trim', explode(',', $mod['webroles']));
        if (!in_array($userRole, $allowedRoles)) continue;
        $link = htmlspecialchars($mod['webpath']);
        $name = htmlspecialchars($mod['webname']);
        $icon = htmlspecialchars($mod['webicon']) ?: 'fa-circle';
    ?>
        <a href="<?php echo $link; ?>">
            <i class="fa-solid <?php echo $icon; ?>"></i> <?php echo $name; ?>
        </a>
    <?php endforeach; ?>

    <?php if ($isAdmin): ?>
      <a href="/admin/manage-users.php" class="admin-only"><i class="fa-solid fa-users-cog"></i> Manage Users</a>
      <a href="/admin/settings.php" class="admin-only"><i class="fa-solid fa-cogs"></i> Server Settings</a>
    <?php endif; ?>
    <a href="https://docs.openpagingserver.org"><i class="fa-solid fa-book"></i> Online Documentation</a>

    <button class="logout-btn-mobile" onclick="logout()"><i class="fa-solid fa-sign-out-alt"></i> Logout</button>
    <button class="logout-btn" onclick="logout()"><i class="fa-solid fa-sign-out-alt"></i> Logout</button>
</div>

<div id="content" onclick="closeSidebarOnContentClick()">
    <h1>Settings</h1>

    <div class="tabs-container">
        <div class="tabs-desktop">
            <div class="tab-link active" onclick="openTab(event, 'general')">General</div>
            <div class="tab-link" onclick="openTab(event, 'login')">Login</div>
            <div class="tab-link" onclick="openTab(event, 'sip')">SIP</div>
            <div class="tab-link" onclick="openTab(event, 'about')">About</div>
        </div>
        <select class="tabs-mobile" onchange="openTabMobile(this.value)">
            <option value="general">General</option>
            <option value="login">Login</option>
            <option value="sip">SIP</option>
            <option value="about">About</option>
        </select>
    </div>

    <div id="general" class="tab-content active">
        <div class="info-card">
            <p>General configuration options will appear here.</p>
        </div>
    </div>

    <div id="sip" class="tab-content">
        <div class="info-card login-settings">
            <p>Open Paging Server uses Session Initiation Protocol (SIP) to integrate with PBXes and phone systems, connect to consoles, and to ATAs.</p>
            
            <form id="sipSettingsForm">

                <div class="info-row" style="border-bottom:none; padding-bottom:0;">
                    <span class="info-label">Enable SIP over UDP/TCP</span>
                    <span>
                        <label class="switch">
                            <input type="checkbox" name="enable_insecure_sip" id="udpToggle" <?= $udpTcpEnabled ? 'checked' : '' ?>>
                            <span class="slider"></span>
                        </label>
                    </span>
                </div>
                <div class="info-row" style="flex-direction: column; align-items: flex-start; gap: 8px; margin-bottom:16px;">
                    <span class="info-label">Port</span>
                    <input type="number" name="insecure_sip_port" id="udpPort" min="1" max="65535" value="<?= htmlspecialchars($udpTcpPort) ?>" <?= !$udpTcpEnabled ? 'disabled' : '' ?>>
                    <span id="udpPortError" class="port-error-text">Please enter a valid port (1-65535).</span>
                </div>

                <div class="info-row" style="border-bottom:none; padding-bottom:0;">
                    <span class="info-label">Enable SIP over TLS</span>
                    <span>
                        <label class="switch">
                            <input type="checkbox" name="enable_secure_sip" id="tlsToggle" <?= $tlsEnabled ? 'checked' : '' ?>>
                            <span class="slider"></span>
                        </label>
                    </span>
                </div>
                <div class="info-row" style="flex-direction: column; align-items: flex-start; gap: 8px;">
                    <span class="info-label">Port</span>
                    <input type="number" name="secure_sip_port" id="tlsPort" min="1" max="65535" value="<?= htmlspecialchars($tlsPort) ?>" <?= !$tlsEnabled ? 'disabled' : '' ?>>
                    <span id="tlsPortError" class="port-error-text">Please enter a valid port (1-65535).</span>
                </div>

                <input type="hidden" name="save_sip_settings" value="1">
                <div style="margin-top:20px; display:flex; align-items:center;">
                    <button type="button" id="saveSipBtn">Save SIP Settings</button>
                    <span id="sip-save-status"></span>
                </div>
            </form>
        </div>
    </div>
    
<div id="login" class="tab-content">
    <div class="info-card login-settings">

        <form id="loginSettingsForm">
            <div class="info-row">
                <span class="info-label">Enable Banner</span>
                <span>
                    <label class="switch">
                        <input type="checkbox" name="login_banner_enabled" id="bannerToggle" <?= $loginBannerEnabled ? 'checked' : '' ?>>
                        <span class="slider"></span>
                    </label>
                </span>
            </div>

            <div class="info-row" style="flex-direction: column; align-items: flex-start; gap: 8px;">
                <span class="info-label">Title</span>
                <input type="text" name="login_banner_title" id="bannerTitle" value="<?= htmlspecialchars($loginBannerTitle) ?>" <?= !$loginBannerEnabled ? 'disabled' : '' ?>>
            </div>

            <div class="info-row" style="flex-direction: column; align-items: flex-start; gap: 8px;">
                <span class="info-label">Message</span>
                <textarea name="login_banner_message" id="bannerMessage" <?= !$loginBannerEnabled ? 'disabled' : '' ?>><?= htmlspecialchars($loginBannerMessage) ?></textarea>
            </div>

            <input type="hidden" name="save_login_settings" value="1">
            <div style="margin-top:20px; display:flex; align-items:center;">
                <button type="button" id="saveLoginBtn">Save Settings</button>
                <span id="save-status"></span>
            </div>
        </form>
    </div>
</div>

    <div id="about" class="tab-content">
        <picture>
            <source srcset="/assets/OPENPAGINGSERVER-768x576-DARKMODE.png" media="(prefers-color-scheme: dark)">
            <img src="/assets/OPENPAGINGSERVER-768x576-LIGHTMODE.png" class="server-image">
        </picture>
        <p>Open Paging Sever 0.1.0</p>
        <p>Open Paging Server is provided "as is" without any warranties, express or implied, including but not limited to fitness for a particular purpose or non-infringement.</p>
        <p>Open Paging Server installs and uses several open-source software from their official sources. These components are subject to their own licenses.</p>
        <div class="info-card">
            <h2>Hardware & OS</h2>
            <div class="info-row"><span class="info-label">Hostname</span><span><?php echo htmlspecialchars($sysInfo['hostname']); ?></span></div>
            <div class="info-row"><span class="info-label">Operating System</span><span><?php echo htmlspecialchars($sysInfo['os']); ?></span></div>
            <div class="info-row"><span class="info-label">Processor</span><span><?php echo htmlspecialchars($sysInfo['cpu']); ?></span></div>
            <?php if(isset($sysInfo['ram'])): ?>
            <div class="info-row"><span class="info-label">Total Memory</span><span><?php echo htmlspecialchars($sysInfo['ram']); ?></span></div>
            <?php endif; ?>
            <div class="info-row"><span class="info-label">System Uptime</span><span><?php echo htmlspecialchars($sysInfo['uptime']); ?></span></div>
        </div>

        <div class="info-card">
            <h2>Networking</h2>
            <?php if (!empty($netInfo['private_ipv4'])): ?>
                <div class="info-row"><span class="info-label">Private IPv4</span><span><?php echo htmlspecialchars(implode(', ', $netInfo['private_ipv4'])); ?></span></div>
                <div class="info-row"><span class="info-label">Public IPv4 (Detected)</span><span><?php echo htmlspecialchars($netInfo['public_detected'] ?? 'Unknown'); ?></span></div>
            <?php else: ?>
                <div class="info-row"><span class="info-label">Public IPv4</span><span><?php echo htmlspecialchars(implode(', ', $netInfo['public_ipv4'])); ?></span></div>
            <?php endif; ?>
            <div class="info-row"><span class="info-label">Gateway</span><span><?php echo htmlspecialchars($netInfo['gateway']); ?></span></div>
            <?php if (!empty($netInfo['dns'])): ?>
            <div class="info-row"><span class="info-label">DNS Servers</span><span><?php echo htmlspecialchars(implode(', ', $netInfo['dns'])); ?></span></div>
            <?php endif; ?>
            <?php if (!empty($netInfo['ipv6'])): ?>
            <div class="info-row"><span class="info-label">IPv6 Addresses</span><span><?php echo htmlspecialchars(implode(', ', $netInfo['ipv6'])); ?></span></div>
            <?php endif; ?>
        </div>

        <div class="info-card">
            <h2>Software Environment</h2>
            <div class="info-row"><span class="info-label">PHP Version</span><span><?php echo htmlspecialchars($sysInfo['php_version']); ?></span></div>
            <div class="info-row"><span class="info-label">Web Server</span><span><?php echo htmlspecialchars($_SERVER['SERVER_SOFTWARE']); ?></span></div>
        </div>
    </div>
</div>

<script>
function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  sidebar.classList.toggle("open");
  document.getElementById("overlay").classList.toggle("active", sidebar.classList.contains("open"));
}
function closeSidebar() {
  document.getElementById("sidebar").classList.remove("open");
  document.getElementById("overlay").classList.remove("active");
}
function closeSidebarOnContentClick() {
  if (document.getElementById("sidebar").classList.contains("open")) closeSidebar();
}
function logout() {
  window.location.href = "/logout.php";
}

function openTab(evt, tabName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tab-content");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].classList.remove("active");
  }
  tablinks = document.getElementsByClassName("tab-link");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].classList.remove("active");
  }
  document.getElementById(tabName).classList.add("active");
  evt.currentTarget.classList.add("active");
  document.querySelector(".tabs-mobile").value = tabName;
}

function openTabMobile(tabName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tab-content");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].classList.remove("active");
  }
  tablinks = document.getElementsByClassName("tab-link");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].classList.remove("active");
    if(tablinks[i].innerText.toLowerCase() === tabName) {
        tablinks[i].classList.add("active");
    }
  }
  document.getElementById(tabName).classList.add("active");
}

document.addEventListener('DOMContentLoaded', function() {
    const bannerToggle = document.getElementById('bannerToggle');
    const bannerTitle = document.getElementById('bannerTitle');
    const bannerMessage = document.getElementById('bannerMessage');
    const saveBtn = document.getElementById('saveLoginBtn');
    const statusText = document.getElementById('save-status');

    if(bannerToggle){
        bannerToggle.addEventListener('change', function() {
            bannerTitle.disabled = !this.checked;
            bannerMessage.disabled = !this.checked;
        });
    }

    saveBtn.addEventListener('click', function() {
        const formData = new FormData(document.getElementById('loginSettingsForm'));
        saveBtn.disabled = true;
        statusText.innerText = "Saving...";
        statusText.style.color = "inherit";

        fetch(window.location.href, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(response => response.json())
        .then(data => {
            if(data.status === 'success') {
                statusText.innerText = "Settings saved successfully.";
                statusText.style.color = "#4CAF50";
            } else {
                statusText.innerText = "Error saving settings.";
                statusText.style.color = "#F44336";
            }
        })
        .catch(error => {
            statusText.innerText = "Connection error.";
            statusText.style.color = "#F44336";
        })
        .finally(() => {
            saveBtn.disabled = false;
            setTimeout(() => { statusText.innerText = ""; }, 3000);
        });
    });

    const udpToggle = document.getElementById('udpToggle');
    const udpPortInput = document.getElementById('udpPort');
    const udpPortError = document.getElementById('udpPortError');
    const tlsToggle = document.getElementById('tlsToggle');
    const tlsPortInput = document.getElementById('tlsPort');
    const tlsPortError = document.getElementById('tlsPortError');
    const saveSipBtn = document.getElementById('saveSipBtn');
    const sipStatusText = document.getElementById('sip-save-status');

    function validatePortInput(input, errorElement) {
        let val = parseInt(input.value);
        if (input.value === "" || isNaN(val) || val < 1 || val > 65535) {
            input.classList.add('invalid-port');
            errorElement.style.display = 'block';
            return false;
        } else {
            input.classList.remove('invalid-port');
            errorElement.style.display = 'none';
            return true;
        }
    }

    [udpPortInput, tlsPortInput].forEach(input => {
        input.addEventListener('input', function() {
            if (this.value > 65535) this.value = 65535;
            if (this.value.length > 5) this.value = this.value.slice(0, 5);
            const err = this.id === 'udpPort' ? udpPortError : tlsPortError;
            validatePortInput(this, err);
        });
    });

    if(udpToggle){
        udpToggle.addEventListener('change', function() {
            udpPortInput.disabled = !this.checked;
            if(!this.checked) {
                udpPortInput.classList.remove('invalid-port');
                udpPortError.style.display = 'none';
            } else {
                validatePortInput(udpPortInput, udpPortError);
            }
        });
    }

    if(tlsToggle){
        tlsToggle.addEventListener('change', function() {
            tlsPortInput.disabled = !this.checked;
            if(!this.checked) {
                tlsPortInput.classList.remove('invalid-port');
                tlsPortError.style.display = 'none';
            } else {
                validatePortInput(tlsPortInput, tlsPortError);
            }
        });
    }

    if(saveSipBtn){
        saveSipBtn.addEventListener('click', function() {
            let isValid = true;
            if (udpToggle.checked && !validatePortInput(udpPortInput, udpPortError)) isValid = false;
            if (tlsToggle.checked && !validatePortInput(tlsPortInput, tlsPortError)) isValid = false;

            if (!isValid) {
                sipStatusText.innerText = "Please fix port errors.";
                sipStatusText.style.color = "#F44336";
                setTimeout(() => { sipStatusText.innerText = ""; }, 3000);
                return;
            }

            const formData = new FormData(document.getElementById('sipSettingsForm'));
            saveSipBtn.disabled = true;
            sipStatusText.innerText = "Saving...";
            sipStatusText.style.color = "inherit";

            fetch(window.location.href, {
                method: 'POST',
                body: formData,
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            })
            .then(response => response.json())
            .then(data => {
                if(data.status === 'success') {
                    sipStatusText.innerText = "SIP Settings saved.";
                    sipStatusText.style.color = "#4CAF50";
                } else {
                    sipStatusText.innerText = data.message || "Error saving.";
                    sipStatusText.style.color = "#F44336";
                }
            })
            .catch(error => {
                sipStatusText.innerText = "Connection error.";
                sipStatusText.style.color = "#F44336";
            })
            .finally(() => {
                saveSipBtn.disabled = false;
                setTimeout(() => { sipStatusText.innerText = ""; }, 3000);
            });
        });
    }
    
    if(udpToggle && udpToggle.checked) validatePortInput(udpPortInput, udpPortError);
    if(tlsToggle && tlsToggle.checked) validatePortInput(tlsPortInput, tlsPortError);
});
</script>
</body>
</html>
