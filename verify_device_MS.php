/** 
* Developer: Muskan Sayyed
* Description: It is a device verification system designed to manage and secure user devices for an account. 
*              It allows users to register up to 5 devices, and if the limit is reached, 
*              they must select an existing device to remove before adding a new one. 
*              The system uses OTP verification to ensure that only authorized users can add or replace devices. 
*              It also captures browser information and generates a unique fingerprint for each device, 
*              which is stored in the database and used for authentication.
*
*               
* Created on: 15-05-2026
*
* CHANGELOG:
*----------------------------------------------------------------------------
* Version | Date       | Author              | Description
* ----------------------------------------------------------------------------
* ----------------------------------------------------------------------------
*
*-----------------------------------------------------------------------------
*/
<?php
session_start();
include_once "config.php";
require_once 'device_fingerprint.php'; // include the fingerprint class

if(!isset($_SESSION['temp_user_id'])){
    header("Location: login_1_MS.php");
    exit();
}

$user_id = (int)$_SESSION['temp_user_id'];
$newIP   = $_SESSION['new_device_ip'];
$device  = $_SESSION['new_device_name'];

// ── Retrieve fingerprint passed from login_1_MS.php ─────────────────
$fp = DeviceFingerprint::fromSession();   

// Generate OTP only on first page load — NOT on form submit.
// If generated on every load, the session OTP gets replaced before
// the verify_otp check runs, causing "Invalid or Expired OTP" every time.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $_SESSION['otp']      = rand(100000, 999999);
    $_SESSION['otp_time'] = time();
}

$msg = "";

// ================= GET USER DEVICES =================
$query = "SELECT FPrint FROM tbl_login WHERE id=$user_id";
$result = mysqli_query($conn,$query);
$row = mysqli_fetch_assoc($result);

$rawIPfield  = $row['FPrint'] ?? '';
//print_r($rawIPfield); // DEBUG

// Parse entries correctly regardless of old or new format
$deviceEntries = DeviceFingerprint::parseAllEntries($rawIPfield);  
$deviceCount   = count($deviceEntries);
 
// Keep raw strings in same order for display & removal
//if (strpos($rawIPfield, ';;') !== false) {
//    $rawList = array_values(array_filter(array_map('trim', explode(';;', $rawIPfield))));
//} else {
//    $rawList = array_values(array_filter(array_map('trim', explode(',', $rawIPfield))));
//}
$rawList = array_values(array_filter(array_map('trim', explode(';;', $rawIPfield))));

// ================= VERIFY OTP =================
if(isset($_POST['verify_otp'])){

    // 🔁 ALWAYS RECHECK FROM DB
    $check = mysqli_query($conn, "SELECT FPrint FROM tbl_login WHERE id=$user_id");
    $data  = mysqli_fetch_assoc($check);
    $latestRaw  = $data['FPrint'] ?? '';

    // Parse fresh from DB
    $latestParsed = DeviceFingerprint::parseAllEntries($latestRaw);
    $currentCount = count($latestParsed);
    //Echo "Current count: " . $currentCount; // DEBUG
    //exit();
 
    //if (strpos($latestRaw, ';;') !== false) {
    //    $latestRawList = array_values(array_filter(array_map('trim', explode(';;', $latestRaw))));
    //} else {
    //    $latestRawList = array_values(array_filter(array_map('trim', explode(',', $latestRaw))));
    //}
    // Always split by ;; only — same reason as rawList above
    $latestRawList = array_values(array_filter(array_map('trim', explode(';;', $latestRaw))));
    
    // Block if limit reached but no device selected yet
    if ($currentCount >= 5 && !isset($_SESSION['remove_index'])) {
        $msg = "Please select a device to remove first";
    }
 
    // OTP valid
    elseif (
        isset($_SESSION['otp']) &&
        $_POST['otp'] == $_SESSION['otp'] &&
        (time() - $_SESSION['otp_time']) < 300
    ) {
        $browser = mysqli_real_escape_string($conn, $_SERVER['HTTP_USER_AGENT']);
 
        // Get fingerprint — prefer POST (freshly computed), fall back to session
        $currentFP = DeviceFingerprint::fromPost();
        if (!DeviceFingerprint::isValid($currentFP)) {
            $currentFP = $fp; // from session (set in login_1_MS.php)
        }
 
        // ── CASE 1: ADD NEW DEVICE ────────────────────────────────
        if ($currentCount < 5) {
 
            $deviceLabel = trim($_POST['device_label'] ?? '');
            if ($deviceLabel === '') $deviceLabel = 'New Device';
 
            // buildEntry() creates "IP|Label|UA|Token|FP" — clean, consistent
            $newRawEntry = DeviceFingerprint::buildEntry($newIP, $deviceLabel, $browser, $currentFP);
            $latestRawList[] = $newRawEntry;
            $deviceCount = $currentCount + 1;
        }
 
        // ── CASE 2: REPLACE DEVICE ───────────────────────────────
        else {
            $removeIndex = (int)$_SESSION['remove_index'];
            if (isset($latestRawList[$removeIndex])) {
                array_splice($latestRawList, $removeIndex, 1);
            }
            $deviceLabel = trim($_POST['device_label'] ?? '');
            if ($deviceLabel === '') $deviceLabel = 'New Device';
            $newRawEntry = DeviceFingerprint::buildEntry($newIP, $deviceLabel, $browser, $currentFP);
            $latestRawList[] = $newRawEntry;
        }
 
        // Serialize ALL entries with consistent ;; delimiter
        $updatedIPs = DeviceFingerprint::serializeEntries($latestRawList);  
 
        // Token to store in DB and cookie
        $token = DeviceFingerprint::isValid($currentFP)
            ? DeviceFingerprint::generateToken($currentFP)
            : bin2hex(random_bytes(16));

            // ECHO "Token generated: " . $token; // DEBUG
 
        $usedOTP     = $_SESSION['otp'];
        $OTPusedTime = $_SESSION['otp_time'];
 
        mysqli_query($conn, "UPDATE tbl_login
            SET FPrint = '" . mysqli_real_escape_string($conn, $updatedIPs) . "',
                Token     = '" . mysqli_real_escape_string($conn, $token) . "',
                OTP       = '" . mysqli_real_escape_string($conn, $usedOTP) . "',
                OTPCount  = '$deviceCount',
                OTPTime   = '" . mysqli_real_escape_string($conn, $OTPusedTime) . "'
            WHERE id = " . $user_id);
 
        // Set cookie — 1 year (safe because token is derived, not random)
        DeviceFingerprint::setCookie($token);                               
 
        // Clear session
        unset(
            $_SESSION['otp'], $_SESSION['otp_time'], $_SESSION['remove_index'],
            $_SESSION['temp_user_id'], $_SESSION['new_device_ip'],
            $_SESSION['new_device_name'], $_SESSION['device_fingerprint']
        );
 
        header("Location: inventory_layout");
        exit();
 
    } else {
        //$msg = "Invalid or Expired OTP!"; // Not getting cleared on page reload, so moved to session to show only once
        $_SESSION['vd_error'] = "Invalid or Expired OTP!";
        header("Location: verify_device_MS.php");
        exit();
    }
}
 
 
// ═══════════════════════════════════════════
//  SELECT DEVICE TO REMOVE
// ═══════════════════════════════════════════
if (isset($_POST['select_device'])) {
    if (!isset($_POST['device_index'])) {
        $msg = "Please select a device";
    } else {
        $_SESSION['remove_index'] = (int)$_POST['device_index'];
    }
}
 
 
// ═══════════════════════════════════════════
//  REJECT / CANCEL
// ═══════════════════════════════════════════
if (isset($_POST['reject'])) {
    session_destroy();
    header("Location: login_1_MS.php");
    exit();
}
 
// Fingerprint value to pre-fill hidden inputs in HTML
$fpForForm = htmlspecialchars(DeviceFingerprint::fromSession());
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device Verification | Pipeway</title>
<link rel="shortcut icon" href="img/fevicon.ico">
<link rel="stylesheet" href="css/PSnnect.min.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
/* ── Pipeway Design Tokens ───────────────────────────────────── */
:root {
    --pw-navy:         #002e5b;
    --pw-crimson:      #BB133E;
    --pw-crimson-dark: #96102f;
    --pw-blue-light:   #e8f0fe;
    --pw-green:        #00a65a;
    --pw-green-dark:   #008d4c;
    --pw-border:       #d2d6de;
    --pw-text:         #333;
    --pw-muted:        #777;
    --pw-font:         'Source Sans Pro', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
}
 
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
 
html {
    background: linear-gradient(135deg, #BB133E 0%, #002e5b 100%);
    min-height: 100vh;
}
body {
    /* font-family: var(--pw-font);*/
    font-family:'Manrope',sans-serif;
    font-size: 14px;
    color: var(--pw-text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 30px 16px;
    background: transparent;
}
 
/* ── Card ────────────────────────────────────────────────────── */
.vd-card {
    background: #fff;
    width: 100%;
    max-width: 460px;
    border-radius: 6px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.22);
    overflow: hidden;
}
 
/* ── Header ─────────────────────────────────────────────────── */
.vd-header {
    background: var(--pw-navy);
    padding: 18px 24px;
    display: flex;
    align-items: center;
    gap: 13px;
}
.vd-header-icon {
    width: 40px; height: 40px;
    background: var(--pw-crimson);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
}
.vd-header-icon i { color: #fff; font-size: 17  px; }
.vd-header-text h2 {
    color: #fff; font-size: 18px;
    font-weight: 600; letter-spacing: 0.2px; line-height: 1.2;
}
.vd-header-text p { color: rgba(255,255,255,0.6); font-size: 12px; margin-top: 2px; }
 
/* ── Device Slot Bar ─────────────────────────────────────────── */
.vd-slots {
    background: var(--pw-blue-light);
    border-bottom: 1px solid var(--pw-border);
    padding: 11px 24px;
    display: flex; align-items: center; justify-content: space-between;
}
.vd-slots-label {
    font-size: 11px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.5px; color: var(--pw-muted);
}
.vd-slots-right { display: flex; align-items: center; gap: 5px; }
.vd-slot-pip {
    width: 24px; height: 8px; border-radius: 4px;
    background: var(--pw-border); transition: background 0.2s;
}
.vd-slot-pip.used      { background: var(--pw-navy); }
.vd-slot-pip.used.full { background: var(--pw-crimson); }
.vd-slots-text { font-size: 12px; color: var(--pw-muted); margin-left: 5px; }
.vd-slots-text b { color: var(--pw-text); }
 
/* ── Browser Meta Row ────────────────────────────────────────── */
.vd-meta {
    padding: 14px 24px 0;
    display: flex; align-items: center; gap: 12px;
}
.vd-meta-icon { color: var(--pw-navy); font-size: 24px; flex-shrink: 0; }
.vd-meta-label {
    font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--pw-muted);
}
.vd-meta-value { font-size: 13px; font-weight: 700; color: var(--pw-navy); }
 
/* ── Body ────────────────────────────────────────────────────── */
.vd-body { padding: 20px 24px 20px; }
 
.vd-section-title {
    font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.6px; color: var(--pw-muted);
    margin-bottom: 12px; padding-bottom: 7px;
    border-bottom: 1px solid var(--pw-border);
}
 
/* ── Form Controls ───────────────────────────────────────────── */
.vd-form-group { margin-bottom: 13px; }
.vd-form-group label {
    display: block; font-size: 11px; font-weight: 700;
    color: var(--pw-muted); margin-bottom: 5px;
    text-transform: uppercase; letter-spacing: 0.4px;
}
.vd-input {
    width: 100%; padding: 8px 12px; font-size: 14px;
    font-family: var(--pw-font); color: var(--pw-text);
    background: var(--pw-blue-light);
    border: 1px solid var(--pw-border); border-radius: 4px;
    outline: none; transition: border-color 0.2s, box-shadow 0.2s;
}
.vd-input:focus {
    border-color: var(--pw-navy);
    box-shadow: 0 0 0 2px rgba(0,46,91,0.12);
    background: #fff;
}
.vd-input::placeholder { color: #aaa; }
.vd-input.otp-input {
    text-align: center; font-size: 26px; font-weight: 700;
    letter-spacing: 10px; padding: 10px 12px; color: var(--pw-navy);
}
 
/* ── Buttons ─────────────────────────────────────────────────── */
.vd-btn {
    display: inline-flex; align-items: center;
    justify-content: center; gap: 7px;
    width: 100%; padding: 9px 20px;
    font-size: 14px; font-family: var(--pw-font); font-weight: 600;
    border: none; border-radius: 4px; cursor: pointer;
    box-shadow: 2px 2px 3px rgba(0,46,91,0.22);
    transition: background 0.15s, transform 0.1s;
    margin-top: 4px;
}
.vd-btn:active { transform: translateY(1px); }
.vd-btn-success { background: var(--pw-green);   color: #fff; }
.vd-btn-success:hover { background: var(--pw-green-dark); }
.vd-btn-primary { background: var(--pw-navy);    color: #fff; }
.vd-btn-primary:hover { background: #003d7a; }
.vd-btn-danger  { background: var(--pw-crimson); color: #fff; margin-top: 10px; }
.vd-btn-danger:hover  { background: var(--pw-crimson-dark); }
 
/* ── Alert banner ────────────────────────────────────────────── */
.vd-alert {
    display: flex; align-items: flex-start; gap: 10px;
    background: #fdf2f4; border-left: 4px solid var(--pw-crimson);
    border-radius: 3px; padding: 11px 14px; margin-bottom: 15px;
    font-size: 13px; color: var(--pw-crimson-dark); font-weight: 600;
}
.vd-alert i { flex-shrink: 0; margin-top: 1px; }
 
/* ── Error message ───────────────────────────────────────────── */
.vd-error {
    display: flex; align-items: center; gap: 8px;
    background: #fdf2f4; border: 1px solid #f5c6cb;
    border-radius: 4px; padding: 9px 12px;
    font-size: 13px; color: #721c24; margin-bottom: 14px;
}
 
/* ── Device Radio List ───────────────────────────────────────── */
.vd-device-list { list-style: none; margin-bottom: 13px; }
.vd-device-item {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px; border: 1px solid var(--pw-border);
    border-radius: 4px; margin-bottom: 7px; cursor: pointer;
    transition: border-color 0.15s, background 0.15s; width: 100%;
}
.vd-device-item:hover { border-color: var(--pw-navy); background: #f0f4fb; }
.vd-device-item input[type="radio"] {
    accent-color: var(--pw-navy); width: 15px; height: 15px; flex-shrink: 0;
}
.vd-device-item-icon { color: var(--pw-navy); font-size: 15px; flex-shrink: 0; }
.vd-device-item-name { font-size: 13px; font-weight: 600; color: var(--pw-text); }
 
/* ── OTP Testing Hint ────────────────────────────────────────── */
.vd-otp-hint {
    text-align: center; padding: 0 24px 4px;
    font-size: 11px; color: #888;
}
.vd-otp-hint span {
    display: inline-block; margin-top: 5px;
    background: var(--pw-blue-light);
    border: 1px dashed var(--pw-navy);
    color: var(--pw-navy); font-weight: 700;
    font-size: 20px; padding: 4px 20px;
    border-radius: 4px; letter-spacing: 5px;
}
 
/* ── Footer ──────────────────────────────────────────────────── */
.vd-footer {
    text-align: center; padding: 8px 24px 18px;
    font-size: 11px; color: var(--pw-muted);
}
</style>
</head>
 
<body>
 
<?php
$deviceLimit = 5;
$isFull      = ($deviceCount >= $deviceLimit);
$showStep2   = $isFull && isset($_SESSION['remove_index']);
 
// Pick FontAwesome browser icon from the browser name
$bl = strtolower($device);
if     (strpos($bl, 'edge')    !== false) $faIcon = 'fa-edge';
elseif (strpos($bl, 'firefox') !== false) $faIcon = 'fa-firefox';
elseif (strpos($bl, 'safari')  !== false) $faIcon = 'fa-safari';
elseif (strpos($bl, 'opera')   !== false) $faIcon = 'fa-opera';
else                                      $faIcon = 'fa-chrome';
?>
 
<div class="vd-card">
 
    <!-- Header -->
    <div class="vd-header">
       <!-- <div class="vd-header-icon"><i class="fa fa-lock"></i></div> -->
        <div class="vd-header-text">
            <h2>Device Verification</h2>
            <p>Verify your identity to register this device</p>
        </div>
    </div>

    <!-- Registered Devices Slot Bar -->
<div class="vd-slots">
    <span class="vd-slots-label">Registered Devices</span>
    <span class="vd-slots-text"><b><?php echo $deviceCount; ?></b> / <?php echo $deviceLimit; ?></span>
</div>
 
    <!-- Registered Devices Slot Bar -->
    <!-- <div class="vd-slots">
        <span class="vd-slots-label">Registered Devices</span>
        <div class="vd-slots-right"> 
            <?php for ($i = 0; $i < $deviceLimit; $i++): ?>
                <div class="vd-slot-pip 
                 <?php
                   /* if ($i < $deviceCount) echo $isFull ? 'used full' : 'used'; */
                ?>">  </div> 
            <?php endfor; ?>
            <span class="vd-slots-text"><b><?php echo $deviceCount; ?></b> / <?php echo $deviceLimit; ?></span>
        </div> 
    </div> -->
 
    <!-- Browser Info (IP removed as requested) -->
    <div class="vd-meta">
        <div class="vd-meta-icon"><i class="fa <?php echo $faIcon; ?>"></i></div>
        <div>
            <div class="vd-meta-label">Detected Browser</div>
            <div class="vd-meta-value"><?php echo htmlspecialchars($device); ?></div>
        </div>
    </div>
 
    <!-- Body -->
    <div class="vd-body">
 
        <?php if (!empty($_SESSION['vd_error'])): ?> 
        <div class="vd-error">
            <i class="fa fa-exclamation-circle"></i>
            <?php echo htmlspecialchars($_SESSION['vd_error']); ?>
        </div>
        <?php endif; ?>
 
        <?php if (!$isFull): ?>
        <!-- ══ NORMAL FLOW ═══════════════════════════════════════ -->
        <div class="vd-section-title">
            <i class="fa fa-plus-circle"></i>&nbsp; Register New Device
        </div>
        <form method="post">
            <input type="hidden" id="device_fingerprint" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
            <div class="vd-form-group">
                <label><i class="fa fa-tag"></i>&nbsp; Device Name</label>
                <input type="text" name="device_label" class="vd-input"
                       placeholder="e.g. My Work Laptop" required>
            </div>
            <div class="vd-form-group">
                <label><i class="fa fa-key"></i>&nbsp; One-Time Password (OTP)</label>
                <input type="text" name="otp" class="vd-input otp-input"
                       placeholder="••••••" maxlength="6" autocomplete="off" required>
            </div>
            <button type="submit" name="verify_otp" class="vd-btn vd-btn-success">
                <i class="fa fa-check-circle"></i> Save &amp; Login
            </button>
        </form>
 
        <?php elseif (!$showStep2): ?>
        <!-- ══ LIMIT REACHED — Step 1: Pick device to remove ════ -->
        <div class="vd-alert">
            <i class="fa fa-exclamation-triangle"></i>
            Device limit of <?php echo $deviceLimit; ?> reached. Remove one to continue.
        </div>
        <div class="vd-section-title">
            <i class="fa fa-trash-o"></i>&nbsp; Select Device to Remove
        </div>
        <form method="post">
            <ul class="vd-device-list">
                <?php foreach ($deviceEntries as $index => $parsed): ?>
                <li>
                    <label class="vd-device-item">
                        <input type="radio" name="device_index"
                               value="<?php echo $index; ?>" required>
                        <span class="vd-device-item-icon"><i class="fa fa-desktop"></i></span>
                        <span class="vd-device-item-name">
                            <?php echo htmlspecialchars($parsed['label'] ?: 'Unknown Device'); ?>
                        </span>
                    </label>
                </li>
                <?php endforeach; ?>
            </ul>
            <button type="submit" name="select_device" class="vd-btn vd-btn-primary">
                <i class="fa fa-arrow-right"></i> Continue
            </button>
        </form>
 
        <?php else: ?>
        <!-- ══ LIMIT REACHED — Step 2: OTP to confirm replace ═══ -->
        <div class="vd-alert">
            <i class="fa fa-info-circle"></i>
            Enter OTP to confirm replacement of the selected device.
        </div>
        <div class="vd-section-title">
            <i class="fa fa-key"></i>&nbsp; Confirm with OTP
        </div>
        <form method="post">
            <input type="hidden" id="device_fingerprint" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
            <div class="vd-form-group">
                <label><i class="fa fa-tag"></i>&nbsp; New Device Name</label>
                <input type="text" name="device_label" class="vd-input"
                       placeholder="e.g. My Work Laptop" required>
            </div>
            <div class="vd-form-group">
                <label><i class="fa fa-key"></i>&nbsp; One-Time Password (OTP)</label>
                <input type="text" name="otp" class="vd-input otp-input"
                       placeholder="••••••" maxlength="6" autocomplete="off" required>
            </div>
            <button type="submit" name="verify_otp" class="vd-btn vd-btn-success">
                <i class="fa fa-refresh"></i> Verify &amp; Replace
            </button>
        </form>
        <?php endif; ?>
 
        <!-- Cancel always visible -->
        <form method="post">
            <button type="submit" name="reject" class="vd-btn vd-btn-danger">
                <i class="fa fa-times-circle"></i> Cancel
            </button>
        </form>
 
    </div><!-- /vd-body -->
 
    <!-- OTP Testing hint — REMOVE IN PRODUCTION -->
    <?php if (isset($_SESSION['otp'])): ?>
    <div class="vd-otp-hint">
        OTP <br> <!--(testing only — remove in production) -->
        <span><?php echo $_SESSION['otp']; ?></span>
    </div>
    <br>
    <?php endif; ?>
 
    <div class="vd-footer">
        <i class="fa fa-shield"></i>&nbsp; This device will be securely registered to your account.
    </div>
 
</div><!-- /vd-card -->
 
<script src="js/DeviceFingerprint.js"></script>
<script>
  DeviceFingerprint.init('device_fingerprint');
</script>
</body>
</html>
 