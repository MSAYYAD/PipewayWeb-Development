<?php
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
session_start();
include_once "config.php";
require_once 'device_fingerprint.php'; // include the fingerprint class

if(!isset($_SESSION['temp_user_id'])){
    header("Location: login_MS.php");
    exit();
}

$user_id = (int)$_SESSION['temp_user_id'];
$newIP   = $_SESSION['new_device_ip'];
$device  = $_SESSION['new_device_name'];

// ── Retrieve fingerprint passed from login_MS.php ─────────────────
$fp = DeviceFingerprint::fromSession();   

// Generate OTP only on first page load OR when "Request new code" is submitted.
// NOT on every POST — otherwise the OTP is overwritten before the comparison runs.
$otpSendError = '';
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || isset($_POST['resend_otp'])) {

    $otp = rand(100000, 999999);
    $_SESSION['otp']      = $otp;
    $_SESSION['otp_time'] = time();

    // ── Fetch user email from DB to send OTP ──────────────────────────
    $emailQuery  = mysqli_query($conn, "SELECT email, fullName FROM tbl_login WHERE id = $user_id");
    $emailRow    = mysqli_fetch_assoc($emailQuery);
    $toEmail     = $emailRow['email']    ?? '';
    $toName      = $emailRow['fullName'] ?? 'User';

    if (!empty($toEmail)) {
        $subject = 'Your Device Verification Code';

        // ── Using existing PHPMailer setup to send OTP email 
        include_once 'PHPMailer/class.phpmailer.php';
        include_once 'PHPMailer/class.smtp.php';

        $mail = new PHPMailer;
        $mail->isSMTP();
        $mail->Host      = '172.16.13.209';   // internal SMTP server
        $mail->SMTPAuth  = false;              
        $mail->Port      = 25;
        $mail->From      = 'pwadmin@aacanet.org';
        $mail->FromName  = 'Pipeway 2.0';

        $mail->addAddress($toEmail, $toName);
        $mail->Subject = $subject;
        $mail->isHTML(false);                  // plain text
        $mail->Body =
            "Dear " . $toName . ",\r\n\r\n"
          . "Your one-time password (OTP) for device verification is:\r\n\r\n"
          . "    " . $otp . "\r\n\r\n"
          . "This code is valid for 15 minutes.\r\n\r\n"
          . "If you did not request this, please contact support immediately.\r\n\r\n"
          . "Regards,\r\nPipeway 2.0";

        if (!$mail->send()) {
        $otpSendError = 'Could not send OTP email. Please try again or contact support.';
        }
    } else {
        $otpSendError = 'No email address found for your account. Please contact support.';
    }
}

// ================= GET USER DEVICES =================
$query = "SELECT FPrint FROM tbl_login WHERE id=$user_id";
$result = mysqli_query($conn,$query);
$row = mysqli_fetch_assoc($result);

$rawIPfield  = $row['FPrint'] ?? '';
//print_r($rawIPfield); // DEBUG

// Parse entries correctly regardless of old or new format
$deviceEntries = DeviceFingerprint::parseAllEntries($rawIPfield);  
$deviceCount   = count($deviceEntries);
 
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
 
    // Always split by ;; only to get the latest list of entries, then parse each entry for details.
    $latestRawList = array_values(array_filter(array_map('trim', explode(';;', $latestRaw))));
    
    // Block if limit reached but no device selected yet
    if ($currentCount >= 5 && !isset($_SESSION['remove_index'])) {
        $msg = "Please select a device to remove first";
    }
 
    // OTP valid
    elseif (
        isset($_SESSION['otp']) &&
        $_POST['otp'] == $_SESSION['otp'] &&
        //(time() - $_SESSION['otp_time']) < 300
        (time() - $_SESSION['otp_time']) < 900
    ) {
        $browser = mysqli_real_escape_string($conn, $_SERVER['HTTP_USER_AGENT']);
 
        // Get fingerprint — prefer POST (freshly computed), fall back to session
        $currentFP = DeviceFingerprint::fromPost();
        if (!DeviceFingerprint::isValid($currentFP)) {
            $currentFP = $fp; // from session (set in login_MS.php)
        }
 
        // ── CASE 1: ADD NEW DEVICE ────────────────────────────────
        if ($currentCount < 5) {
 
            $deviceLabel = trim($_POST['device_label'] ?? '');
            // if ($deviceLabel === '') $deviceLabel = 'New Device';
            /* If user left the Device Name field blank, assign a sequential
               default name based on how many devices are already registered.*/
            if ($deviceLabel === '') {
                $deviceLabel = 'Device ' . ($currentCount + 1);
            }
 
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
            // if ($deviceLabel === '') $deviceLabel = 'New Device';
            /* If user left the Device Name field blank during replacement,
               reuse the same slot number that was removed e.g. slot 3 removed → new device gets "Device 3" */
            if ($deviceLabel === '') {
                $deviceLabel = 'Device ' . ($removeIndex + 1);
            }

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
        $_SESSION['vd_error'] = "Entered Invalid OTP!";
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
    header("Location: login_MS.php");
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
    padding: 12px 20px;
    display: flex;
    align-items: center;
    gap: 12px;
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
    text-align: center; font-size: 20px; font-weight: 700;
    letter-spacing: 10px; padding: 8px 10px; color: var(--pw-navy);
}
 
/* ── Buttons ─────────────────────────────────────────────────── */
.vd-btn {
    display: inline-flex; align-items: center;
    justify-content: center; gap: 6px;
    width: 100%; padding: 9px 20px;
    font-size: 14px; font-family: var(--pw-font); font-weight: 600;
    border: none; border-radius: 4px; cursor: pointer;
    box-shadow: 0 1px 3px rgba(0,46,91,0.15);
    transition: background 0.15s, box-shadow 0.15s, transform 0.1s;
    margin-top: 4px;
}
.vd-btn:active { transform: translateY(1px); }

/* Full-width green — Save & Login (normal flow only, no sibling) */
.vd-btn-success {
    background: #2e9e68;  /* lighter professional green — less saturated than #00a65a */
    color: #fff;
    border: 1.5px solid #1ea456;             /* muted green border */
    border-radius: 4px; cursor: pointer;
}
.vd-btn-success:hover { background: #dce8f7; }

.vd-btn-primary { background: #2c5282; color: #fff; } /* lighter professional navy */
.vd-btn-primary:hover { background: #244070; }

.vd-btn-danger  { background: #c0392b; color: #fff; margin-top: 10px; } /* lighter professional red */
.vd-btn-danger:hover  { background: #a93226; }

/* ── Side-by-side button row ─────────────────────────────────────
   Used to place "Verify & Replace" and "Request new code" on the
   same line. Each button takes exactly 50% of the row width.
   gap: 8px gives a clean breathing space between them.            */
.vd-btn-row {
    display: flex;
    gap: 8px;
    margin-top: 6px;
    align-items: stretch;
}

/* When inside a .vd-btn-row, buttons share the row equally.
   Override width:100% set on .vd-btn so they don't overflow.     */
.vd-btn-row .vd-btn {
    flex: 1;          /* each button takes equal share of available width */
    width: auto;      /* override the default width:100% */
    margin-top: 0;    /* row already has margin-top:6px */
    font-size: 13px;  /* slightly smaller so both labels fit comfortably */
    padding: 9px 10px;
}

/* "Request new code" inside the row — outlined style to visually
   distinguish it from the primary action (Verify & Replace).
   Lighter, professional — feels secondary without being disabled. */
.vd-btn-row .vd-btn-resend-inline {
    flex: 1;
    width: auto;
    margin-top: 0;
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    padding: 9px 10px; font-size: 13px;
    font-family: var(--pw-font); font-weight: 600;
    color: #fff;                           /* navy text */
    background: #2c5282;                      /* very light blue-grey background */
    border: 1.5px solid #a0b4d0;             /* muted navy border */
    border-radius: 4px; cursor: pointer;
    box-shadow: 0 1px 2px rgba(0,46,91,0.08);
    transition: background 0.15s, border-color 0.15s, transform 0.1s;
}
.vd-btn-row .vd-btn-resend-inline:hover {
    background: #dce8f7;
    border-color: #2c5282;
}
.vd-btn-row .vd-btn-resend-inline:active { transform: translateY(1px); }

/* ── Countdown text below the button row ─────────────────────── */
.vd-countdown {
    text-align: center;
    font-size: 12px;
    color: var(--pw-muted);
    margin-top: 7px;
}
.vd-countdown b { color: var(--pw-navy); font-weight: 700; }
 
/* ── Alert banner ────────────────────────────────────────────── */
.vd-alert {
    display: flex; align-items: flex-start; gap: 10px;
    background: #fdf2f4; border-left: 4px solid var(--pw-crimson);
    border-radius: 3px; padding: 9px 12px; margin-bottom: 15px;
    font-size: 12px; color: var(--pw-crimson-dark); font-weight: 600;
}
.vd-alert i { flex-shrink: 0; margin-top: 1px; }
 
/* ── Error message ───────────────────────────────────────────── */
.vd-error {
    display: flex; align-items: center; gap: 8px;
    background: #fdf2f4; border: 1px solid #f5c6cb;
    border-radius: 4px; padding: 8px 11px;
    font-size: 12px; color: #721c24; margin-bottom: 12px;
}

/* ── Disabled / greyed-out submit button ─────────────────────────
   Applied by JS when OTP expires. Overrides green/navy with grey,
   prevents any click via pointer-events:none so user cannot submit
   an expired OTP even by pressing Enter or clicking rapidly.      */
.vd-btn-disabled {
    background: #adb5bd !important;
    color: #fff !important;
    cursor: not-allowed !important;
    box-shadow: none !important;
    opacity: 0.75;
    pointer-events: none;
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

/* ── Email info message ──────────────────────────────────────── */
.vd-info-msg {
    display: flex; align-items: flex-start; gap: 10px;
    background: #eaf4fb; border-left: 4px solid #2980b9;
    border-radius: 3px; padding: 11px 14px; margin-bottom: 14px;
    font-size: 13px; color: #1a5276; line-height: 1.5;
}
.vd-info-msg i { flex-shrink: 0; margin-top: 2px; color: #2980b9; }

/* ── Resend / countdown ──────────────────────────────────────── */
.vd-resend-wrap { text-align: center; margin-top: 12px; }
.vd-countdown { font-size: 12px; color: var(--pw-muted); }
.vd-countdown b { color: var(--pw-navy); }
.vd-btn-resend {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 7px 18px; font-size: 13px; font-family: var(--pw-font);
    font-weight: 600; color: var(--pw-navy);
    background: var(--pw-blue-light); border: 1px solid var(--pw-navy);
    border-radius: 4px; cursor: pointer; transition: background .15s;
    margin-top: 6px;
}
.vd-btn-resend:hover { background: #d0e4fa; }
 
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
    text-align: center; padding: 6px 18px 10px;
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
        <!--<div class="vd-meta-icon"><i class="fa <?php/* echo $faIcon; */?>"></i></div>-->
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

        <?php if (!empty($otpSendError)): ?>
        <div class="vd-error">
            <i class="fa fa-exclamation-circle"></i>
            <?php echo htmlspecialchars($otpSendError); ?>
        </div>
        <?php else: ?>
        <div class="vd-info-msg">
            <i class="fa fa-envelope"></i>
            A one time password has been sent to your email address.
            If you do not receive it, please check your junk or spam filters.
        </div>

        <!-- Countdown + Request new code — shown for OTP states (not Step 1 device list) -->
        <!-- <div class="vd-resend-wrap">
            <div class="vd-countdown" id="countdown-msg">
                Code expires in <b id="countdown-timer">15:00</b>
            </div>
            <form method="post" id="resend-form" style="display:none; margin-top:4px;">
                <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
                <button type="submit" name="resend_otp" class="vd-btn-resend">
                    <i class="fa fa-rotate-right"></i> Request new code
                </button>
            </form>
        </div>-->

        <!-- OTP display removed — OTP is now sent via email only -->

        <?php endif; ?>

        <form method="post">
            <input type="hidden" id="device_fingerprint" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
            <div class="vd-form-group">
                <label><i class="fa fa-tag"></i>&nbsp; Device Name</label>
                <input type="text" name="device_label" class="vd-input"
                       placeholder="e.g. My Work Laptop">
            </div>
            <div class="vd-form-group">
                <label><i class="fa fa-key"></i>&nbsp; One-Time Password (OTP)</label>
                <input type="text" name="otp" class="vd-input otp-input"
                       placeholder="••••••" maxlength="6" autocomplete="off" required>
            </div>
           <!-- <button type="submit" name="verify_otp" class="vd-btn vd-btn-success">
                <i class="fa fa-check-circle"></i> Save &amp; Login
            </button>-->
        </form>

        <!-- ── Countdown + Request new code ──────────────────────────
             The countdown shows remaining OTP time.
             "Request new code" is always visible (static) — user can
             request a new code at any time, not only after expiry.
             When the OTP expires, JS additionally:
               - greys out the submit button
               - replaces the timer with an expiry alert
               - sets $_SESSION['vd_error'] via a hidden POST redirect  -->

               <div class="vd-btn-row">
                <button type="submit" name="verify_otp" class="vd-btn vd-btn-success">
                    <i class="fa fa-check-circle"></i> Save &amp; Login
                </button>
                <button type="submit" name="resend_otp"
                        form="resend-form-1"
                        class="vd-btn-resend-inline">
                    <i class="fa fa-rotate-right"></i> Request new code
                </button>
            </div><!-- /vd-btn-row -->
            <!-- Hidden resend form — submitted by the button above via form= attribute -->
            <form method="post" id="resend-form-1" style="display:none;">
                <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
            </form>

            <!-- Countdown sits below both buttons, centred -->
            <div class="vd-countdown" id="countdown-msg" style="margin-top:8px;">
                Code expires in <b id="countdown-timer">15:00</b>
            </div>
            
            
        <!-- <div class="vd-resend-wrap"> -->
            <!-- Countdown text — JS updates this every second -->
            <!-- <div class="vd-countdown" id="countdown-msg">
                Code expires in <b id="countdown-timer">15:00</b>
            </div> -->

            <!-- Expiry alert — hidden initially, shown by JS when timer hits 0:00.
                 Uses the same vd-error style as the server-side flash error so it
                 looks identical to "Invalid or Expired OTP!" from $_SESSION['vd_error'] -->
            <div id="otp-expired-alert" class="vd-error" style="display:none; margin-top:7px;">
                <i class="fa fa-exclamation-circle"></i>
                Expired OTP! Please request a new code.
            </div>

            <!-- Static "Request new code" button — always visible so users
                 do not have to wait for the countdown to reach zero.
                 Submits resend_otp POST which regenerates OTP and sends new email. -->
            <!-- <form method="post" id="resend-form" style="margin-top:8px;">
                <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
                <button type="submit" name="resend_otp" class="vd-btn-resend"> -->
                    <!--<i class="fa fa-rotate-right"></i> Request new code -->
                <!-- </button>
            </form>
        </div> -->
 
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
        <?php if (!empty($otpSendError)): ?>
        <div class="vd-error">
            <i class="fa fa-exclamation-circle"></i>
            <?php echo htmlspecialchars($otpSendError); ?>
        </div>
        <?php else: ?>
        <div class="vd-info-msg">
            <i class="fa fa-envelope"></i>
            A one time password has been sent to your email address.
            If you do not receive it, please check your junk or spam filters.
        </div>
        <?php endif; ?>
        <div class="vd-section-title">
            <i class="fa fa-key"></i>&nbsp; Confirm with OTP
        </div>
        <form method="post">
            <input type="hidden" id="device_fingerprint" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
            <div class="vd-form-group">
                <label><i class="fa fa-tag"></i>&nbsp; New Device Name</label>
                <input type="text" name="device_label" class="vd-input"
                       placeholder="e.g. My Work Laptop">
            </div>
            <div class="vd-form-group">
                <label><i class="fa fa-key"></i>&nbsp; One-Time Password (OTP)</label>
                <input type="text" name="otp" class="vd-input otp-input"
                       placeholder="••••••" maxlength="6" autocomplete="off" required>
            </div>


            <!-- ── Side-by-side button row (replace flow) ────────────────
                 "Verify & Replace" primary action + "Request new code"
                 secondary outlined — equal width, same line.
                 form="resend-form-2" targets the hidden form below.     -->
            <div class="vd-btn-row">
                <button type="submit" name="verify_otp" class="vd-btn vd-btn-success">
                    <i class="fa fa-refresh"></i> Verify &amp; Replace
                </button>
                <button type="submit" name="resend_otp"
                        form="resend-form-2"
                        class="vd-btn-resend-inline">
                    <i class="fa fa-rotate-right"></i> Request new code
                </button>
            </div><!-- /vd-btn-row -->

            <!-- Hidden resend form — submitted by the button above via form= attribute -->
            <form method="post" id="resend-form-2" style="display:none;">
                <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
            </form>

            <!-- Countdown below both buttons, centred -->
            <div class="vd-countdown" id="countdown-msg" style="margin-top:8px;">
                Code expires in <b id="countdown-timer">15:00</b>
            </div>

            <!-- Expiry alert — hidden initially, shown by JS when timer hits 0:00.
                 Uses the same vd-error styling as $_SESSION['vd_error'] flash errors
                 so the expiry message looks identical to server-side OTP errors. -->
            <div id="otp-expired-alert" class="vd-error" style="display:none; margin-top:7px;">
                <i class="fa fa-exclamation-circle"></i>
                Expired OTP! Please request a new code.
            </div>
            </form>
        <?php endif; ?>

        <!-- Hidden resend form — OUTSIDE all other forms -->
        <form method="post" id="resend-form-2" style="display:none;">
            <input type="hidden" name="resend_otp" value="1">
            <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
        </form>


            <!-- Countdown + Request new code — shown for OTP states (not Step 1 device list) -->
        
            <!-- <div class="vd-resend-wrap">
            <div class="vd-countdown" id="countdown-msg">
                Code expires in <b id="countdown-timer">15:00</b>
            </div>
            <form method="post" id="resend-form" style="display:none; margin-top:4px;">
                <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>"> -->
                <!--<button type="submit" name="resend_otp" class="vd-btn-resend">
                    <i class="fa fa-rotate-right"></i> Request new code
                </button>-->
            <!-- </form>
            </div>-->
        <!-- OTP display removed — OTP is now sent via email only -->

            <!-- <button type="submit" name="verify_otp" class="vd-btn vd-btn-success">
                <i class="fa fa-refresh"></i> Verify &amp; Replace
            </button>
        </form>
        <?php //endif; ?> -->

        <!-- ── Countdown + Request new code (shared by both OTP flows) ──
             Shown for normal flow and replace-device flow.
             Not shown during Step 1 device selection (no OTP needed there). -->
        <!-- <div class="vd-resend-wrap"> -->
            <!-- Countdown text — JS updates this every second -->
            <!-- <div class="vd-countdown" id="countdown-msg">
                Code expires in <b id="countdown-timer">15:00</b>
            </div> -->

            <!-- Expiry alert — hidden initially, shown by JS when timer hits 0:00.
                 Uses the same vd-error styling as $_SESSION['vd_error'] flash errors
                 so the expiry message looks identical to server-side OTP errors. -->
            <!-- <div id="otp-expired-alert" class="vd-error" style="display:none; margin-top:8px;">
                <i class="fa fa-exclamation-circle"></i>
                Expired OTP! Please request a new code below.
            </div> -->

            <!-- Static "Request new code" button — always visible.
                 User can request a fresh code at any time without waiting for expiry. -->
            <!-- <form method="post" id="resend-form" style="margin-top:8px;">
                <input type="hidden" name="device_fingerprint" value="<?php echo $fpForForm; ?>">
                <button type="submit" name="resend_otp" class="vd-btn-resend"> -->
                    <!--<i class="fa fa-rotate-right"></i> Request new code-->
                <!-- </button>
            </form>
        </div> -->
 
        <!-- Cancel always visible -->
        <form method="post">
            <button type="submit" name="reject" class="vd-btn vd-btn-danger">
                <i class="fa fa-times-circle"></i> Cancel
            </button>
        </form>
 
    </div><!-- /vd-body -->
 
    <!-- OTP Testing hint — REMOVE IN PRODUCTION -->
    <?php /*if (isset($_SESSION['otp'])): */?>
    <!-- <div class="vd-otp-hint">
        OTP <br> (testing only — remove in production) 
        <span> if (isset($_SESSION['otp'])): </span>
    </div>
    <br> -->
    <?php /*endif;*/ ?>
 
    <div class="vd-footer">
        <i class="fa fa-shield"></i>&nbsp; This device will be securely registered to your account.
    </div>
 
</div><!-- /vd-card -->
 
<script src="js/DeviceFingerprint.js"></script>
<script>
  DeviceFingerprint.init('device_fingerprint');
  // ── OTP countdown timer ──────────────────────────────────────────
  // Uses server-issued timestamp so refreshing never resets the clock.
  // When it hits 0, hides the countdown and shows "Request new code".
  (function () {

    var otpIssuedAt   = <?php echo (int)($_SESSION['otp_time'] ?? time()); ?>;
    var expirySeconds = 900;

    var timerEl      = document.getElementById('countdown-timer');
    var countdownMsg = document.getElementById('countdown-msg');
    var expiredAlert = document.getElementById('otp-expired-alert');

    if (!timerEl) return;

    function disableSubmitButtons() {
      // Select ALL buttons with name="verify_otp" — covers both flows
      var btns = document.querySelectorAll('button[name="verify_otp"]');
      btns.forEach(function (btn) {
        btn.disabled = true;
        btn.classList.add('vd-btn-disabled');
      });
    }

    function tick() {
      var elapsed   = Math.floor(Date.now() / 1000) - otpIssuedAt;
      var remaining = expirySeconds - elapsed;

      if (remaining <= 0) {
        disableSubmitButtons();
        if (countdownMsg) countdownMsg.style.display = 'none';
        if (expiredAlert) expiredAlert.style.display = 'flex';
        return;
      }

      var mins = Math.floor(remaining / 60);
      var secs = remaining % 60;
      timerEl.textContent = mins + ':' + (secs < 10 ? '0' : '') + secs;

      setTimeout(tick, 1000);
    }

    tick();

  })();
</script>
</body>
</html>
 