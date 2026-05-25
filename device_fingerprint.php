<?php
/**
 * device_fingerprint.php
 * ════════════════════════════════════════════════════════════════
 * Single include file. Drop into your project root.
 *
 *   require_once 'device_fingerprint.php';
 *
 * ── ENTRY FORMAT (what is stored in tbl_login.IPaddress) ─────────
 *
 *   Multiple devices are separated by  ;;  (double semicolon)
 *   Fields inside one entry are separated by  |  (pipe)
 *
 *   Full string example (2 devices):
 *     IP1|Label1|UA1|Token1|FP1;;IP2|Label2|UA2|Token2|FP2
 *
 *   This replaces the old broken format that mixed @ and , and
 *   caused the token to always be in the wrong array position.
 *
 * ── TOKEN DESIGN ─────────────────────────────────────────────────
 *
 *   Token = HMAC-SHA256(fingerprint, SERVER_SECRET)
 *
 *   Because the token is DERIVED from stable browser signals,
 *   it never expires. Even if the cookie is cleared, the next
 *   login computes the same fingerprint → same token → match found
 *   in DB → user is recognized without OTP.
 *
 * ── BACKWARD COMPATIBILITY ───────────────────────────────────────
 *
 *   Old entries in the DB used @ and , as delimiters.
 *   DeviceFingerprint::parseAllEntries() handles both old and new
 *   format so existing registered devices are not broken.
 *
 * ════════════════════════════════════════════════════════════════
 */
class DeviceFingerprint
{
    /** Change this to a unique secret for your app.
     *  Generate: php -r "echo bin2hex(random_bytes(32));"
     */
    const SECRET = 'REPLACE_WITH_YOUR_OWN_SECRET_MIN_32_CHARS';

    /** Delimiter between device entries in the IPaddress field */
    const ENTRY_SEP = ';;';

    // ══════════════════════════════════════════════════════════════
    //  TOKEN  (deterministic — same FP always → same token)
    // ══════════════════════════════════════════════════════════════

    public static function generateToken(string $fp): string
    {
        return hash_hmac('sha256', $fp, self::SECRET);
    }

    // ══════════════════════════════════════════════════════════════
    //  INPUT HELPERS
    // ══════════════════════════════════════════════════════════════

    /** Get fingerprint from login/OTP form POST */
    public static function fromPost(): string
    {
        $fp = trim($_POST['device_fingerprint'] ?? '');
        return self::isValid($fp) ? $fp : '';
    }

    /** Save fingerprint to session (login_1.php → verify_device.php) */
    public static function saveToSession(string $fp): void
    {
        if (self::isValid($fp)) $_SESSION['device_fingerprint'] = $fp;
    }

    /** Retrieve fingerprint from session */
    public static function fromSession(): string
    {
        $fp = $_SESSION['device_fingerprint'] ?? '';
        return self::isValid($fp) ? $fp : '';
    }

    // ══════════════════════════════════════════════════════════════
    //  DEVICE MATCHING  (call this in login_1.php foreach)
    // ══════════════════════════════════════════════════════════════

    /**
     * Returns true if the incoming browser matches a stored entry.
     *
     * Priority:
     *   1. Fingerprint  — never expires, survives cookie loss & IP change
     *   2. Cookie token — works while the cookie is alive
     *   3. IP + UA      — legacy fallback for old entries without FP
     */
    public static function isKnownDevice(
        array  $entry,        // result of parseEntry()
        string $fp,           // fromPost()
        string $cookieToken,  // $_COOKIE['device_token'] ?? ''
        string $ip,
        string $userAgent
    ): bool {
        // 1. Fingerprint match
        if ($fp !== '' && $entry['fp'] !== ''
            && hash_equals($entry['fp'], $fp)) {
            return true;
        }

        // 2. Cookie token match
        if ($cookieToken !== '' && $entry['token'] !== ''
            && hash_equals($entry['token'], $cookieToken)) {
            return true;
        }

        // 3. Legacy IP + UA match (for old entries with no FP stored)
        if ($cookieToken === '' && $entry['fp'] === ''
            && $entry['ip'] === $ip
            && $entry['ua'] === $userAgent) {
            return true;
        }

        return false;
    }

    // ══════════════════════════════════════════════════════════════
    //  ENTRY PARSING
    // ══════════════════════════════════════════════════════════════

    /**
     * Parse ALL device entries from tbl_login.IPaddress.
     * Handles BOTH old format (@ / , mixed) and new format (;;).
     *
     * Returns array of parsed entry arrays.
     */
    public static function parseAllEntries(string $raw): array
    {
        if (trim($raw) === '') return [];

        // Detect format: new format contains ;;
        if (strpos($raw, self::ENTRY_SEP) !== false) {
            $chunks = explode(self::ENTRY_SEP, $raw);
        } else {
            // OLD FORMAT: entries were stored as
            //   IP|Label|UA@token,IP|Label|UA@token,...
            // Split by comma to get each old entry chunk
            $chunks = explode(',', $raw);
        }

        $entries = [];
        foreach ($chunks as $chunk) {
            $chunk = trim($chunk);
            if ($chunk === '') continue;
            $parsed = self::parseEntry($chunk);
            if ($parsed !== null) $entries[] = $parsed;
        }
        return $entries;
    }

    /**
     * Parse one raw entry string into named fields.
     * Returns null if the string is empty/garbage.
     *
     * New format: IP|Label|UA|Token|FP
     * Old format: IP|Label|UA@Token   (token was after @)
     */
    public static function parseEntry(string $chunk): ?array
    {
        if ($chunk === '') return null;

        // New format uses | for all 5 fields
        $parts = explode('|', $chunk);

        if (count($parts) >= 4) {
            // New format: IP|Label|UA|Token|FP
            return [
                'ip'    => trim($parts[0]),
                'label' => trim($parts[1]),
                'ua'    => trim($parts[2]),
                'token' => trim($parts[3]),
                'fp'    => trim($parts[4] ?? ''),
            ];
        }

        // Old format: "IP|Label|UA@Token" — token is after @
        if (count($parts) === 3) {
            $uaAndToken = explode('@', $parts[2], 2);
            return [
                'ip'    => trim($parts[0]),
                'label' => trim($parts[1]),
                'ua'    => trim($uaAndToken[0]),
                'token' => trim($uaAndToken[1] ?? ''),
                'fp'    => '',
            ];
        }

        // Very old / unknown format — try best-effort
        $uaAndToken = explode('@', $chunk, 2);
        return [
            'ip'    => '',
            'label' => '',
            'ua'    => trim($uaAndToken[0]),
            'token' => trim($uaAndToken[1] ?? ''),
            'fp'    => '',
        ];
    }

    // ══════════════════════════════════════════════════════════════
    //  ENTRY BUILDING
    // ══════════════════════════════════════════════════════════════

    /**
     * Build a new device entry string (new format).
     * Token is derived from fingerprint — not random — so it
     * can be re-derived later even if the cookie is gone.
     */
    public static function buildEntry(
        string $ip,
        string $label,
        string $ua,
        string $fp
    ): string {
        $token = self::isValid($fp)
            ? self::generateToken($fp)
            : bin2hex(random_bytes(16)); // fallback if no FP

        return implode('|', [
            self::clean($ip),
            self::clean($label ?: 'New Device'),
            self::clean($ua),
            $token,
            $fp,
        ]);
    }

    /**
     * Serialize all entries back to a single string for DB storage.
     * Accepts an array of raw entry strings (not parsed arrays).
     */
    public static function serializeEntries(array $rawEntries): string
    {
        return implode(self::ENTRY_SEP, array_filter(array_map('trim', $rawEntries)));
    }

    // ══════════════════════════════════════════════════════════════
    //  COOKIE
    // ══════════════════════════════════════════════════════════════

    /**
     * Set the device_token cookie.
     * 1-year expiry — safe because token is derived from stable signals.
     */
    public static function setCookie(string $token): void
    {
        setcookie('device_token', $token, time() + 86400 * 365, '/');
    }

    // ══════════════════════════════════════════════════════════════
    //  UTILITIES
    // ══════════════════════════════════════════════════════════════

    public static function isValid(string $fp): bool
    {
        return (bool) preg_match('/^[0-9a-f]{64}$/', $fp);
    }

    /** Strip characters that would break entry delimiters */
    private static function clean(string $v): string
    {
        return str_replace(['|', ';;', "\n", "\r"], ' ', trim($v));
    }
}
