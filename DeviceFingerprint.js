/**
 * DeviceFingerprint.js
 * -------------------------------------------------------------------------------------
 * Developer: Muskan Sayyed
 * Description: Drop-in browser fingerprint library.
 *              Produces the same SHA-256 hash every time on
 *              the same browser/machine - survives close, restart, and cookie deletion.
 *              
 *              INCLUDE: <script src="js/DeviceFingerprint.js"></script>
 *              CALL:    DeviceFingerprint.init('device_fingerprint');
 * 
 * Created on: 15-05-2026
 * 
 * -------------------------------------------------------------------------------------
 * CHANGELOG:
 * ----------------------------------------------------------------------------
 * Version | Date       | Author              | Description
 * ----------------------------------------------------------------------------
 * ----------------------------------------------------------------------------
 *
 * ----------------------------------------------------------------------------
 */
const DeviceFingerprint = (() => {

    const LS_KEY = 'dfp_v1';

    function canvasSignal() {
        try {
            const c = document.createElement('canvas');
            const ctx = c.getContext('2d');
            c.width = 240; c.height = 50;
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(100, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.font = '15px Arial';
            ctx.fillText('DFP-Signal', 2, 15);
            ctx.fillStyle = 'rgba(102,200,0,0.6)';
            ctx.fillText('DFP-Signal', 3, 16);
            return c.toDataURL();
        } catch (e) { return 'canvas-blocked'; }
    }

    function webglSignal() {
        try {
            const c = document.createElement('canvas');
            const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
            if (!gl) return 'no-webgl';
            const ext = gl.getExtension('WEBGL_debug_renderer_info');
            return ext
                ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) + '~~' + gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
                : gl.getParameter(gl.VENDOR) + '~~' + gl.getParameter(gl.RENDERER);
        } catch (e) { return 'webgl-blocked'; }
    }

    function audioSignal() {
        return new Promise(resolve => {
            try {
                const AC = window.AudioContext || window.webkitAudioContext;
                if (!AC) return resolve('no-audio');
                const ctx = new AC();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                const sp = ctx.createScriptProcessor(4096, 1, 1);
                gain.gain.value = 0;
                osc.type = 'triangle';
                osc.frequency.value = 10000;
                osc.connect(sp); sp.connect(gain); gain.connect(ctx.destination);
                osc.start(0);
                sp.onaudioprocess = e => {
                    const d = e.inputBuffer.getChannelData(0);
                    let s = 0; for (let i = 0; i < d.length; i++) s += Math.abs(d[i]);
                    osc.stop(); ctx.close(); resolve(s.toFixed(8));
                };
                setTimeout(() => resolve('audio-timeout'), 900);
            } catch (e) { resolve('audio-blocked'); }
        });
    }

    function fontSignal() {
        const fonts = ['Arial','Courier New','Georgia','Verdana','Tahoma',
            'Trebuchet MS','Comic Sans MS','Impact','Calibri','Cambria',
            'Segoe UI','Consolas','Monaco','Helvetica','Roboto'];
        const c = document.createElement('canvas');
        const ctx = c.getContext('2d');
        const base = {};
        ['monospace','sans-serif','serif'].forEach(f => {
            ctx.font = `72px ${f}`; base[f] = ctx.measureText('mmwwiiWW').width;
        });
        return fonts.filter(font =>
            ['monospace','sans-serif','serif'].some(f => {
                ctx.font = `72px '${font}',${f}`;
                return ctx.measureText('mmwwiiWW').width !== base[f];
            })
        ).join(',');
    }

    function screenSignal() {
        return [screen.width, screen.height, screen.colorDepth,
                window.devicePixelRatio || 1,
                screen.availWidth, screen.availHeight].join('x');
    }

    async function sha256(str) {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
    }

    async function compute() {
        const audio = await audioSignal();
        const raw = [
            navigator.userAgent,
            navigator.platform || '',
            navigator.vendor || '',
            navigator.language,
            (navigator.languages || []).join(','),
            screenSignal(),
            (navigator.hardwareConcurrency || 0) + '|' + (navigator.deviceMemory || 0),
            Intl.DateTimeFormat().resolvedOptions().timeZone + '|' + new Date().getTimezoneOffset(),
            fontSignal(),
            canvasSignal(),
            webglSignal(),
            audio,
            navigator.cookieEnabled ? '1' : '0',
        ].join('|||');
        return sha256(raw);
    }

    async function get() {
        const cached = localStorage.getItem(LS_KEY);
        if (cached && /^[0-9a-f]{64}$/.test(cached)) return cached;
        const fp = await compute();
        try { localStorage.setItem(LS_KEY, fp); } catch(e) {}
        return fp;
    }

    async function init(inputId) {
        const fp = await get();
        const el = document.getElementById(inputId);
        if (el) el.value = fp;
        return fp;
    }

    return { get, init };
})();
