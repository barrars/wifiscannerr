'use strict';

const express  = require('express');
const { exec } = require('child_process');
const fs       = require('fs');
const path     = require('path');
const os       = require('os');

const app       = express();
const PORT      = 3456;
const SCANS_DIR = path.join(__dirname, 'scans');

if (!fs.existsSync(SCANS_DIR)) fs.mkdirSync(SCANS_DIR, { recursive: true });

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Security helpers ─────────────────────────────────────────────────────────

function isValidId(id) {
    return typeof id === 'string' && /^[\w-]{1,60}$/.test(id);
}

function safeScanPath(id) {
    if (!isValidId(id)) return null;
    const resolved = path.resolve(SCANS_DIR, `${id}.json`);
    const base     = path.resolve(SCANS_DIR) + path.sep;
    if (!resolved.startsWith(base)) return null;
    return resolved;
}

// ── netsh parser ─────────────────────────────────────────────────────────────

function parseNetsh(output) {
    const lines  = output.split(/\r?\n/);
    const aps    = [];
    let curSSID = '', curAuth = '', curEnc = '';
    let inBSSID = false, curBSSID = '', curSignal = 0;
    let curRadio = '', curBand = '', curChannel = '';

    function flush() {
        if (inBSSID && curBSSID) {
            aps.push({
                ssid: curSSID, bssid: curBSSID, signal: curSignal,
                radio: curRadio, band: curBand, channel: curChannel,
                auth: curAuth, enc: curEnc
            });
        }
    }

    for (const line of lines) {
        let m;
        if      ((m = line.match(/^SSID \d+ : (.*)/)))              { flush(); inBSSID = false; curBSSID = ''; curSSID = m[1].trim(); curAuth = ''; curEnc = ''; }
        else if ((m = line.match(/^\s+Authentication\s*:\s*(.+)/))) { curAuth    = m[1].trim(); }
        else if ((m = line.match(/^\s+Encryption\s*:\s*(.+)/)))     { curEnc     = m[1].trim(); }
        else if ((m = line.match(/^\s+BSSID \d+\s*:\s*(.+)/)))      { flush(); curBSSID = m[1].trim(); curSignal = 0; curRadio = ''; curBand = ''; curChannel = ''; inBSSID = true; }
        else if ((m = line.match(/^\s+Signal\s*:\s*(\d+)%/)))       { curSignal  = parseInt(m[1], 10); }
        else if ((m = line.match(/^\s+Radio type\s*:\s*(.+)/)))     { curRadio   = m[1].trim(); }
        else if ((m = line.match(/^\s+Band\s*:\s*(.+)/)))           { curBand    = m[1].trim(); }
        else if ((m = line.match(/^\s+Channel\s*:\s*(\d+)/)))       { curChannel = m[1].trim(); }
    }
    flush();
    return aps;
}

function scanSummary(scan) {
    return {
        id:           scan.id,
        location:     scan.location,
        timestamp:    scan.timestamp,
        computer:     scan.computer,
        apCount:      scan.aps.length,
        networkCount: new Set(scan.aps.map(a => a.ssid)).size
    };
}

// ── Scan rate limiting ───────────────────────────────────────────────────────

let isScanRunning = false;

// ── Routes ───────────────────────────────────────────────────────────────────

// List all scans
app.get('/api/scans', (req, res) => {
    try {
        const files = fs.readdirSync(SCANS_DIR).filter(f => f.endsWith('.json'));
        const list  = files
            .map(f => {
                try { return scanSummary(JSON.parse(fs.readFileSync(path.join(SCANS_DIR, f), 'utf8'))); }
                catch { return null; }
            })
            .filter(Boolean)
            .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
        res.json(list);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// WlanScan trigger script — written to a temp .ps1 file to avoid all
// command-line escaping issues. Key fix vs previous attempts:
//   [Guid]$gb  does NOT reliably call Guid(byte[]) in PowerShell.
//   New-Object System.Guid (,$gb)  is the correct form — the leading comma
//   forces the byte array to be passed as a single constructor argument.
const WLAN_SCAN_PS = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WifiTrigger {
    [DllImport("wlanapi.dll")] public static extern uint WlanOpenHandle(uint v, IntPtr r, out uint nv, out IntPtr h);
    [DllImport("wlanapi.dll")] public static extern uint WlanCloseHandle(IntPtr h, IntPtr r);
    [DllImport("wlanapi.dll")] public static extern uint WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr l);
    [DllImport("wlanapi.dll")] public static extern uint WlanScan(IntPtr h, ref Guid g, IntPtr s, IntPtr d, IntPtr r);
    [DllImport("wlanapi.dll")] public static extern void WlanFreeMemory(IntPtr p);
}
"@
$h = [IntPtr]::Zero; [uint32]$nv = 0
if ([WifiTrigger]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h) -eq 0) {
    $lp = [IntPtr]::Zero
    if ([WifiTrigger]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$lp) -eq 0) {
        $n   = [Runtime.InteropServices.Marshal]::ReadInt32($lp, 0)
        $hit = 0
        for ($i = 0; $i -lt $n; $i++) {
            $off = 8 + ($i * 532)
            $gb  = New-Object byte[] 16
            [Runtime.InteropServices.Marshal]::Copy([IntPtr]([Int64]$lp + $off), $gb, 0, 16)
            $g   = New-Object System.Guid (,$gb)
            if ([WifiTrigger]::WlanScan($h, [ref]$g, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero) -eq 0) { $hit++ }
        }
        Write-Output "WlanScan triggered on $hit of $n interface(s)"
        if ($lp -ne [IntPtr]::Zero) { [WifiTrigger]::WlanFreeMemory($lp) }
    } else { Write-Output "WlanEnumInterfaces failed" }
    [WifiTrigger]::WlanCloseHandle($h, [IntPtr]::Zero) | Out-Null
} else { Write-Output "WlanOpenHandle failed" }
`;

const SCAN_SCRIPT_PATH = path.join(os.tmpdir(), '_wifisurveyor_scan.ps1');
fs.writeFileSync(SCAN_SCRIPT_PATH, WLAN_SCAN_PS, 'utf8');

// Trigger a new scan
app.post('/api/scans', (req, res) => {
    if (isScanRunning) return res.status(429).json({ error: 'A scan is already running. Please wait.' });
    isScanRunning = true;

    const locName = (String(req.body.location || '').trim().slice(0, 100)) || `Scan_${Date.now()}`;

    // Step 1: Call WlanScan() — this is the exact API Windows uses when the network
    //         picker opens. It tells the adapter to do an active radio sweep.
    exec(
        `powershell -NoProfile -ExecutionPolicy Bypass -File "${SCAN_SCRIPT_PATH}"`,
        (err, stdout, stderr) => {
            console.log('[WlanScan]', stdout.trim() || stderr.trim() || err?.message || 'no output');

            // Step 2: Poll netsh 3 times after the scan, keeping the best result.
            //         WlanScan() is async — the radio needs ~3-6 s to complete.
            const POLLS       = 3;
            const POLL_GAP_MS = 3000;
            let bestOutput  = '';
            let bestApCount = 0;
            let attempt     = 0;

            function poll() {
                exec('netsh wlan show networks mode=bssid', (nerr, nout) => {
                    attempt++;
                    if (!nerr && nout) {
                        const count = parseNetsh(nout).length;
                        console.log(`[poll ${attempt}/${POLLS}] ${count} APs`);
                        if (count > bestApCount) { bestApCount = count; bestOutput = nout; }
                    }
                    if (attempt < POLLS) {
                        setTimeout(poll, POLL_GAP_MS);
                    } else {
                        isScanRunning = false;
                        if (!bestOutput.trim()) {
                            return res.status(500).json({ error: 'netsh failed. Make sure Wi-Fi is enabled.' });
                        }
                        const aps = parseNetsh(bestOutput);
                        const now = new Date();
                        const id  = now.toISOString().replace('T', '_').replace(/[:.]/g, '-').slice(0, 19);
                        const scan = { id, location: locName, timestamp: now.toISOString(), computer: os.hostname(), aps };
                        fs.writeFileSync(path.join(SCANS_DIR, `${id}.json`), JSON.stringify(scan, null, 2), 'utf8');
                        res.json(scanSummary(scan));
                    }
                });
            }

            // Give WlanScan a 3s head start before first netsh read
            setTimeout(poll, 3000);
        }
    );
});

// Get a single scan
app.get('/api/scans/:id', (req, res) => {
    const fp = safeScanPath(req.params.id);
    if (!fp)                  return res.status(400).json({ error: 'Invalid ID' });
    if (!fs.existsSync(fp))   return res.status(404).json({ error: 'Scan not found' });
    try { res.json(JSON.parse(fs.readFileSync(fp, 'utf8'))); }
    catch { res.status(500).json({ error: 'Could not read scan file' }); }
});

// Delete a scan
app.delete('/api/scans/:id', (req, res) => {
    const fp = safeScanPath(req.params.id);
    if (!fp)                  return res.status(400).json({ error: 'Invalid ID' });
    if (!fs.existsSync(fp))   return res.status(404).json({ error: 'Scan not found' });
    fs.unlinkSync(fp);
    res.json({ ok: true });
});

// Rename a scan
app.patch('/api/scans/:id', (req, res) => {
    const fp = safeScanPath(req.params.id);
    if (!fp)                  return res.status(400).json({ error: 'Invalid ID' });
    if (!fs.existsSync(fp))   return res.status(404).json({ error: 'Scan not found' });
    try {
        const scan = JSON.parse(fs.readFileSync(fp, 'utf8'));
        if (req.body.location) scan.location = String(req.body.location).trim().slice(0, 100);
        fs.writeFileSync(fp, JSON.stringify(scan, null, 2), 'utf8');
        res.json({ ok: true });
    } catch { res.status(500).json({ error: 'Could not update scan' }); }
});

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, '127.0.0.1', () => {
    console.log('\n  ╔══════════════════════════════════╗');
    console.log(`  ║  WiFi Surveyor                   ║`);
    console.log(`  ║  http://localhost:${PORT}          ║`);
    console.log('  ╚══════════════════════════════════╝');
    console.log('\n  Press Ctrl+C to stop.\n');
    exec(`cmd /c start http://localhost:${PORT}`);
});
