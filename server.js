'use strict';

const express      = require('express');
const { exec }     = require('child_process');
const fs           = require('fs');
const path         = require('path');
const os           = require('os');
const PDFDocument  = require('pdfkit');

const app       = express();
const PORT      = 3456;

// When packaged with pkg, __dirname is inside the read-only virtual snapshot.
// Writable files (scans) must live next to the real exe on disk.
const BASE_DIR  = process.pkg ? path.dirname(process.execPath) : __dirname;
const SCANS_DIR = path.join(BASE_DIR, 'scans');

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

// ── PDF Export ───────────────────────────────────────────────────────────────
app.get('/api/scans/:id/pdf', (req, res) => {
    const fp = safeScanPath(req.params.id);
    if (!fp)                return res.status(400).json({ error: 'Invalid ID' });
    if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Scan not found' });

    let scan;
    try { scan = JSON.parse(fs.readFileSync(fp, 'utf8')); }
    catch { return res.status(500).json({ error: 'Could not read scan' }); }

    const doc     = new PDFDocument({ size: 'letter', margins: { top: 40, bottom: 40, left: 40, right: 40 } });
    const safeLoc = (scan.location || 'scan').replace(/[^\w\- ]/g, '_').trim().slice(0, 60);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="WiFiSurvey_${safeLoc}_${scan.id}.pdf"`);
    doc.pipe(res);

    const ML = 40, PW = 612, PH = 792, W = PW - ML * 2;   // W = 532
    const aps  = scan.aps || [];
    const nets = new Set(aps.map(a => a.ssid)).size;
    const b24  = aps.filter(a => a.band && a.band.includes('2.4')).length;
    const b5   = aps.filter(a => a.band && a.band.includes('5') && !a.band.includes('2.5')).length;
    const sx   = aps.filter(a => a.signal >= 80).length;
    const sg   = aps.filter(a => a.signal >= 60 && a.signal < 80).length;
    const sf   = aps.filter(a => a.signal >= 40 && a.signal < 60).length;
    const sp   = aps.filter(a => a.signal <  40).length;
    let y = ML;

    try {
        // ── Header banner ────────────────────────────────────────────────────
        doc.rect(ML, y, W, 58).fill('#1a2a6c');
        doc.fillColor('#fff').font('Helvetica-Bold').fontSize(18)
           .text('WiFi Survey Report', ML + 14, y + 10, { width: W - 28, lineBreak: false });
        doc.font('Helvetica').fontSize(9).fillColor('#e2e8f0')
           .text(`Location: ${scan.location}`, ML + 14, y + 33, { width: W - 28, lineBreak: false });
        doc.fontSize(8).fillColor('#94a3b8')
           .text(`${new Date(scan.timestamp).toLocaleString()}  |  Host: ${scan.computer || 'N/A'}`, ML + 14, y + 46, { width: W - 28, lineBreak: false });
        y += 66;

        // ── Section header helper ─────────────────────────────────────────────
        function secHdr(title) {
            doc.rect(ML, y, W, 14).fill('#e8eaf6');
            doc.fillColor('#1a2a6c').font('Helvetica-Bold').fontSize(8)
               .text(title, ML + 5, y + 3, { width: W - 10, lineBreak: false });
            y += 15;
        }

        // ── Summary stats ─────────────────────────────────────────────────────
        secHdr('SUMMARY');
        const statsData = [
            { label: 'Networks',     val: nets,       clr: '#1d4ed8' },
            { label: 'Access Points',val: aps.length, clr: '#1d4ed8' },
            { label: '2.4 GHz',     val: b24,        clr: '#374151' },
            { label: '5 GHz',       val: b5,         clr: '#6d28d9' },
            { label: 'Excellent',   val: sx,         clr: '#065f46' },
            { label: 'Good',        val: sg,         clr: '#92400e' },
            { label: 'Fair',        val: sf,         clr: '#9a3412' },
            { label: 'Poor',        val: sp,         clr: '#991b1b' },
        ];
        const SW = W / statsData.length;
        const SH = 46;
        statsData.forEach(({ label, val, clr }, i) => {
            const bx = ML + i * SW;
            doc.rect(bx, y, SW, SH).fill('#fff');
            doc.rect(bx, y, SW, SH).stroke('#e5e7eb');
            doc.fillColor(clr).font('Helvetica-Bold').fontSize(18)
               .text(String(val), bx, y + 7, { width: SW, align: 'center', lineBreak: false });
            doc.fillColor('#9ca3af').font('Helvetica').fontSize(6.5)
               .text(label, bx, y + 32, { width: SW, align: 'center', lineBreak: false });
        });
        y += SH + 10;

        // ── Channel chart ─────────────────────────────────────────────────────
        secHdr('CHANNEL UTILIZATION');
        const chCounts = {};
        aps.forEach(a => { if (a.channel) chCounts[a.channel] = (chCounts[a.channel] || 0) + 1; });
        const chKeys = Object.keys(chCounts).sort((a, b) => +a - +b);
        const CH = 44;

        if (chKeys.length) {
            const maxV = Math.max(...chKeys.map(k => chCounts[k]));
            const step = W / chKeys.length;
            const bw   = Math.max(6, Math.min(22, step - 6));
            chKeys.forEach((ch, i) => {
                const cnt = chCounts[ch];
                const is5 = +ch > 14;
                const bx  = ML + i * step + (step - bw) / 2;
                const bh  = Math.max(4, Math.round((cnt / maxV) * CH));
                doc.rect(bx, y + CH - bh, bw, bh).fill(is5 ? '#8b5cf6' : '#3b82f6');
                doc.fillColor('#374151').font('Helvetica-Bold').fontSize(6.5)
                   .text(String(cnt), bx - 3, y + CH - bh - 10, { width: bw + 6, align: 'center', lineBreak: false });
                doc.fillColor('#9ca3af').font('Helvetica').fontSize(6)
                   .text('Ch' + ch, bx - 3, y + CH + 3, { width: bw + 6, align: 'center', lineBreak: false });
            });
            const ly = y + CH + 16;
            doc.rect(ML, ly, 8, 7).fill('#3b82f6');
            doc.fillColor('#6b7280').font('Helvetica').fontSize(7).text('2.4 GHz (ch 1–14)', ML + 11, ly, { lineBreak: false });
            doc.rect(ML + 110, ly, 8, 7).fill('#8b5cf6');
            doc.text('5 GHz (ch 36+)', ML + 121, ly, { lineBreak: false });
            y += CH + 30;
        } else {
            doc.fillColor('#9ca3af').font('Helvetica').fontSize(9).text('No channel data available.', ML, y + 4);
            y += 20;
        }

        // ── AP table ──────────────────────────────────────────────────────────
        y += 4;
        secHdr(`ACCESS POINTS — ${aps.length} total, sorted by signal strength`);

        const cols = [
            { label: 'SSID',     w: 126 },
            { label: 'BSSID',    w: 103 },
            { label: 'Signal',   w: 44  },
            { label: 'Radio',    w: 50  },
            { label: 'Band',     w: 50  },
            { label: 'Channel',  w: 42  },
            { label: 'Security', w: 0   },
        ];
        cols[6].w = W - cols.slice(0, 6).reduce((s, c) => s + c.w, 0);

        function drawTblHdr() {
            doc.rect(ML, y, W, 13).fill('#dbeafe');
            let cx = ML;
            cols.forEach(c => {
                doc.fillColor('#1e40af').font('Helvetica-Bold').fontSize(7)
                   .text(c.label, cx + 2, y + 3, { width: c.w - 4, lineBreak: false });
                cx += c.w;
            });
            y += 13;
        }
        drawTblHdr();

        const sorted = aps.slice().sort((a, b) => b.signal - a.signal);
        const RH = 13;
        sorted.forEach((ap, ri) => {
            if (y + RH > PH - ML) {
                doc.addPage();
                y = ML;
                secHdr('ACCESS POINTS (continued)');
                drawTblHdr();
            }
            if (ri % 2 === 0) doc.rect(ML, y, W, RH).fill('#f8faff');
            doc.rect(ML, y, W, RH).stroke('#eff1f5');

            const sc = ap.signal >= 80 ? '#059669' : ap.signal >= 60 ? '#b45309' : ap.signal >= 40 ? '#c2410c' : '#b91c1c';
            const cells = [
                { v: ap.ssid    || '(hidden)', fn: 'Helvetica-Bold', c: '#111827' },
                { v: ap.bssid   || '',         fn: 'Helvetica',      c: '#374151' },
                { v: ap.signal  + '%',         fn: 'Helvetica-Bold', c: sc        },
                { v: ap.radio   || 'n/a',      fn: 'Helvetica',      c: '#374151' },
                { v: ap.band    || 'n/a',      fn: 'Helvetica',      c: '#374151' },
                { v: ap.channel || 'n/a',      fn: 'Helvetica',      c: '#374151' },
                { v: ap.auth    || 'Unknown',  fn: 'Helvetica',      c: '#374151' },
            ];
            let cx = ML;
            cells.forEach((cell, ci) => {
                doc.fillColor(cell.c).font(cell.fn).fontSize(7)
                   .text(String(cell.v), cx + 2, y + 3, { width: cols[ci].w - 4, lineBreak: false });
                cx += cols[ci].w;
            });
            y += RH;
        });

        // ── Footer ────────────────────────────────────────────────────────────
        y += 14;
        if (y > PH - ML) { doc.addPage(); y = ML; }
        doc.fillColor('#9ca3af').font('Helvetica').fontSize(7.5)
           .text(`Generated by WiFi Surveyor  •  ${new Date().toLocaleString()}`, ML, y, { width: W, align: 'center', lineBreak: false });

    } catch (err) {
        console.error('[PDF]', err.message);
    }

    doc.end();
});

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, '127.0.0.1', () => {
    console.log('\n  ╔══════════════════════════════════╗');
    console.log(`  ║  WiFi Surveyor                   ║`);
    console.log(`  ║  http://localhost:${PORT}          ║`);
    console.log('  ╚══════════════════════════════════╝');
    console.log('\n  Press Ctrl+C to stop.\n');
    exec(`cmd /c start http://localhost:${PORT}`);
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`\n  ERROR: Port ${PORT} is already in use.\n`);
        console.error('  Another instance may already be running.');
        console.error(`  Open http://localhost:${PORT} in your browser, or close the other instance first.\n`);
    } else {
        console.error('\n  ERROR starting server:', err.message, '\n');
    }
    console.log('  Press Enter to exit...');
    process.stdin.resume();
    process.stdin.once('data', () => process.exit(1));
});
