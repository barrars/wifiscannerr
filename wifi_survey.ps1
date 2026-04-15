# ============================================================
#  WiFi Site Survey Tool  —  Windows PowerShell
# ============================================================
#  Run:  Right-click > "Run with PowerShell"
#   or:  powershell -ExecutionPolicy Bypass -File wifi_survey.ps1
# ============================================================

function HtmlEncode([string]$s) {
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

# ─── Prompt ─────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     WiFi Site Survey Tool"             -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$location = Read-Host "Enter location name (e.g., Conference Room)"
if ([string]::IsNullOrWhiteSpace($location)) {
    $location = "Location_$(Get-Date -Format 'HHmmss')"
}
$locationSafe = $location -replace '[\\/:*?"<>|]', '_'

$timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$currentDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$computerName = $env:COMPUTERNAME
$scriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$reportsDir   = Join-Path $scriptDir "WiFiReports"
New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null

# ─── Scan ───────────────────────────────────────────────────
Write-Host ""
# Poll netsh up to 4 times and keep whichever result has the most APs.
# Each call nudges Windows to refresh its BSSID cache; a full radio scan
# cycle typically completes within 3-9 seconds on most adapters.
$bestLines = @()
$bestCount = 0
for ($poll = 1; $poll -le 4; $poll++) {
    Write-Host "  Pass $poll of 4..." -ForegroundColor DarkGray
    $attempt = & netsh wlan show networks mode=bssid 2>&1
    $apCount = ($attempt | Select-String -Pattern '^BSSID \d+').Count
    if ($apCount -gt $bestCount) { $bestCount = $apCount; $bestLines = $attempt }
    if ($poll -lt 4) { Start-Sleep -Seconds 3 }
}

Write-Host "Scanning WiFi at: $location ..." -ForegroundColor Yellow
Write-Host ""

$rawLines = $bestLines

if (-not $rawLines) {
    Write-Host "ERROR: No output from netsh. Make sure your Wi-Fi adapter is enabled." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$lines = $rawLines | ForEach-Object { "$_".TrimEnd() }

# ─── Parse ──────────────────────────────────────────────────
$apList        = New-Object System.Collections.Generic.List[PSCustomObject]
$totalNetworks = 0

$curSSID    = ""
$curAuth    = ""
$curEnc     = ""
$inBSSID    = $false
$curBSSID   = ""
$curSignal  = 0
$curRadio   = ""
$curBand    = ""
$curChannel = ""

function Save-AP {
    if ($script:inBSSID -and $script:curBSSID -ne "") {
        $script:apList.Add([PSCustomObject]@{
            SSID    = $script:curSSID
            BSSID   = $script:curBSSID
            Signal  = $script:curSignal
            Radio   = $script:curRadio
            Band    = $script:curBand
            Channel = $script:curChannel
            Auth    = $script:curAuth
            Enc     = $script:curEnc
        })
    }
}

foreach ($line in $lines) {
    switch -Regex ($line) {
        "^SSID \d+ : (.*)" {
            Save-AP
            $script:totalNetworks++
            $script:curSSID   = $Matches[1].Trim()
            $script:curAuth   = ""
            $script:curEnc    = ""
            $script:inBSSID   = $false
            $script:curBSSID  = ""
            break
        }
        "^\s+Authentication\s*:\s*(.+)" {
            $script:curAuth = $Matches[1].Trim()
            break
        }
        "^\s+Encryption\s*:\s*(.+)" {
            $script:curEnc = $Matches[1].Trim()
            break
        }
        "^\s+BSSID \d+\s*:\s*(.+)" {
            Save-AP
            $script:curBSSID   = $Matches[1].Trim()
            $script:curSignal  = 0
            $script:curRadio   = ""
            $script:curBand    = ""
            $script:curChannel = ""
            $script:inBSSID    = $true
            break
        }
        "^\s+Signal\s*:\s*(\d+)%" {
            $script:curSignal = [int]$Matches[1]
            break
        }
        "^\s+Radio type\s*:\s*(.+)" {
            $script:curRadio = $Matches[1].Trim()
            break
        }
        "^\s+Band\s*:\s*(.+)" {
            $script:curBand = $Matches[1].Trim()
            break
        }
        "^\s+Channel\s*:\s*(\d+)" {
            $script:curChannel = $Matches[1].Trim()
            break
        }
    }
}
Save-AP   # flush final entry

# ─── Stats ──────────────────────────────────────────────────
$totalAPs       = $apList.Count
$band24Count    = ($apList | Where-Object { $_.Band -like "*2.4*" }).Count
$band5Count     = ($apList | Where-Object { $_.Band -like "*5*" -and $_.Band -notlike "*2.5*" }).Count
$excellentCount = ($apList | Where-Object { $_.Signal -ge 80 }).Count
$goodCount      = ($apList | Where-Object { $_.Signal -ge 60 -and $_.Signal -lt 80 }).Count
$fairCount      = ($apList | Where-Object { $_.Signal -ge 40 -and $_.Signal -lt 60 }).Count
$poorCount      = ($apList | Where-Object { $_.Signal -lt 40 }).Count

# ─── Channel data ───────────────────────────────────────────
$channelCounts = @{}
foreach ($ap in $apList) {
    if (-not [string]::IsNullOrEmpty($ap.Channel)) {
        $ch = $ap.Channel
        if ($channelCounts.ContainsKey($ch)) { $channelCounts[$ch]++ }
        else { $channelCounts[$ch] = 1 }
    }
}
if ($channelCounts.Count -gt 0) {
    $channelDataJson = "{" + (($channelCounts.GetEnumerator() |
        Sort-Object { [int]$_.Key } |
        ForEach-Object { "`"$($_.Key)`": $($_.Value)" }) -join ", ") + "}"
} else {
    $channelDataJson = "{}"
}

# ─── Table rows ─────────────────────────────────────────────
$tableRows = ""
foreach ($ap in ($apList | Sort-Object -Property Signal -Descending)) {

    $ssidHtml = if ([string]::IsNullOrEmpty($ap.SSID)) {
        "<em style='color:#aaa'>Hidden Network</em>"
    } else {
        "<strong>$(HtmlEncode $ap.SSID)</strong>"
    }

    $sig = $ap.Signal
    $sigClass = if     ($sig -ge 80) { "sig-excellent" }
                elseif ($sig -ge 60) { "sig-good"      }
                elseif ($sig -ge 40) { "sig-fair"      }
                else                 { "sig-poor"      }

    $authDisplay = if ([string]::IsNullOrEmpty($ap.Auth)) { "Unknown" } else { HtmlEncode $ap.Auth }
    $badgeClass  = if     ($ap.Auth -like "*WPA3*") { "b-wpa3"  }
                   elseif ($ap.Auth -like "*WPA2*") { "b-wpa2"  }
                   elseif ($ap.Auth -like "*WPA*")  { "b-wpa"   }
                   elseif ($ap.Auth -like "*Open*") { "b-open"  }
                   else                             { "b-other" }

    $bandDisp    = if ([string]::IsNullOrEmpty($ap.Band))    { "n/a" } else { HtmlEncode $ap.Band    }
    $radioDisp   = if ([string]::IsNullOrEmpty($ap.Radio))   { "n/a" } else { HtmlEncode $ap.Radio   }
    $channelDisp = if ([string]::IsNullOrEmpty($ap.Channel)) { "n/a" } else { HtmlEncode $ap.Channel }

    $tableRows += @"
        <tr data-signal="$sig" data-band="$($ap.Band)" data-ssid="$(HtmlEncode $ap.SSID)" data-bssid="$(HtmlEncode $ap.BSSID)" data-auth="$(HtmlEncode $ap.Auth)">
          <td>$ssidHtml</td>
          <td><code>$(HtmlEncode $ap.BSSID)</code></td>
          <td class="$sigClass" data-sort="$sig">
            <div class="bar-wrap">
              <div class="bar-outer"><div class="bar-inner" style="width:$sig%"></div></div>
              <span>$sig%</span>
            </div>
          </td>
          <td>$radioDisp</td>
          <td>$bandDisp</td>
          <td>$channelDisp</td>
          <td><span class="badge $badgeClass">$authDisplay</span></td>
        </tr>
"@
}

# ─── HTML ───────────────────────────────────────────────────
$htmlFile = Join-Path $reportsDir "WiFiReport_${locationSafe}_${timestamp}.html"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Survey &mdash; $(HtmlEncode $location)</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
    background: #eef0f4; color: #1a1a2e; padding: 20px;
  }
  .container {
    max-width: 1400px; margin: 0 auto; background: #fff;
    border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.12); overflow: hidden;
  }

  /* Header */
  .header {
    background: linear-gradient(135deg, #1a2a6c 0%, #b21f1f 60%, #e8a900 100%);
    color: #fff; padding: 28px 36px; text-align: center;
  }
  .header h1 { font-size: 1.9em; margin-bottom: 6px; }
  .header p  { opacity: .85; font-size: .93em; }

  /* Stats */
  .stats {
    display: flex; flex-wrap: wrap; gap: 14px;
    padding: 20px 30px; background: #f8f9fa; border-bottom: 1px solid #e4e7ec;
  }
  .stat {
    flex: 1; min-width: 90px; text-align: center; padding: 14px 8px;
    background: #fff; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,0.07);
  }
  .stat-val { font-size: 1.9em; font-weight: 700; line-height: 1; }
  .stat-lbl { color: #6c757d; font-size: .75em; margin-top: 5px; }
  .c-blue   { color: #3b82f6; } .c-purple { color: #8b5cf6; }
  .c-green  { color: #10b981; } .c-yellow { color: #d97706; }
  .c-orange { color: #f97316; } .c-red    { color: #ef4444; }

  /* Channel chart */
  .section       { padding: 20px 30px; border-bottom: 1px solid #e4e7ec; }
  .section h2    { font-size: .8em; color: #9ca3af; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; }
  .ch-chart      { display: flex; align-items: flex-end; gap: 6px; height: 90px; }
  .ch-col        { display: flex; flex-direction: column; align-items: center; gap: 3px; }
  .ch-bar        { width: 34px; border-radius: 4px 4px 0 0; background: #3b82f6; min-height: 4px; cursor: default; }
  .ch-bar.ghz5   { background: #8b5cf6; }
  .ch-cnt        { font-size: 11px; font-weight: 600; color: #374151; }
  .ch-lbl        { font-size: 11px; color: #9ca3af; }
  .chart-legend  { display: flex; gap: 16px; margin-top: 10px; font-size: 12px; color: #6c757d; }
  .leg-dot       { display: inline-block; width: 11px; height: 11px; border-radius: 3px; margin-right: 4px; vertical-align: middle; }

  /* Controls */
  .controls {
    padding: 14px 30px; background: #fff; border-bottom: 1px solid #e4e7ec;
    display: flex; gap: 10px; flex-wrap: wrap; align-items: center;
  }
  .controls input, .controls select {
    padding: 8px 12px; border: 1px solid #dde1e7; border-radius: 8px;
    font-size: 13px; background: #f8f9fa; color: #1a1a2e; outline: none;
  }
  .controls input       { flex: 1; min-width: 180px; }
  .controls input:focus,
  .controls select:focus { border-color: #3b82f6; background: #fff; }

  /* Table */
  .table-wrap { overflow-x: auto; padding: 0 30px 30px; }
  table  { width: 100%; border-collapse: collapse; font-size: 13.5px; margin-top: 16px; }
  thead th {
    background: #1a2a6c; color: #fff; padding: 11px 13px;
    text-align: left; cursor: pointer; user-select: none; white-space: nowrap;
  }
  thead th:hover       { background: #243382; }
  thead th::after      { content: ' \2195'; opacity: .4; font-size: 10px; }
  thead th.sort-asc::after  { content: ' \2191'; opacity: 1; }
  thead th.sort-desc::after { content: ' \2193'; opacity: 1; }
  tbody td  { padding: 9px 13px; border-bottom: 1px solid #f0f2f5; vertical-align: middle; }
  tbody tr:hover { background: #f5f8ff; }
  tbody tr:last-child td { border-bottom: none; }
  code { font-size: 12px; background: #f1f5f9; padding: 2px 7px; border-radius: 4px; }

  /* Signal bars */
  .bar-wrap   { display: flex; align-items: center; gap: 8px; }
  .bar-outer  { width: 70px; height: 8px; background: #e5e7eb; border-radius: 99px; flex-shrink: 0; overflow: hidden; }
  .bar-inner  { height: 100%; border-radius: 99px; }
  .bar-wrap span { font-size: 12px; font-weight: 600; white-space: nowrap; }
  .sig-excellent .bar-inner { background: #10b981; }
  .sig-excellent span        { color: #059669; }
  .sig-good      .bar-inner  { background: #f59e0b; }
  .sig-good      span        { color: #d97706; }
  .sig-fair      .bar-inner  { background: #f97316; }
  .sig-fair      span        { color: #ea580c; }
  .sig-poor      .bar-inner  { background: #ef4444; }
  .sig-poor      span        { color: #dc2626; }

  /* Badges */
  .badge { display: inline-block; padding: 3px 9px; border-radius: 6px; font-size: 11.5px; font-weight: 500; white-space: nowrap; }
  .b-wpa3  { background: #d1fae5; color: #065f46; }
  .b-wpa2  { background: #dbeafe; color: #1e40af; }
  .b-wpa   { background: #ede9fe; color: #4c1d95; }
  .b-open  { background: #fee2e2; color: #991b1b; }
  .b-other { background: #f3f4f6; color: #374151; }

  .no-results { text-align: center; padding: 40px; color: #9ca3af; }
  .footer { background: #f8f9fa; padding: 13px 30px; text-align: center; color: #9ca3af; font-size: 12px; border-top: 1px solid #e4e7ec; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>&#x1F4E1; WiFi Site Survey Report</h1>
    <p><strong>$(HtmlEncode $location)</strong> &nbsp;&bull;&nbsp; $currentDate &nbsp;&bull;&nbsp; $computerName</p>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-val c-blue">$totalNetworks</div><div class="stat-lbl">Networks (SSIDs)</div></div>
    <div class="stat"><div class="stat-val c-blue">$totalAPs</div><div class="stat-lbl">Access Points</div></div>
    <div class="stat"><div class="stat-val">$band24Count</div><div class="stat-lbl">2.4 GHz APs</div></div>
    <div class="stat"><div class="stat-val c-purple">$band5Count</div><div class="stat-lbl">5 GHz APs</div></div>
    <div class="stat"><div class="stat-val c-green">$excellentCount</div><div class="stat-lbl">Excellent (&ge;80%)</div></div>
    <div class="stat"><div class="stat-val c-yellow">$goodCount</div><div class="stat-lbl">Good (60&ndash;79%)</div></div>
    <div class="stat"><div class="stat-val c-orange">$fairCount</div><div class="stat-lbl">Fair (40&ndash;59%)</div></div>
    <div class="stat"><div class="stat-val c-red">$poorCount</div><div class="stat-lbl">Poor (&lt;40%)</div></div>
  </div>

  <div class="section">
    <h2>Channel Utilization</h2>
    <div class="ch-chart" id="chChart"></div>
    <div class="chart-legend">
      <span><span class="leg-dot" style="background:#3b82f6"></span>2.4 GHz (ch 1&ndash;14)</span>
      <span><span class="leg-dot" style="background:#8b5cf6"></span>5 GHz (ch 36+)</span>
    </div>
  </div>

  <div class="controls">
    <input type="text" id="searchInput" placeholder="Search SSID or BSSID..." oninput="applyFilters()">
    <select id="sigFilter" onchange="applyFilters()">
      <option value="">All Signal Levels</option>
      <option value="excellent">Excellent (80-100%)</option>
      <option value="good">Good (60-79%)</option>
      <option value="fair">Fair (40-59%)</option>
      <option value="poor">Poor (&lt;40%)</option>
    </select>
    <select id="bandFilter" onchange="applyFilters()">
      <option value="">All Bands</option>
      <option value="2.4">2.4 GHz</option>
      <option value="5">5 GHz</option>
    </select>
    <select id="secFilter" onchange="applyFilters()">
      <option value="">All Security</option>
      <option value="WPA3">WPA3</option>
      <option value="WPA2">WPA2</option>
      <option value="WPA-">WPA (legacy)</option>
      <option value="Open">Open / None</option>
    </select>
  </div>

  <div class="table-wrap">
    <table id="wifiTable">
      <thead>
        <tr>
          <th onclick="sortTable(this,0)">SSID</th>
          <th onclick="sortTable(this,1)">BSSID</th>
          <th onclick="sortTable(this,2)">Signal</th>
          <th onclick="sortTable(this,3)">Radio</th>
          <th onclick="sortTable(this,4)">Band</th>
          <th onclick="sortTable(this,5)">Channel</th>
          <th onclick="sortTable(this,6)">Security</th>
        </tr>
      </thead>
      <tbody>
$tableRows
      </tbody>
    </table>
    <div class="no-results" id="noResults" style="display:none">No access points match the current filters.</div>
  </div>

  <div class="footer">
    Click column headers to sort &nbsp;&bull;&nbsp; Use filters above to narrow results &nbsp;&bull;&nbsp; Captured at $currentDate
  </div>
</div>

<script>
  // ── Channel chart ──────────────────────────────────────────
  (function () {
    var data    = $channelDataJson;
    var keys    = Object.keys(data).sort(function (a, b) { return +a - +b; });
    var maxVal  = Math.max.apply(null, keys.map(function (k) { return data[k]; }).concat([1]));
    var el      = document.getElementById("chChart");
    var maxH    = 64;

    keys.forEach(function (ch) {
      var count = data[ch];
      var is5   = +ch > 14;
      var barH  = Math.max(4, Math.round((count / maxVal) * maxH));
      var col   = document.createElement("div");
      col.className = "ch-col";
      col.title     = "Channel " + ch + ": " + count + " AP" + (count !== 1 ? "s" : "");
      col.innerHTML =
        '<div class="ch-cnt">' + count + '</div>' +
        '<div class="ch-bar' + (is5 ? ' ghz5' : '') + '" style="height:' + barH + 'px"></div>' +
        '<div class="ch-lbl">Ch ' + ch + '</div>';
      el.appendChild(col);
    });
  })();

  // ── Filtering ─────────────────────────────────────────────
  function applyFilters() {
    var search  = document.getElementById("searchInput").value.toLowerCase();
    var sigF    = document.getElementById("sigFilter").value;
    var bandF   = document.getElementById("bandFilter").value;
    var secF    = document.getElementById("secFilter").value;
    var rows    = document.querySelectorAll("#wifiTable tbody tr");
    var visible = 0;

    rows.forEach(function (row) {
      var ssid  = (row.dataset.ssid  || "").toLowerCase();
      var bssid = (row.dataset.bssid || "").toLowerCase();
      var sig   = parseInt(row.dataset.signal || "0", 10);
      var band  = row.dataset.band  || "";
      var auth  = row.dataset.auth  || "";

      var okText = !search || ssid.indexOf(search) !== -1 || bssid.indexOf(search) !== -1;
      var okSig  = !sigF   ||
        (sigF === "excellent" && sig >= 80) ||
        (sigF === "good"      && sig >= 60 && sig < 80) ||
        (sigF === "fair"      && sig >= 40 && sig < 60) ||
        (sigF === "poor"      && sig < 40);
      var okBand = !bandF  ||
        (bandF === "2.4" && band.indexOf("2.4") !== -1) ||
        (bandF === "5"   && band.indexOf("5")   !== -1 && band.indexOf("2.5") === -1);
      var okSec  = !secF || auth.indexOf(secF) !== -1;

      var show = okText && okSig && okBand && okSec;
      row.style.display = show ? "" : "none";
      if (show) visible++;
    });

    document.getElementById("noResults").style.display = visible === 0 ? "" : "none";
  }

  // ── Sorting ───────────────────────────────────────────────
  var _sortCol = -1, _sortDir = 1;

  function sortTable(th, col) {
    if (_sortCol === col) { _sortDir *= -1; } else { _sortCol = col; _sortDir = 1; }

    document.querySelectorAll("thead th").forEach(function (h) {
      h.classList.remove("sort-asc", "sort-desc");
    });
    th.classList.add(_sortDir === 1 ? "sort-asc" : "sort-desc");

    var tbody = document.querySelector("#wifiTable tbody");
    var rows  = Array.from(tbody.rows);

    rows.sort(function (a, b) {
      var av, bv;
      if (col === 2) {                              // numeric: signal
        av = parseInt(a.cells[col].dataset.sort || 0, 10);
        bv = parseInt(b.cells[col].dataset.sort || 0, 10);
        return _sortDir * (av - bv);
      }
      if (col === 5) {                              // numeric: channel
        av = parseInt(a.cells[col].innerText, 10) || 0;
        bv = parseInt(b.cells[col].innerText, 10) || 0;
        return _sortDir * (av - bv);
      }
      av = a.cells[col].innerText.trim().toLowerCase();
      bv = b.cells[col].innerText.trim().toLowerCase();
      return _sortDir * av.localeCompare(bv);
    });

    rows.forEach(function (r) { tbody.appendChild(r); });
  }
</script>
</body>
</html>
"@

[System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.UTF8Encoding]::new($false))

# ─── Console summary ────────────────────────────────────────
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Scan complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Location  : $location"
Write-Host "  Networks  : $totalNetworks SSIDs"
Write-Host "  APs found : $totalAPs access points"
Write-Host "  2.4 GHz   : $band24Count APs"
Write-Host "  5 GHz     : $band5Count APs"
Write-Host ""
Write-Host "  Report    : $htmlFile" -ForegroundColor Cyan
Write-Host ""

Start-Process $htmlFile
Write-Host "Report opened in your browser." -ForegroundColor Green
Write-Host "All reports are saved to: $reportsDir"
Write-Host ""
