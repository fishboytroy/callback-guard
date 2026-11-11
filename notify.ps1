Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$notice = New-Object System.Windows.Forms.NotifyIcon
$notice.Icon = [System.Drawing.SystemIcons]::Warning
$notice.Visible = $true
$notice.BalloonTipTitle = 'Callback Guard: review needed'
$notice.BalloonTipText = 'A download or Git checkout needs review, or a scan failed. Open Callback Guard reports. Files have not been blocked or removed.'
$notice.ShowBalloonTip(8000)
Start-Sleep -Seconds 9
$notice.Dispose()
