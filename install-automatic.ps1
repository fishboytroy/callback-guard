$ErrorActionPreference = 'Stop'
$guardRoot = $PSScriptRoot
$runtime = Join-Path $guardRoot 'automatic-state'
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$python = (Get-Command python.exe).Source
$pythonw = Join-Path (Split-Path $python) 'pythonw.exe'
if (!(Test-Path -LiteralPath $pythonw)) { throw 'pythonw.exe is required for the background monitor.' }
$currentHooks = & git config --global --get core.hooksPath
if ($currentHooks) { throw 'Existing core.hooksPath requires integration; nothing has been replaced.' }
$oldTemplate = & git config --global --get init.templateDir
$template = Join-Path $runtime 'git-template'
$installation = Join-Path $runtime 'installation.json'
if ($oldTemplate -and $oldTemplate -ne $template) { throw 'A different Git template is configured; refusing to replace it.' }
if (!(Test-Path -LiteralPath $installation)) {
    if ($oldTemplate) { throw 'Existing init.templateDir requires integration; nothing has been replaced.' }
    @{ previousTemplate = $null; template = $template; installed = (Get-Date).ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $installation -Encoding UTF8
}
New-Item -ItemType Directory -Path (Join-Path $template 'hooks') -Force | Out-Null
$execPath = & git --exec-path
$gitPrefix = Split-Path (Split-Path $execPath)
$stock = Join-Path $gitPrefix 'share/git-core/templates'
if (!(Test-Path -LiteralPath $stock)) { throw "Cannot locate Git stock templates: $stock" }
Copy-Item -Path (Join-Path $stock '*') -Destination $template -Recurse -Force
$pythonSh = $python.Replace('\', '/')
$automaticSh = (Join-Path $guardRoot 'automatic.py').Replace('\', '/')
if ($pythonSh.Contains("'") -or $automaticSh.Contains("'")) { throw 'Single quote in installation path unsupported.' }
$hook = "#!/bin/sh`n# Callback Guard: after-checkout scan; does not quarantine or undo checkout.`nexec '$pythonSh' -E -s '$automaticSh' --repo .`n"
[System.IO.File]::WriteAllText((Join-Path $template 'hooks/post-checkout'), $hook, (New-Object System.Text.UTF8Encoding($false)))
& git config --global init.templateDir $template
if ($LASTEXITCODE -ne 0) { throw 'Could not configure Git template.' }
$startup = [Environment]::GetFolderPath('Startup')
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $startup 'Callback Guard Downloads.lnk'))
$shortcut.TargetPath = $pythonw
$shortcut.Arguments = '-E -s "' + (Join-Path $guardRoot 'automatic.py') + '" --monitor'
$shortcut.WorkingDirectory = $guardRoot
$shortcut.WindowStyle = 7
$shortcut.Description = 'Scan completed browser downloads and report findings; does not block originals.'
$shortcut.Save()
$stop = Join-Path $runtime 'stop.request'
if (Test-Path -LiteralPath $stop) { Remove-Item -LiteralPath $stop }
Start-Process -FilePath $pythonw -ArgumentList $shortcut.Arguments -WorkingDirectory $guardRoot -WindowStyle Hidden
Write-Output 'Installed login startup and Git template hook. Monitor started.'
Write-Output "Status and reports: $runtime"
