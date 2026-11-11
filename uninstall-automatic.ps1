$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot 'automatic-state'
[System.IO.File]::WriteAllText((Join-Path $runtime 'stop.request'), '')
$startupLink = Join-Path ([Environment]::GetFolderPath('Startup')) 'Callback Guard Downloads.lnk'
if (Test-Path -LiteralPath $startupLink) { Remove-Item -LiteralPath $startupLink }
$installedTemplate = Join-Path $runtime 'git-template'
$currentTemplate = & git config --global --get init.templateDir
if ($currentTemplate -eq $installedTemplate) { & git config --global --unset init.templateDir }
Write-Output 'Login monitor disabled; Git default template restored if still owned by Callback Guard.'
Write-Output 'Hooks already copied into cloned repositories remain. Remove their .git/hooks/post-checkout only if it is the Callback Guard hook.'
Write-Output 'Reports have been retained. A currently running scan can take up to two minutes to finish.'
