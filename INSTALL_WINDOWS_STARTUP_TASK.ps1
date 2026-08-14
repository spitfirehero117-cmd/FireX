
$ErrorActionPreference = "Stop"

$Folder = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = (Get-Command python).Source
$Server = Join-Path $Folder "server.py"
$TaskName = "NFC Crew System V6"

$Action = New-ScheduledTaskAction `
  -Execute $Python `
  -Argument "`"$Server`"" `
  -WorkingDirectory $Folder

$Trigger = New-ScheduledTaskTrigger -AtStartup

$Settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero)

$Principal = New-ScheduledTaskPrincipal `
  -UserId $env:USERNAME `
  -LogonType S4U `
  -RunLevel Highest

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $Action `
  -Trigger $Trigger `
  -Settings $Settings `
  -Principal $Principal `
  -Force

Write-Host ""
Write-Host "Installed Windows startup task: $TaskName"
Write-Host "It will start at boot and Windows will retry after failures."
Write-Host ""
