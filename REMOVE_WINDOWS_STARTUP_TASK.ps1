
$TaskName = "NFC Crew System V6"
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "Removed Windows startup task: $TaskName"
