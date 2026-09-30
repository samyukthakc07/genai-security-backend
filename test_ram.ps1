
$p = Start-Process -PassThru -FilePath "C:\garak\venv\Scripts\python.exe" -ArgumentList "-m garak --model_type ollama.OllamaGeneratorChat --model_name llama3.2:3b --probes promptinject" -NoNewWindow
Start-Sleep -Seconds 2
for ($i=0; $i -lt 10; $i++) {
    if ($p.HasExited) { break }
    Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" | Select-Object @{Name="RAM (MB)";Expression={[math]::Round($_.WorkingSetSize / 1MB, 2)}} | Format-Table -HideTableHeaders
    Start-Sleep -Seconds 2
}
if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }

