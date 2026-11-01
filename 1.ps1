$output = "$env:USERPROFILE\Desktop\wifi_passwords.txt"

# Obtener perfiles WiFi
$profiles = netsh wlan show profiles |
    Select-String ':\s*(.+)$' |
    ForEach-Object {
        $_.Matches[0].Groups[1].Value.Trim()
    }

# Limpiar archivo anterior
Set-Content -Path $output -Value "" -Encoding UTF8

foreach ($profile in $profiles) {

    Write-Host "Procesando: $profile" -ForegroundColor Cyan

    $result = netsh wlan show profile name="$profile" key=clear

    $passwordLine = $result |
        Select-String 'Key Content|Contenido de la clave'

    if ($passwordLine) {
        $password = ($passwordLine.ToString() -split ':', 2)[1].Trim()
        Add-Content -Path $output -Value "$profile : $password"
    }
    else {
        Add-Content -Path $output -Value "$profile : Sin contraseña disponible"
    }
}

Write-Host "Archivo generado: $output" -ForegroundColor Green