<#
  Export-FirefoxPasswords.ps1
  Exporta las credenciales guardadas en Firefox a un TXT (tabulado).
  Uso normal:
     powershell -ExecutionPolicy Bypass -File .\Export-FirefoxPasswords.ps1
  Si tienes contrasena maestra en Firefox:
     powershell -ExecutionPolicy Bypass -File .\Export-FirefoxPasswords.ps1 -MasterPassword "tuClave"
  Requiere Windows 10/11 (usa winsqlite3.dll) y ejecutarse con el mismo usuario de Windows.
#>
param(
    [string]$MasterPassword = '',
    [string]$OutFile = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'firefox_passwords.txt')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path "$env:SystemRoot\System32\winsqlite3.dll")) {
    throw "Falta winsqlite3.dll (Windows 10 1809+ / Windows 11)."
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Sql3 {
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)]
    public static extern int sqlite3_open_v2(string filename, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)]
    public static extern int sqlite3_prepare_v2(IntPtr db, string sql, int nBytes, out IntPtr stmt, IntPtr tail);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    public static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    public static extern IntPtr sqlite3_column_blob(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    public static extern int sqlite3_column_bytes(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    public static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]
    public static extern int sqlite3_close(IntPtr db);
}
"@

function Get-MetadataBlobs {
    param([string]$DbPath)
    $db = [IntPtr]::Zero
    if ([Sql3]::sqlite3_open_v2($DbPath, [ref]$db, 1, [IntPtr]::Zero) -ne 0) { return $null }
    $stmt = [IntPtr]::Zero
    $res = $null
    try {
        if ([Sql3]::sqlite3_prepare_v2($db, "SELECT item1, item2 FROM metadata WHERE id = 'password'", -1, [ref]$stmt, [IntPtr]::Zero) -eq 0) {
            if ([Sql3]::sqlite3_step($stmt) -eq 100) {
                $p1 = [Sql3]::sqlite3_column_blob($stmt, 0); $n1 = [Sql3]::sqlite3_column_bytes($stmt, 0)
                $p2 = [Sql3]::sqlite3_column_blob($stmt, 1); $n2 = [Sql3]::sqlite3_column_bytes($stmt, 1)
                $b1 = New-Object byte[] $n1
                $b2 = New-Object byte[] $n2
                if ($n1 -gt 0) { [System.Runtime.InteropServices.Marshal]::Copy($p1, $b1, 0, $n1) }
                if ($n2 -gt 0) { [System.Runtime.InteropServices.Marshal]::Copy($p2, $b2, 0, $n2) }
                $res = @{ item1 = $b1; item2 = $b2 }
            }
        }
    } finally {
        if ($stmt -ne [IntPtr]::Zero) { [void][Sql3]::sqlite3_finalize($stmt) }
        [void][Sql3]::sqlite3_close($db)
    }
    return $res
}

function Get-OctetStrings {
    param([byte[]]$Data)
    $res = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $Data.Length) {
        $tag = [int]$Data[$i]; $i++
        if ($i -ge $Data.Length) { break }
        $len = [int]$Data[$i]; $i++
        if (($len -band 0x80) -ne 0) {
            $n = $len -band 0x7F
            $len = 0
            for ($j = 0; $j -lt $n; $j++) { $len = ($len -shl 8) + [int]$Data[$i]; $i++ }
        }
        if ($len -gt ($Data.Length - $i)) { break }
        $val = New-Object byte[] $len
        if ($len -gt 0) { [Array]::Copy($Data, $i, $val, 0, $len) }
        if ($tag -eq 0x04) { [void]$res.Add($val) }
        if ((($tag -band 0x20) -ne 0) -and $len -gt 0) {
            foreach ($o in (Get-OctetStrings -Data $val)) { [void]$res.Add($o) }
        }
        $i += $len
    }
    return $res
}

function Get-FirefoxKey {
    param([byte[]]$Item1, [byte[]]$Item2, [string]$Master)
    if ($Item2.Length -eq 0 -or ($Item2.Length % 16) -ne 0) { return $null }

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $mp   = [System.Text.Encoding]::UTF8.GetBytes($Master)
    $octs = Get-OctetStrings -Data $Item1

    $salts = New-Object System.Collections.ArrayList
    [void]$salts.Add([byte[]]$Item1[0..([Math]::Min(19, $Item1.Length - 1))])
    foreach ($o in $octs) { [void]$salts.Add($o) }

    foreach ($salt in $salts) {
        $hp = $sha1.ComputeHash([byte[]]($salt + $mp))
        foreach ($entrySalt in $octs) {
            $pes = New-Object byte[] 20
            [Array]::Copy($entrySalt, $pes, [Math]::Min(20, $entrySalt.Length))
            $chp = $sha1.ComputeHash([byte[]]($hp + $pes))

            $hm = New-Object System.Security.Cryptography.HMACSHA1
            $hm.Key = $chp
            $k1 = $hm.ComputeHash([byte[]]($pes + $entrySalt))
            $tk = $hm.ComputeHash($pes)
            $k2 = $hm.ComputeHash([byte[]]($tk + $entrySalt))
            $k  = [byte[]]($k1 + $k2)

            $aesKey = $k[0..31]
            $ivs = @(, $k[32..47])
            foreach ($o in $octs) { if ($o.Length -eq 16) { $ivs += , $o } }

            foreach ($iv in $ivs) {
                try {
                    $aes = [System.Security.Cryptography.Aes]::Create()
                    $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.Key = $aesKey; $aes.IV = $iv
                    $plain = $aes.CreateDecryptor().TransformFinalBlock($Item2, 0, $Item2.Length)
                } catch { continue }

                if ([System.Text.Encoding]::ASCII.GetString($plain) -match 'password-check') {
                    $inner = Get-OctetStrings -Data $plain
                    $cands = @($inner | Where-Object { $_.Length -ge 16 })
                    if ($cands.Count -gt 0) { return , $cands[-1] }
                }
            }
        }
    }
    return $null
}

function Try-DecryptField {
    param([string]$B64, [byte[]]$Key)
    if ([string]::IsNullOrEmpty($B64)) { return '' }
    try { $raw = [Convert]::FromBase64String($B64) } catch { return '<ilegible>' }
    if ($raw.Length -le 20) { return '' }

    foreach ($ivLen in 16, 12) {
        if ($raw.Length -le (3 + $ivLen)) { continue }
        $iv = New-Object byte[] 16
        [Array]::Copy($raw, 3, $iv, 0, [Math]::Min($ivLen, 16))
        $ct = New-Object byte[] ($raw.Length - 3 - $ivLen)
        [Array]::Copy($raw, 3 + $ivLen, $ct, 0, $ct.Length)
        try {
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $Key; $aes.IV = $iv
            $plain = $aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)
            return [System.Text.Encoding]::UTF8.GetString($plain)
        } catch { }
    }
    return '<no descifrado>'
}

# ------------------------- ejecucion -------------------------
$root = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
if (-not (Test-Path $root)) { throw "No hay perfiles de Firefox en $root" }

$result = New-Object System.Collections.ArrayList
foreach ($prof in Get-ChildItem $root -Directory) {
    $lj  = Join-Path $prof.FullName 'logins.json'
    $kdb = Join-Path $prof.FullName 'key4.db'
    if (-not (Test-Path $lj) -or -not (Test-Path $kdb)) { continue }

    $tmp = Join-Path $env:TEMP ("ffpw_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Copy-Item $lj $tmp -Force
    Copy-Item $kdb $tmp -Force
    try {
        $meta = Get-MetadataBlobs -DbPath (Join-Path $tmp 'key4.db')
        if (-not $meta) { Write-Warning "key4.db ilegible en perfil $($prof.Name)"; continue }

        $key = Get-FirefoxKey -Item1 $meta.item1 -Item2 $meta.item2 -Master $MasterPassword
        if (-not $key) { Write-Warning "No pude obtener la clave de $($prof.Name) (revisa la contrasena maestra)."; continue }

        $json = Get-Content (Join-Path $tmp 'logins.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $json.logins) { continue }

        foreach ($l in $json.logins) {
            [void]$result.Add([pscustomobject]@{
                Perfil   = $prof.Name
                Url      = $l.hostname
                Usuario  = (Try-DecryptField $l.encryptedUsername $key)
                Password = (Try-DecryptField $l.encryptedPassword $key)
            })
        }
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($result.Count -eq 0) { Write-Host "No se encontraron credenciales."; return }

$lines = $result | ForEach-Object { "{0}`t{1}`t{2}`t{3}" -f $_.Perfil, $_.Url, $_.Usuario, $_.Password }
(@("Perfil`tURL`tUsuario`tPassword") + $lines) | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host "$($result.Count) credenciales exportadas a $OutFile"