<#
    provision.ps1 (versión con mejoras)
    SO objetivo: Windows 11 Pro 10.0.26100
    Requiere ejecución como Administrador (auto-elevación incluida).

    Inventario CSV (único formato):
      MAC,DesiredHostname,DesiredIP

    Acciones:
      - Full        : Validar + Red estática + Renombrar + Unir a dominio (reinicia si corresponde)
      - NetOnly     : Solo red estática
      - JoinOnly    : Solo unión a dominio
      - RenameOnly  : Solo renombrar equipo
      - Validate    : DNS dominio + búsqueda en inventario por MAC (no modifica)
      - InventoryAdd: Agregar/actualizar registro al inventario (usar MAC actual)
      - CredsSetup  : Configurar credenciales seguras en el USB (portables, con ACL)
      - DryRun      : Simulación (sin cambios ni escritura)

    Dominio: instructores.senati.local
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [ValidateSet('Full','NetOnly','JoinOnly','RenameOnly','Validate','InventoryAdd','CredsSetup','DryRun')]
    [string]$Action = 'Full',

    # Dominio objetivo
    [ValidatePattern('^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
    [string]$DomainFQDN = 'instructores.senati.local',

    # Config de red
    [ValidateScript({[System.Net.IPAddress]::TryParse($_, [ref]$null)})]
    [string]$Gateway = '172.16.64.1',
    
    [ValidateScript({
        $valid = $true
        foreach ($ip in $_) { if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$null)) { $valid = $false; break } }
        $valid
    })]
    [string[]]$DnsServers = @('172.16.11.2','172.16.11.4'),
    
    [ValidateScript({[System.Net.IPAddress]::TryParse($_, [ref]$null)})]
    [string]$NetMask = '255.255.248.0',

    # Nuevo: permitir seleccionar NIC explícitamente (si no se indica, se elige la cableada activa más rápida)
    [string]$AdapterName,

    # Nuevo: no reiniciar automáticamente cuando se requiera
    [switch]$NoReboot
)

# -------------------- Config base --------------------
$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','STEP','OK')][string]$Level='INFO'
    )
    if (-not $script:LogFile) { $script:LogFile = "$env:TEMP\provision_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).log" }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $levelText = $Level.PadRight(5)
    $line = "$timestamp [$levelText] $Message"
    try { $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8 -ErrorAction Stop } catch { Write-Host "Error escribiendo en log: $($_.Exception.Message)" -ForegroundColor Red }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        'STEP'  { Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
}

function Ensure-Admin {
    param([hashtable]$BoundParams)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    Write-Log "Elevando a Administrador..." 'STEP'
    if ($PSCommandPath) {
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        foreach ($key in $BoundParams.Keys) {
            $value = $BoundParams[$key]
            if ($null -eq $value) { continue }
            if ($value -is [array]) { $argList += "-$key"; $argList += $value }
            elseif ($value -is [switch]) { if ($value.IsPresent) { $argList += "-$key" } }
            else { $argList += "-$key"; $argList += "`"$value`"" }
        }
        try { Start-Process -Verb RunAs -FilePath "powershell.exe" -ArgumentList $argList -ErrorAction Stop; exit }
        catch { Write-Log "Error al elevar: $($_.Exception.Message)" 'ERROR'; throw "No se pudo elevar a administrador. Ejecute manualmente como administrador." }
    } else { throw "Este script debe ejecutarse desde un archivo .ps1" }
}

function Get-UsbRootByLabel {
    param([string]$Label='RED_BOX')
    try {
        $vol = Get-CimInstance Win32_Volume -ErrorAction Stop | Where-Object { $_.Label -eq $Label -and $_.DriveLetter } | Select-Object -First 1
        if (-not $vol) { throw "No se encontró unidad con etiqueta '$Label'. Conecte el USB y verifique." }
        return $vol.DriveLetter
    } catch { Write-Log "Error buscando USB: $($_.Exception.Message)" 'ERROR'; throw }
}

function Init-Paths {
    try {
        $root = Get-UsbRootByLabel
        $script:UsbRoot      = $root
        $script:BaseProv     = Join-Path $root 'ROOT\OPS\SCRIPTS\PROVISION'
        $script:CsvDir       = Join-Path $root 'ROOT\OPS\SCRIPTS\BD_CSV'
        $script:CsvFile      = Join-Path $script:CsvDir 'Provision_plan.csv'
        $script:CredsDir     = Join-Path $script:BaseProv 'Creds'
        $script:AesKeyPath   = Join-Path $script:CredsDir 'domain.aes.key'
        $script:CredXmlPath  = Join-Path $script:CredsDir 'domain.cred.xml'
        $script:UserTxtPath  = Join-Path $script:CredsDir 'domain.user.txt'
        $script:LogsDir      = Join-Path $script:BaseProv 'Logs'
        foreach($dir in @($script:CsvDir,$script:CredsDir,$script:LogsDir)) { if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null } }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $script:LogFile = Join-Path $script:LogsDir "Provision_${env:COMPUTERNAME}_$timestamp.log"
        Write-Log "Estructura de directorios inicializada" 'OK'
        Write-Log "USB raíz: $root"
        Write-Log "Ruta CSV: $script:CsvFile"

        # Nuevo: transcripción completa de la sesión
        try {
            $script:TranscriptPath = Join-Path $script:LogsDir "Transcript_${env:COMPUTERNAME}_$timestamp.txt"
            Start-Transcript -Path $script:TranscriptPath -Force | Out-Null
            Write-Log "Transcript iniciado: $script:TranscriptPath" 'OK'
        } catch { Write-Log "No se pudo iniciar transcript: $($_.Exception.Message)" 'WARN' }
    } catch { Write-Log "Error inicializando rutas: $($_.Exception.Message)" 'ERROR'; throw }
}

function Normalize-Mac { param([string]$Mac) if ([string]::IsNullOrWhiteSpace($Mac)) { return $null } ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper() }

function Get-PrimaryWiredAdapter {
    param([string]$PreferredName)
    try {
        if ($PreferredName) {
            $byName = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Name -eq $PreferredName -and $_.MediaType -eq '802.3' -and $_.Status -eq 'Up' } | Select-Object -First 1
            if ($byName) { Write-Log "NIC seleccionada por nombre: $($byName.Name) (MAC: $($byName.MacAddress))" 'INFO'; return $byName }
            Write-Log "NIC '$PreferredName' no encontrada o no activa. Se seleccionará automáticamente." 'WARN'
        }
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and $_.MediaType -eq '802.3' } | Sort-Object -Property Speed -Descending
        if (-not $adapters) { throw "No se encontraron NICs físicas activas. Verifique conexión de red." }
        $selectedAdapter = $adapters | Select-Object -First 1
        Write-Log "NIC seleccionada: $($selectedAdapter.Name) (MAC: $($selectedAdapter.MacAddress))" 'INFO'
        return $selectedAdapter
    } catch { Write-Log "Error detectando adaptador: $($_.Exception.Message)" 'ERROR'; throw }
}

function Get-PrefixFromMask {
    param([string]$Mask)
    try {
        $ipAddress = [System.Net.IPAddress]::Parse($Mask)
        $bits = ($ipAddress.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') }) -join ''
        if ($bits -match '01') { throw "Máscara inválida: debe ser contigua" }
        $prefix = $bits.TrimEnd('0').Length
        if ($prefix -lt 8 -or $prefix -gt 30) { throw "Prefijo $prefix fuera de rango permitido (/8 a /30)" }
        return $prefix
    } catch { Write-Log "Error calculando prefijo: $($_.Exception.Message)" 'ERROR'; throw "Máscara de red inválida: $Mask" }
}

function Test-HostnameRule {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return "Hostname no puede estar vacío." }
    if ($Name.Length -gt 15) { return "Hostname excede 15 caracteres." }
    if ($Name -notmatch '^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,13}[a-zA-Z0-9])?$') { return "Solo letras, números y guiones internos. Sin espacios o caracteres especiales." }
    if ($Name -match '^[-]|[-]$') { return "No puede comenzar o terminar con guión." }
    return $null
}

function Load-Inventory {
    try {
        if (-not (Test-Path $script:CsvFile -PathType Leaf)) { throw "Archivo de inventario no encontrado." }
        $csv = Import-Csv -Path $script:CsvFile -Encoding UTF8
        if ($csv.Count -eq 0) { Write-Log "Inventario vacío" 'WARN'; return @() }
        $requiredColumns = 'MAC','DesiredHostname','DesiredIP'
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $csv[0].PSObject.Properties.Name }
        if ($missingColumns) { throw "Faltan columnas requeridas: $($missingColumns -join ', ')" }
        return $csv
    } catch { Write-Log "Error cargando inventario: $($_.Exception.Message)" 'ERROR'; throw }
}

function Find-RecordByMac { param($Csv,[string]$MacNorm) try { $Csv | Where-Object { (Normalize-Mac $_.MAC) -eq $MacNorm } | Select-Object -First 1 } catch { Write-Log "Error buscando en inventario: $($_.Exception.Message)" 'ERROR'; $null } }

function Ensure-InventoryRow {
    param([string]$MacNorm)
    Write-Log "Preparando registro de inventario para MAC $MacNorm..." 'STEP'
    $csv = @()
    if (Test-Path $script:CsvFile -PathType Leaf) { $csv = Import-Csv -Path $script:CsvFile -Encoding UTF8 }

    $existing = $null
    if ($csv) { $existing = Find-RecordByMac -Csv $csv -MacNorm $MacNorm }

    if ($existing) {
        Write-Log "La MAC ya existe en inventario. Se ofrecerá actualización." 'INFO'
        $currentHost = $existing.DesiredHostname
        $currentIP   = $existing.DesiredIP
        Write-Host "Registro actual → Hostname: $currentHost | IP: $currentIP" -ForegroundColor Cyan
        $doUpdate = Read-Host "¿Actualizar registro? (S/N)"
        if ($doUpdate -notin @('S','s','Y','y')) { Write-Log "No se actualizó el registro existente." 'OK'; return }
        do { $hostname = Read-Host "Nuevo DesiredHostname (máx 15). Enter para mantener '$currentHost'"; if ([string]::IsNullOrWhiteSpace($hostname)) { $hostname=$currentHost }; $hnErr = Test-HostnameRule -Name $hostname; if ($hnErr) { Write-Host "Nombre inválido: $hnErr" -ForegroundColor Red } } until (-not $hnErr)
        do { $ip = Read-Host "Nuevo DesiredIP (ej. 172.16.64.10). Enter para mantener '$currentIP'"; if ([string]::IsNullOrWhiteSpace($ip)) { $ip=$currentIP } } until ([System.Net.IPAddress]::TryParse($ip, [ref]$null))
        # Validaciones contra duplicados (excluyendo la fila actual)
        if ($csv | Where-Object { $_ -ne $existing -and $_.DesiredHostname -eq $hostname }) { throw "El hostname '$hostname' ya existe en otro registro." }
        if ($csv | Where-Object { $_ -ne $existing -and $_.DesiredIP -eq $ip }) { throw "La IP '$ip' ya está asignada a otro equipo." }
        # Actualizar en memoria y reescribir CSV completo
        $existing.DesiredHostname = $hostname
        $existing.DesiredIP       = $ip
        if ($PSCmdlet.ShouldProcess($script:CsvFile,"Actualizar fila de inventario para MAC $MacNorm")) {
            $csv | Export-Csv -Path $script:CsvFile -NoTypeInformation -Encoding UTF8 -Force
            Write-Log "Registro actualizado exitosamente" 'OK'
        }
        return
    }

    # Crear nuevo registro
    do { $hostname = Read-Host 'DesiredHostname (máx 15 caracteres)'; $hnErr = Test-HostnameRule -Name $hostname; if ($hnErr) { Write-Host "Nombre inválido: $hnErr" -ForegroundColor Red } } until (-not $hnErr)
    do { $ip = Read-Host 'DesiredIP (ej. 172.16.64.10)' } until ([System.Net.IPAddress]::TryParse($ip, [ref]$null))
    try {
        if ($csv) {
            if ($csv.DesiredHostname -contains $hostname) { throw "El hostname '$hostname' ya existe en el inventario." }
            if ($csv.DesiredIP -contains $ip) { throw "La IP '$ip' ya está asignada a otro equipo." }
        } else {
@"
MAC,DesiredHostname,DesiredIP
"@ | Out-File -FilePath $script:CsvFile -Encoding UTF8
        }
        if ($PSCmdlet.ShouldProcess($script:CsvFile,"Agregar fila de inventario para MAC $MacNorm")) {
            [pscustomobject]@{ MAC=$MacNorm; DesiredHostname=$hostname; DesiredIP=$ip } |
                Export-Csv -Path $script:CsvFile -Append -NoTypeInformation -Encoding UTF8 -Force
            Write-Log "Registro agregado exitosamente" 'OK'
        }
    } catch { Write-Log "Error agregando registro: $($_.Exception.Message)" 'ERROR'; throw }
}

function Get-TargetConfigFromInventory {
    param([bool]$Required = $true)
    try {
        $nic = Get-PrimaryWiredAdapter -PreferredName $AdapterName
        $macNorm = Normalize-Mac $nic.MacAddress
        Write-Log "Buscando configuración para MAC: $macNorm" 'INFO'
        $csv = Load-Inventory
        $record = Find-RecordByMac -Csv $csv -MacNorm $macNorm
        if (-not $record) { $msg = "MAC no encontrada en inventario. Use -Action InventoryAdd para agregar."; if ($Required) { throw $msg } else { Write-Log $msg 'WARN'; return $null } }
        $hostname = $record.DesiredHostname.Trim(); $hnError = Test-HostnameRule -Name $hostname; if ($hnError) { throw "Hostname inválido en inventario: '$hostname'. $hnError" }
        $ip = $record.DesiredIP.Trim(); if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$null)) { throw "IP inválida en inventario: '$ip'" }
        return [pscustomobject]@{ Nic=$nic; MacNorm=$macNorm; Hostname=$hostname; IP=$ip; Mask=$NetMask; Gateway=$Gateway; Dns=$DnsServers }
    } catch { Write-Log "Error obteniendo configuración: $($_.Exception.Message)" 'ERROR'; if ($Required) { throw } else { return $null } }
}

function Protect-CredsAcl {
    param([string]$TargetPath)
    try {
        $drive = $script:UsbRoot.TrimEnd('\')
        $volInfo = Get-Volume -DriveLetter $drive[0] -ErrorAction Stop
        if ($volInfo.FileSystem -ne 'NTFS') { Write-Log "Sistema de archivos no es NTFS. ACLs no aplicadas." 'WARN'; return }
        $acl = Get-Acl -Path $TargetPath
        $acl.SetAccessRuleProtection($true,$false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($adminRule); $acl.AddAccessRule($systemRule)
        if ($PSCmdlet.ShouldProcess($TargetPath,"Aplicar ACLs estrictas")) {
            Set-Acl -Path $TargetPath -AclObject $acl
        }
        Write-Log "ACLs reforzadas en $TargetPath" 'OK'
    } catch { Write-Log "Error aplicando ACLs: $($_.Exception.Message)" 'WARN' }
}

function Get-DomainCredential {
    # 1) Artefactos portables
    if ( (Test-Path $script:AesKeyPath) -and (Test-Path $script:CredXmlPath) -and (Test-Path $script:UserTxtPath) ) {
        try {
            $key        = Get-Content $script:AesKeyPath -Encoding Byte -ErrorAction Stop
            $encrypted  = Get-Content $script:CredXmlPath -Raw -ErrorAction Stop
            $secure     = ConvertTo-SecureString -String $encrypted -Key $key
            $user       = (Get-Content $script:UserTxtPath -Raw -ErrorAction Stop).Trim()
            Write-Log "Credenciales cargadas desde almacenamiento seguro" 'OK'
            return New-Object System.Management.Automation.PSCredential($user,$secure)
        } catch { Write-Log "Error cargando credenciales seguras: $($_.Exception.Message)" 'WARN' }
    }
    # 2) Prompt interactivo (no forzar UPN si ya viene con dominio)
    Write-Log "Solicitando credenciales de dominio" 'STEP'
    $userInput = Read-Host "Usuario (DOMINIO\usuario o usuario@dominio o solo usuario)"
    $securePass = Read-Host "Contraseña" -AsSecureString
    $userFinal = $userInput
    if ($userInput -notmatch '\\' -and $userInput -notmatch '@') { $userFinal = "$userInput@$DomainFQDN" }
    return New-Object System.Management.Automation.PSCredential($userFinal,$securePass)
}

function Setup-SecureCreds {
    try {
        if (-not (Test-Path $script:CredsDir)) { New-Item -ItemType Directory -Path $script:CredsDir -Force | Out-Null }
        Write-Log "Configurando credenciales seguras" 'STEP'
        $user = Read-Host "Usuario de dominio (sin dominio)"
        $pass = Read-Host "Contraseña" -AsSecureString
        if (-not (Test-Path $script:AesKeyPath)) {
            $key = New-Object byte[] 32
            [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
            if ($PSCmdlet.ShouldProcess($script:AesKeyPath,"Crear clave AES")) {
                $key | Set-Content $script:AesKeyPath -Encoding Byte -Force
            }
            Write-Log "Clave AES generada" 'OK'
        }
        $key = Get-Content $script:AesKeyPath -Encoding Byte
        $secureString = ConvertFrom-SecureString -SecureString $pass -Key $key
        if ($PSCmdlet.ShouldProcess($script:CredXmlPath,"Guardar credencial cifrada")) {
            $secureString | Set-Content $script:CredXmlPath -Force
            $user | Set-Content $script:UserTxtPath -Force
        }
        Protect-CredsAcl -TargetPath $script:CredsDir
        Protect-CredsAcl -TargetPath $script:AesKeyPath
        Protect-CredsAcl -TargetPath $script:CredXmlPath
        Protect-CredsAcl -TargetPath $script:UserTxtPath
        Write-Log "Credenciales seguras almacenadas correctamente" 'OK'
    } catch { Write-Log "Error almacenando credenciales: $($_.Exception.Message)" 'ERROR'; throw }
}

function Test-DomainReachable {
    param([string]$DomainFQDN)
    Write-Log "Validando conectividad con dominio: $DomainFQDN" 'STEP'
    try {
        # A/AAAA
        $dnsResult  = Resolve-DnsName -Name $DomainFQDN -Type A -ErrorAction Stop -DnsOnly
        $ipAddresses = $dnsResult | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress
        Write-Log "DNS resuelto: $DomainFQDN → $($ipAddresses -join ', ')" 'INFO'

        # SRV LDAP para DCs
        try {
            $srv = Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs." + $DomainFQDN) -Type SRV -ErrorAction Stop -DnsOnly
            $targets = ($srv | Where-Object Target | Select-Object -ExpandProperty Target -Unique)
            if ($targets) { Write-Log "SRV DCs: $($targets -join ', ')" 'INFO' }
        } catch { Write-Log "No se resolvió SRV de DCs (no crítico): $($_.Exception.Message)" 'WARN' }

        # Puertos esenciales con timeout 5s
        $essentialPorts = @(
            [pscustomobject]@{Port=88;   Service="Kerberos"},
            [pscustomobject]@{Port=389;  Service="LDAP"},
            [pscustomobject]@{Port=636;  Service="LDAPS"},
            [pscustomobject]@{Port=3268; Service="Global Catalog"}
        )
        $reachable = $false
        foreach ($ip in $ipAddresses) {
            Write-Log "Probando servicios en $ip" 'INFO'
            $allPortsOpen = $true
            foreach ($p in $essentialPorts) {
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $ar = $tcp.BeginConnect($ip,$p.Port,$null,$null)
                    $ok = $ar.AsyncWaitHandle.WaitOne(5000,$false)
                    if (-not $ok) { Write-Log "  Puerto $($p.Port) ($($p.Service)): TIMEOUT" 'WARN'; $allPortsOpen = $false }
                    else { $tcp.EndConnect($ar); Write-Log "  Puerto $($p.Port) ($($p.Service)): ABIERTO" 'OK' }
                } catch { Write-Log "  Puerto $($p.Port) ($($p.Service)): ERROR ($($_.Exception.Message))" 'WARN'; $allPortsOpen = $false }
                finally { if ($tcp) { $tcp.Close() } }
            }
            if ($allPortsOpen) { $reachable = $true; break }
        }
        if (-not $reachable) { throw "No se pudo conectar a servicios esenciales del dominio" }
        Write-Log "Dominio accesible correctamente" 'OK'; return $true
    } catch { Write-Log "Error conectando al dominio: $($_.Exception.Message)" 'ERROR'; return $false }
}

function Test-IpInUse {
    param([string]$IPAddress,[int]$Attempts=2,[int]$TimeoutMs=400)
    try {
        for ($i=0; $i -lt $Attempts; $i++) {
            if (Test-Connection -ComputerName $IPAddress -Count 1 -Quiet -TimeoutMilliseconds $TimeoutMs) {
                Write-Log "La IP $IPAddress responde a ping." 'WARN'
                return $true
            }
            Start-Sleep -Milliseconds 200
        }
        return $false
    } catch { Write-Log "Error probando IP en uso: $($_.Exception.Message)" 'WARN'; return $false }
}

function Configure-NetworkStatic {
    param($cfg)
    Write-Log "Configurando red estática..." 'STEP'
    try {
        $nic = $cfg.Nic
        $prefix = Get-PrefixFromMask -Mask $cfg.Mask
        $currentIP  = Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $currentDNS = Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        # Comprobar configuración actual
        $ipMatch = $false
        if ($currentIP) { 
            $ipMatch = ($currentIP | Where-Object { 
                $_.IPAddress -eq $cfg.IP -and $_.PrefixLength -eq $prefix 
            }).Count -gt 0 
        }
        
        $dnsMatch = $false
        if ($currentDNS) {
            $currentDNSServers = @($currentDNS.ServerAddresses)
            $dnsMatch = (($currentDNSServers | Sort-Object) -join ',') -eq (($cfg.Dns | Sort-Object) -join ',')
        }
        
        $gatewayObj = Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
            Where-Object NextHop | Select-Object -First 1
        $gatewayMatch = $gatewayObj -and ($gatewayObj.NextHop -eq $cfg.Gateway)
        
        if ($ipMatch -and $dnsMatch -and $gatewayMatch) { 
            Write-Log "Configuración de red ya aplicada" 'OK'; return 
        }

        # Verificar IP en uso antes de tomarla
        if (-not $ipMatch -and (Test-IpInUse -IPAddress $cfg.IP)) {
            throw "La IP $($cfg.IP) ya está en uso. Aborta para evitar conflicto."
        }

        if ($currentIP) {
            if ($PSCmdlet.ShouldProcess($nic.Name, "Eliminar IP(s) previas")) {
                $currentIP | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        if ($PSCmdlet.ShouldProcess($nic.Name, "Asignar IP $($cfg.IP)/$prefix, GW $($cfg.Gateway)")) {
            New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $cfg.IP -PrefixLength $prefix -DefaultGateway $cfg.Gateway -ErrorAction Stop | Out-Null
        }
        if ($PSCmdlet.ShouldProcess($nic.Name, "Configurar DNS @($(@($cfg.Dns) -join ', '))")) {
            Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $cfg.Dns -ErrorAction Stop | Out-Null
        }
        Write-Log "Red configurada: IP=$($cfg.IP)/$prefix, GW=$($cfg.Gateway), DNS=$(@($cfg.Dns) -join ',')" 'OK'
    } catch { Write-Log "Error configurando red: $($_.Exception.Message)" 'ERROR'; throw }
}

function Ensure-ComputerName {
    param([string]$Desired)
    $err = Test-HostnameRule -Name $Desired; if ($err) { throw $err }
    if ($env:COMPUTERNAME -eq $Desired) { Write-Log "Nombre de equipo ya es '$Desired'" 'OK'; return $false }
    try {
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Renombrar equipo a '$Desired'")) {
            Write-Log "Cambiando nombre de equipo: $env:COMPUTERNAME → $Desired" 'STEP'
            Rename-Computer -NewName $Desired -Force -ErrorAction Stop
            Write-Log "Nombre cambiado. Requiere reinicio." 'OK'
        }
        return $true
    } catch { Write-Log "Error cambiando nombre: $($_.Exception.Message)" 'ERROR'; throw }
}

function Ensure-DomainJoin {
    param([string]$DomainFQDN,[string]$NewName = $null)
    $currentDomain = (Get-CimInstance Win32_ComputerSystem).Domain
    if ($currentDomain -eq $DomainFQDN) { Write-Log "Equipo ya unido a $DomainFQDN" 'OK'; return $false }
    if ($NewName) { $err = Test-HostnameRule -Name $NewName; if ($err) { throw $err } }
    try {
        $cred = Get-DomainCredential
        $joinParams = @{ DomainName=$DomainFQDN; Credential=$cred; Force=$true; ErrorAction='Stop' }
        if ($NewName) { $joinParams['NewName'] = $NewName; Write-Log "Uniendo a dominio $DomainFQDN con nuevo nombre '$NewName'..." 'STEP' }
        else { Write-Log "Uniendo a dominio $DomainFQDN..." 'STEP' }

        if ($PSCmdlet.ShouldProcess($DomainFQDN, "Unir equipo al dominio")) {
            Add-Computer @joinParams
            Write-Log "Unión a dominio exitosa. Requiere reinicio." 'OK'
        }
        return $true
    } catch { Write-Log "Error uniendo a dominio: $($_.Exception.Message)" 'ERROR'; throw }
}

function Test-PendingReboot {
    $indicators = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    )
    foreach ($path in $indicators) { if (Test-Path $path) { Write-Log "Reinicio pendiente detectado: $path" 'WARN'; return $true } }
    $sm = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue
    if ($sm.PendingFileRenameOperations -and $sm.PendingFileRenameOperations.Length -gt 0) { Write-Log "Reinicio pendiente detectado: PendingFileRenameOperations" 'WARN'; return $true }
    return $false
}

# -------------------- Acciones --------------------
function Action-Validate {
    Write-Log "=== MODO VALIDACIÓN ===" 'STEP'
    $domainReachable = Test-DomainReachable -DomainFQDN $DomainFQDN
    $cfg = Get-TargetConfigFromInventory -Required:$false
    if ($cfg) {
        Write-Log "Configuración encontrada en inventario" 'OK'
        Write-Log "  Hostname: $($cfg.Hostname)"
        Write-Log "  IP: $($cfg.IP)"
        Write-Log "  Gateway: $($cfg.Gateway)"
        Write-Log "  DNS: $($cfg.Dns -join ', ')"
        Write-Log "  NIC: $($cfg.Nic.Name)"
    } else { Write-Log "No se encontró configuración en inventario" 'WARN' }
    if ($domainReachable) { Write-Log "Validación completada satisfactoriamente" 'OK' } else { Write-Log "Validación completada con advertencias" 'WARN' }
}

function Action-NetOnly {
    Write-Log "=== CONFIGURACIÓN DE RED ===" 'STEP'
    $cfg = Get-TargetConfigFromInventory -Required:$true
    Configure-NetworkStatic -cfg $cfg
    Write-Log "Configuración de red completada" 'OK'
}

function Action-JoinOnly {
    Write-Log "=== UNIÓN A DOMINIO ===" 'STEP'
    if (Test-PendingReboot) { throw "Reinicio pendiente detectado. Complete reinicios pendientes primero." }
    if (-not (Test-DomainReachable -DomainFQDN $DomainFQDN)) { throw "Dominio no accesible. Verifique conectividad de red." }
    $needsReboot = Ensure-DomainJoin -DomainFQDN $DomainFQDN
    if ($needsReboot) {
        if ($NoReboot) { Write-Log "Reinicio requerido, omitido por -NoReboot" 'WARN' }
        else { Write-Log "Reiniciando en 10 segundos..." 'STEP'; Start-Sleep 10; Restart-Computer -Force }
    }
}

function Action-RenameOnly {
    Write-Log "=== CAMBIO DE NOMBRE ===" 'STEP'
    if (Test-PendingReboot) { throw "Reinicio pendiente detectado. Complete reinicios pendientes primero." }
    $cfg = Get-TargetConfigFromInventory -Required:$true
    $needsReboot = Ensure-ComputerName -Desired $cfg.Hostname
    if ($needsReboot) {
        if ($NoReboot) { Write-Log "Reinicio requerido, omitido por -NoReboot" 'WARN' }
        else { Write-Log "Reiniciando en 10 segundos..." 'STEP'; Start-Sleep 10; Restart-Computer -Force }
    }
}

function Action-Full {
    Write-Log "=== PROVISIÓN COMPLETA ===" 'STEP'
    if (Test-PendingReboot) { throw "Reinicio pendiente detectado. Complete reinicios pendientes primero." }
    $domainAccessible = Test-DomainReachable -DomainFQDN $DomainFQDN
    if (-not $domainAccessible) { Write-Log "Advertencia: El dominio no es accesible. Continuando con precaución." 'WARN' }
    $cfg = Get-TargetConfigFromInventory -Required:$true
    Configure-NetworkStatic -cfg $cfg
    $needsReboot = Ensure-DomainJoin -DomainFQDN $DomainFQDN -NewName $cfg.Hostname
    if ($needsReboot) {
        if ($NoReboot) { Write-Log "Reinicio requerido, omitido por -NoReboot" 'WARN' }
        else { Write-Log "Reiniciando en 10 segundos..." 'STEP'; Start-Sleep 10; Restart-Computer -Force }
    } else { Write-Log "Provisionamiento completado sin requerir reinicio" 'OK' }
}

function Action-InventoryAdd {
    Write-Log "=== AGREGAR/ACTUALIZAR INVENTARIO ===" 'STEP'
    $nic = Get-PrimaryWiredAdapter -PreferredName $AdapterName
    $macNorm = Normalize-Mac $nic.MacAddress
    Ensure-InventoryRow -MacNorm $macNorm
}

function Action-CredsSetup { Write-Log "=== CONFIGURAR CREDENCIALES ===" 'STEP'; Setup-SecureCreds }

function Action-DryRun {
    Write-Log "=== SIMULACIÓN (sin cambios reales) ===" 'STEP'
    $domainAccessible = Test-DomainReachable -DomainFQDN $DomainFQDN
    $cfg = Get-TargetConfigFromInventory -Required:$false
    if ($cfg) {
        $prefix = Get-PrefixFromMask -Mask $cfg.Mask
        Write-Log "Simularía configurar red:"; Write-Log "  IP: $($cfg.IP)/$prefix"; Write-Log "  Gateway: $($cfg.Gateway)"; Write-Log "  DNS: $(@($cfg.Dns) -join ', ')"
        if ($cfg.Hostname -ne $env:COMPUTERNAME) { Write-Log "Simularía cambiar nombre: $env:COMPUTERNAME → $($cfg.Hostname)" }
        Write-Log "Simularía unir al dominio $DomainFQDN"
    } else { Write-Log "No se encontró configuración en inventario" 'WARN' }
    Write-Log "Simulación completada" 'OK'
}

# -------------------- Main --------------------
try {
    Ensure-Admin -BoundParams $PSBoundParameters
    Init-Paths
    Write-Log "Iniciando acción: $Action" 'STEP'
    Write-Log "Equipo actual: $env:COMPUTERNAME" 'INFO'
    Write-Log "Usuario: $env:USERNAME" 'INFO'
    Write-Log "Sistema operativo: $((Get-CimInstance Win32_OperatingSystem).Caption)" 'INFO'
    Write-Log "Parámetros: DomainFQDN=$DomainFQDN | Gateway=$Gateway | NetMask=$NetMask | DNS=$(@($DnsServers) -join ', ') | AdapterName=$AdapterName | NoReboot=$($NoReboot.IsPresent)" 'INFO'

    switch ($Action) {
        'Validate'     { Action-Validate }
        'NetOnly'      { Action-NetOnly }
        'JoinOnly'     { Action-JoinOnly }
        'RenameOnly'   { Action-RenameOnly }
        'Full'         { Action-Full }
        'InventoryAdd' { Action-InventoryAdd }
        'CredsSetup'   { Action-CredsSetup }
        'DryRun'       { Action-DryRun }
        default        { throw "Acción no implementada: $Action" }
    }
    Write-Log "Acción '$Action' completada satisfactoriamente" 'OK'
}
catch {
    $errorLine = $_.InvocationInfo.ScriptLineNumber
    $errorMsg = $_.Exception.Message
    Write-Log "ERROR en línea $errorLine: $errorMsg" 'ERROR'
    Write-Log "Acción fallida. Consulte el log: $script:LogFile" 'ERROR'
    exit 1
}
finally {
    $duration = [math]::Round((New-TimeSpan -Start $script:StartTime).TotalMinutes, 2)
    Write-Log "Tiempo total de ejecución: $duration minutos" 'INFO'
    try { Stop-Transcript | Out-Null } catch { }
}
