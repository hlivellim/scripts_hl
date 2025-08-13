<#
  Provision.ps1 — Aprovisionamiento local idempotente (join unificado)
  - Busca MAC Ethernet en Provision_Plan.csv
  - Valida plan (regex hostname, no-solo-numérico, duplicados, IP en /21, no red/gw/broadcast)
  - Detecta IP en uso (Ping + ARP + NBNS best-effort)
  - Configura NIC: IP /21, GW 172.16.64.1, DNS 172.16.11.2/172.16.11.4
  - Aplica sufijo DNS instructores.senati.local (global e interfaz)
  - **Unificado**: si no está en dominio y debe renombrar, usa Add-Computer -NewName
  - Si ya está en el dominio y debe renombrar, usa Rename-Computer con credencial de dominio
  - ODJ soportado con djoin.exe (+ Rename-Computer si corresponde)
  - Reinicio auto si hace falta (30s, firme) / 3010 con -NoReboot / 5s con -RebootNow
  - Logs + backup NIC + Results CSV + JSON resultado
#>

[CmdletBinding()]
param(
  [string]$PlanPath,
  [string]$ResultsPath,
  [string]$Domain,
  [string]$UserNetbios,
  [string]$NicName,
  [string]$NicId,
  [int]   $NicIndex,
  [switch]$DisableWifi,
  [switch]$NoWifiAuto,
  [switch]$DryRun,
  [switch]$Force,
  [switch]$NoReboot,
  [switch]$RebootNow,
  [int]   $RebootDelay = 30,
  [switch]$ValidatePlan,
  [string]$ODJBlobPath
)

# ====== Constantes / INI ======
$ScriptsDir     = Split-Path -Parent $PSScriptRoot
$BDCSVDir       = Join-Path $ScriptsDir 'BD_CSV'
$ProvDir        = $PSScriptRoot
$LogsDir        = Join-Path $ProvDir 'logs'
$PlanDefault    = Join-Path $BDCSVDir 'Provision_Plan.csv'
$ResultsDefault = Join-Path $BDCSVDir 'Provision_Results.csv'
$PrefsIni       = Join-Path $ProvDir 'Provision_prefs.ini'

$cfg = [ordered]@{
  Domain             = 'instructores.senati.local'
  NetbiosDomain      = 'INSTRUCTORES'
  JoinUser           = 'hlivelli-instructore'
  SubnetPrefixLength = 21
  Gateway            = '172.16.64.1'
  DnsServers         = @('172.16.11.2','172.16.11.4')
  DnsSuffix          = 'instructores.senati.local'
  PlanPath           = $PlanDefault
  ResultsPath        = $ResultsDefault
  LogsRetentionDays  = 30
  VlanSubnet         = '172.16.64.0'
  AutoDisableWifi    = $true
}

# Leer INI (clave=valor)
if (Test-Path -LiteralPath $PrefsIni) {
  foreach($line in (Get-Content -LiteralPath $PrefsIni)){
    if ($line -match '^\s*#' -or -not ($line -match '=')) { continue }
    $k,$v = $line.Split('=',2); $k=$k.Trim(); $v=$v.Trim()
    switch -Regex ($k) {
      '^Domain$'             { if($v){ $cfg.Domain = $v } }
      '^NetbiosDomain$'      { if($v){ $cfg.NetbiosDomain = $v } }
      '^JoinUser$'           { if($v){ $cfg.JoinUser = $v } }
      '^SubnetPrefixLength$' { if($v){ $cfg.SubnetPrefixLength = [int]$v } }
      '^Gateway$'            { if($v){ $cfg.Gateway = $v } }
      '^DnsServers$'         { if($v){ $cfg.DnsServers = $v.Split(',') | ForEach-Object { $_.Trim() } } }
      '^DnsSuffix$'          { if($v){ $cfg.DnsSuffix = $v } }
      '^PlanPath$'           { if($v){ $cfg.PlanPath = $v } }
      '^ResultsPath$'        { if($v){ $cfg.ResultsPath = $v } }
      '^LogsRetentionDays$'  { if($v){ $cfg.LogsRetentionDays = [int]$v } }
      '^VlanSubnet$'         { if($v){ $cfg.VlanSubnet = $v } }
      '^AutoDisableWifi$'    { if($v){ $cfg.AutoDisableWifi = ($v -match '^(1|true|yes)$') } }
    }
  }
}

# Overrides por parámetros
if($PlanPath){     $cfg.PlanPath    = $PlanPath }
if($ResultsPath){  $cfg.ResultsPath = $ResultsPath }
if($Domain){       $cfg.Domain      = $Domain }
if($UserNetbios){  $cfg.JoinUser    = $UserNetbios -replace '^.*\\','' ; $cfg.NetbiosDomain = ($UserNetbios -split '\\',2)[0] }

# Rutas relativas -> absolutas (respecto a $ProvDir)
foreach($k in 'PlanPath','ResultsPath'){
  $v = $cfg[$k]
  if($v -and -not [IO.Path]::IsPathRooted($v)){
    $cfg[$k] = Join-Path $ProvDir $v
  }
}

# ====== Utilitarios ======
function Ensure-Dir([string]$p){ if(-not (Test-Path -LiteralPath $p)){ New-Item -ItemType Directory -Path $p -Force | Out-Null } }

function Normalize-Mac([string]$s){
  if([string]::IsNullOrWhiteSpace($s)){ return $null }
  $hex = ($s -replace '[^0-9A-Fa-f]', '').ToUpper()
  if($hex.Length -ne 12){ return $null }
  return [string]::Join(':', (0..5 | ForEach-Object { $hex.Substring($_*2,2) }))
}

function Is-NumericOnly([string]$s){ return ($s -match '^\d+$') }

function Test-Cidr([string]$ip,[string]$net,[int]$prefix){
  try{
    $ipB=[Net.IPAddress]::Parse($ip).GetAddressBytes();[array]::Reverse($ipB);$ip32=[BitConverter]::ToUInt32($ipB,0)
    $ntB=[Net.IPAddress]::Parse($net).GetAddressBytes();[array]::Reverse($ntB);$nt32=[BitConverter]::ToUInt32($ntB,0)
    $mask=[uint32]0;for($i=0;$i -lt $prefix;$i++){$mask=$mask -bor (1 -shl (31-$i))}
    return (($ip32 -band $mask) -eq ($nt32 -band $mask))
  }catch{ return $false }
}

function Resolve-Delimiter([string]$path){
  $line = (Get-Content -LiteralPath $path -TotalCount 5 | Where-Object { $_ -and $_ -notmatch '^\s*#' } | Select-Object -First 1)
  if(-not $line){ return ',' }
  $c = ($line.ToCharArray() | Group-Object | Where-Object { $_.Name -in ',',';' } | Sort-Object Count -Descending | Select-Object -First 1).Name
  if(-not $c){ return ',' } else { return $c }
}

function Import-Plan([string]$path){
  if(-not (Test-Path -LiteralPath $path)){
    Ensure-Dir (Split-Path -Parent $path)
    @(
      '# Provision_Plan.csv - plantilla inicial'
      'MAC,DesiredHostname,DesiredIP,Enabled,Notes'
      'AA:BB:CC:DD:EE:01,PC-AULA01,172.16.66.25,1,"Equipo docente, aula 1"'
      'AA:BB:CC:DD:EE:02,PC-AULA02,172.16.66.26,1,"Mouse reemplazado"'
    ) | Set-Content -LiteralPath $path -Encoding UTF8
  }
  $delim = Resolve-Delimiter $path
  $raw   = Get-Content -LiteralPath $path
  $clean = $raw | Where-Object { $_ -and $_ -notmatch '^\s*#' }
  $tmp   = Join-Path $env:TEMP ("plan_{0}.csv" -f ([guid]::NewGuid()))
  $clean | Set-Content -LiteralPath $tmp -Encoding UTF8
  try{
    $csv = Import-Csv -LiteralPath $tmp -Delimiter $delim
  } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

  if(-not $csv -or $csv.Count -eq 0){ return @() }

  function Find-ColName($obj,[string]$key){
    foreach($p in $obj.PSObject.Properties){
      if( (($p.Name -replace '\s','').ToLower()) -eq $key ){ return $p.Name }
    }
    return $null
  }
  $hMAC  = Find-ColName $csv[0] 'mac'
  $hHOST = Find-ColName $csv[0] 'desiredhostname'
  $hIP   = Find-ColName $csv[0] 'desiredip'
  $hEN   = Find-ColName $csv[0] 'enabled'
  $hNOT  = Find-ColName $csv[0] 'notes'
  if(-not $hMAC -or -not $hHOST -or -not $hIP){
    throw "El CSV debe contener columnas: MAC, DesiredHostname, DesiredIP."
  }
  foreach($row in $csv){
    if($hMAC  -ne 'MAC'){                 Add-Member -InputObject $row -NotePropertyName 'MAC'             -NotePropertyValue $row.$hMAC  -Force }
    if($hHOST -ne 'DesiredHostname'){     Add-Member -InputObject $row -NotePropertyName 'DesiredHostname' -NotePropertyValue $row.$hHOST -Force }
    if($hIP   -ne 'DesiredIP'){           Add-Member -InputObject $row -NotePropertyName 'DesiredIP'       -NotePropertyValue $row.$hIP   -Force }
    if($hEN   -and $hEN -ne 'Enabled'){   Add-Member -InputObject $row -NotePropertyName 'Enabled'         -NotePropertyValue $row.$hEN   -Force }
    if($hNOT  -and $hNOT -ne 'Notes'){    Add-Member -InputObject $row -NotePropertyName 'Notes'           -NotePropertyValue $row.$hNOT  -Force }
  }
  return $csv
}

function Validate-PlanRows($rows){
  $errors = @()
  if(-not $rows -or $rows.Count -eq 0){ $errors += "El CSV está vacío."; return $errors }

  $idxMAC=@{};$idxHost=@{};$idxIP=@{}

  foreach($row in $rows){
    $row.MAC             = Normalize-Mac $row.MAC
    $row.DesiredHostname = ("" + $row.DesiredHostname).Trim().ToUpper()
    $row.DesiredIP       = ("" + $row.DesiredIP).Trim()
    $row.Enabled         = if([string]::IsNullOrWhiteSpace($row.Enabled)) { '1' } else { $row.Enabled.Trim() }

    if(-not $row.MAC){ $errors += "Fila con MAC inválida."; continue }
    if(-not $row.DesiredHostname){ $errors += "[$($row.MAC)] DesiredHostname vacío." }
    if(-not $row.DesiredIP){ $errors += "[$($row.MAC)] DesiredIP vacío." }
    if($row.Enabled -notmatch '^(0|1)$'){ $row.Enabled = '1' }

    # Regex correcta para hostname
    if($row.DesiredHostname -notmatch '^[A-Z0-9-]{1,15}$'){
      $errors += "[$($row.MAC)] Hostname no cumple '^[A-Z0-9-]{1,15}$': '$($row.DesiredHostname)'."
    }
    if($row.DesiredHostname -match '(^-|-$)|\s|\.'){ $errors += "[$($row.MAC)] Hostname con espacios/puntos o inicia/termina en guion." }
    if(Is-NumericOnly $row.DesiredHostname){ $errors += "[$($row.MAC)] Hostname solo numérico no permitido." }

    try{
      [void][Net.IPAddress]::Parse($row.DesiredIP)
      if(-not (Test-Cidr $row.DesiredIP $cfg.VlanSubnet $cfg.SubnetPrefixLength)){ $errors += "[$($row.MAC)] IP fuera de $($cfg.VlanSubnet)/$($cfg.SubnetPrefixLength): $($row.DesiredIP)" }
      # calcular broadcast
      $netBase = [Net.IPAddress]::Parse($cfg.VlanSubnet).GetAddressBytes()
      [array]::Reverse($netBase); $nt32=[BitConverter]::ToUInt32($netBase,0)
      $mask=[uint32]0;for($i=0;$i -lt $cfg.SubnetPrefixLength;$i++){$mask=$mask -bor (1 -shl (31-$i))}
      $bcast = $nt32 -bor (-bnot $mask)
      $bcB=[byte[]](0,0,0,0); [BitConverter]::GetBytes($bcast).CopyTo($bcB,0); [array]::Reverse($bcB)
      $broadcast=[Net.IPAddress]::new($bcB).IPAddressToString
      if($row.DesiredIP -in @($cfg.Gateway,$cfg.VlanSubnet,$broadcast)){ $errors += "[$($row.MAC)] IP reservada (gateway/red/broadcast): $($row.DesiredIP)" }
    }catch{ $errors += "[$($row.MAC)] IP inválida: $($row.DesiredIP)" }

    if(-not $idxMAC.ContainsKey($row.MAC)){ $idxMAC[$row.MAC]=0 }; $idxMAC[$row.MAC]++
    if($row.DesiredHostname){ if(-not $idxHost.ContainsKey($row.DesiredHostname)){ $idxHost[$row.DesiredHostname]=0 }; $idxHost[$row.DesiredHostname]++ }
    if($row.DesiredIP){ if(-not $idxIP.ContainsKey($row.DesiredIP)){ $idxIP[$row.DesiredIP]=0 }; $idxIP[$row.DesiredIP]++ }
  }

  $dupMac  = $idxMAC.GetEnumerator()  | Where-Object { $_.Value -gt 1 } | ForEach-Object { $_.Key }
  $dupHost = $idxHost.GetEnumerator() | Where-Object { $_.Value -gt 1 } | ForEach-Object { $_.Key }
  $dupIP   = $idxIP.GetEnumerator()   | Where-Object { $_.Value -gt 1 } | ForEach-Object { $_.Key }
  if($dupMac){  $errors += "MAC duplicada(s): $($dupMac -join ', ')" }
  if($dupHost){ $errors += "DesiredHostname duplicado(s): $($dupHost -join ', ')" }
  if($dupIP){   $errors += "DesiredIP duplicada(s): $($dupIP -join ', ')" }

  return $errors
}

# … (el resto del script se mantiene igual que en la versión anterior)

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-LocalEthernetMacAndAdapter {
  $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {
    $_.Status -ne 'Disabled' -and $_.HardwareInterface -and $_.InterfaceDescription -notmatch 'Wireless|Wi-?Fi|802\.11'
  }

  if($NicId){
    $sel = $adapters | Where-Object { $_.InterfaceGuid -eq $NicId }
    if(-not $sel){ throw "No se encontró NIC por NicId=$NicId" }
    return $sel
  }
  if($NicIndex){
    $sel = $adapters | Where-Object { $_.ifIndex -eq $NicIndex }
    if(-not $sel){ throw "No se encontró NIC por NicIndex=$NicIndex" }
    return $sel
  }
  if($NicName){
    $sel = $adapters | Where-Object { $_.Name -eq $NicName }
    if(-not $sel){ throw "No se encontró NIC por NicName EXACTO='$NicName'" }
    return $sel
  }

  $ipcfg = Get-NetIPConfiguration -All

  # 1) NIC en VLAN /21
  $inVlan = @()
  foreach($a in $adapters){
    $c = $ipcfg | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }
    $ips = @($c.IPv4Address | ForEach-Object { $_.IPv4Address.IPAddressToString })
    if($ips | Where-Object { Test-Cidr $_ $cfg.VlanSubnet $cfg.SubnetPrefixLength }){ $inVlan += $a }
  }
  if($inVlan.Count -gt 1){ throw "Más de una NIC en VLAN $($cfg.VlanSubnet)/$($cfg.SubnetPrefixLength): $($inVlan.Name -join ',')" }
  if($inVlan.Count -eq 1){ return $inVlan }

  # 2) Up con gateway deseado
  $gwMatch=@()
  foreach($a in $adapters){
    $c  = $ipcfg | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }
    $gw = ($c.IPv4DefaultGateway | Select-Object -First 1).NextHop
    if($a.Status -eq 'Up' -and $gw -eq $cfg.Gateway){ $gwMatch += $a }
  }
  if($gwMatch.Count -gt 1){ throw "Más de una NIC Up con gateway $($cfg.Gateway): $($gwMatch.Name -join ', ')" }
  if($gwMatch.Count -eq 1){ return $gwMatch }

  # 3) Up con algún gateway
  $upGw=@()
  foreach($a in $adapters){
    $c  = $ipcfg | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }
    if($a.Status -eq 'Up' -and $c.IPv4DefaultGateway){ $upGw += $a }
  }
  if($upGw.Count -gt 1){ throw "Más de una NIC Up con gateway presente: $($upGw.Name -join ', ')" }
  if($upGw.Count -eq 1){ return $upGw }

  # 4) Primera Up
  $up = $adapters | Where-Object { $_.Status -eq 'Up' }
  if($up.Count -gt 1){ throw "Más de una NIC Up candidata: $($up.Name -join ', ')" }
  if($up.Count -eq 1){ return $up }

  throw "No hay NIC Ethernet candidata (todas Down/ausentes)."
}

function Test-IpInUse([string]$ip){
  $alive = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
  if($alive){ return $true }
  try{
    $null = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
    $arp = (arp -a $ip) 2>$null
    if($arp -match '([0-9a-f]{2}-){5}[0-9a-f]{2}'){ return $true }
  }catch{}
  try{
    $nb = (nbtstat -A $ip) 2>$null
    if($LASTEXITCODE -eq 0 -and $nb){ return $true }
  }catch{}
  return $false
}

function Ensure-DnsSuffix([int]$ifIndex){
  try{
    Set-DnsClient -InterfaceIndex $ifIndex -ConnectionSpecificSuffix $cfg.DnsSuffix -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue
    $global = Get-DnsClientGlobalSetting
    if(-not ($global.SuffixSearchList -contains $cfg.DnsSuffix)){
      $new = @($global.SuffixSearchList + $cfg.DnsSuffix | Where-Object { $_ })
      Set-DnsClientGlobalSetting -SuffixSearchList $new -ErrorAction SilentlyContinue
    }
  }catch{ Write-Warning "No se pudo aplicar sufijo DNS: $($_.Exception.Message)" }
}

function Prechecks-Domain([string]$fqdn){
  Write-Host "[i] Prechecks dominio: $fqdn" -ForegroundColor Cyan
  try{ $null = Resolve-DnsName -Name $fqdn -ErrorAction Stop } catch{ throw "DNS no resuelve $fqdn" }
  try{ $srv = Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs.{0}" -f $fqdn) -Type SRV -ErrorAction Stop } catch { throw "No se encontraron SRV de DC para $fqdn" }
  $dc = ($srv | Sort-Object -Property Priority | Select-Object -First 1).NameTarget.TrimEnd('.')
  if(-not $dc){ throw "No se pudo determinar un DC." }
  $ok = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
  if(-not $ok){ Write-Warning "No responde ping el DC $dc (ICMP puede estar bloqueado)" }
  return $true
}

function Write-ResultRow([hashtable]$r){
  $file = $cfg.ResultsPath
  Ensure-Dir (Split-Path -Parent $file)
  $exists = Test-Path -LiteralPath $file
  $obj = [PSCustomObject]$r
  if(-not $exists){ $obj | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 }
  else { $obj | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -Append }
}

# ====== Inicio ======
if(-not (Test-Admin)){ Write-Error "Ejecuta en consola elevada (Administrador)."; exit 1 }

Ensure-Dir $LogsDir
Get-ChildItem -LiteralPath $LogsDir -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$cfg.LogsRetentionDays) } | Remove-Item -Force -ErrorAction SilentlyContinue

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$transcript = Join-Path $LogsDir ("Provision_{0}.log" -f $ts)
Start-Transcript -Path $transcript -ErrorAction SilentlyContinue | Out-Null
Write-Host "[policy] Join unificado: ACTIVO (usa Add-Computer -NewName si no esta en dominio y el nombre debe cambiar)" -ForegroundColor DarkYellow

try{
  # === PRECHECK: edición apta para dominio (permite Pro; bloquea Home/Core/Starter) ===
  try{
    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $edId = $null
    try { $edId = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID } catch {}
    $noJoin = @('Core','CoreN','CoreSingleLanguage','Starter','Home','HomeN','HomeSingleLanguage')
    if ($edId -and $noJoin -contains $edId) {
      Write-Error "Edición de Windows no apta para dominio. Detectado: $caption (EditionID=$edId)"
      exit 20
    } else {
      Write-Host "[OK] Edición compatible para dominio: $caption (EditionID=$edId)"
    }
  }catch{ Write-Warning "No se pudo validar edición de Windows: $($_.Exception.Message)" }

  # Cargar plan
  $rows = Import-Plan $cfg.PlanPath

  if($ValidatePlan){
    $errs = Validate-PlanRows $rows
    if($errs.Count -gt 0){
      Write-Host "[X] Errores de plan:" -ForegroundColor Red
      $errs | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
      exit 2
    } else { Write-Host "[OK] Plan válido." -ForegroundColor Green; exit 0 }
  }

  $errs = Validate-PlanRows $rows
  if($errs.Count -gt 0){
    Write-Host "[X] Errores de plan:" -ForegroundColor Red
    $errs | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
    exit 2
  }

  # NIC Ethernet
  $nic = Get-LocalEthernetMacAndAdapter
  $nicMac = Normalize-Mac $nic.MacAddress
  if(-not $nicMac){ throw "No se pudo obtener MAC Ethernet." }
  Write-Host "[i] NIC seleccionada: $($nic.Name) (MAC raw $($nic.MacAddress) -> $nicMac, ifIndex $($nic.ifIndex))" -ForegroundColor Cyan

  # Política Wi-Fi
  $wifiAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Wireless|Wi-?Fi|802\.11' -and $_.Status -eq 'Up' }
  $wifiDisabled = @()
  if($DisableWifi -or ($cfg.AutoDisableWifi -and -not $NoWifiAuto)){
    foreach($w in $wifiAdapters){
      try{ if(-not $DryRun){ Disable-NetAdapter -Name $w.Name -Confirm:$false -ErrorAction Stop }; $wifiDisabled += $w.Name; Write-Host "[i] Wi-Fi deshabilitado: $($w.Name)" }
      catch{ Write-Warning "No se pudo deshabilitar Wi-Fi $($w.Name): $($_.Exception.Message)" }
    }
  }

  # Fila activa por MAC
  $row = $rows | Where-Object { $_.Enabled -ne '0' } | Where-Object { (Normalize-Mac $_.MAC) -eq $nicMac } | Select-Object -First 1
  if(-not $row){ throw "No hay fila activa para MAC $nicMac en el plan." }

  $desiredHost = ("" + $row.DesiredHostname).Trim().ToUpper()
  $desiredIP   = ("" + $row.DesiredIP).Trim()
  $notes       = $row.Notes

  # Estado actual
  $cs = Get-CimInstance Win32_ComputerSystem
  $oldHost = $cs.Name.ToUpper()
  $partOfDomain = $cs.PartOfDomain
  $currentDomain= ("" + $cs.Domain).ToLower()

  if($desiredHost.Length -gt 15){ Write-Warning "Hostname deseado >15 chars: '$desiredHost' (se continúa por decisión)." }

  # Colisión de IP
  if(-not $DryRun){
    $used = Test-IpInUse $desiredIP
    if($used -and -not $Force){ throw "La IP $desiredIP parece en uso (Ping/ARP/NBNS). Usa -Force para ignorar." }
    elseif($used -and $Force){ Write-Warning "IP $desiredIP parece en uso; se aplica por -Force." }
  } else { Write-Host "[DryRun] Chequeo IP en uso: $desiredIP" }

  # Backup NIC
  $backup = @{
    Time=(Get-Date)
    Nic=$nic | Select-Object Name,InterfaceGuid,ifIndex,MacAddress,Status,LinkSpeed
    IpConf=(Get-NetIPConfiguration -InterfaceIndex $nic.ifIndex) | Select-Object -Property *
  }
  $backupJson = Join-Path $LogsDir ("NetBackup_{0}_{1}.json" -f $oldHost,$ts)
  $backup | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $backupJson -Encoding UTF8

  # Aplicar red si difiere
  $applyIP = $false
  try{
    $cfgNow = Get-NetIPConfiguration -InterfaceIndex $nic.ifIndex
    $nowIP  = ($cfgNow.IPv4Address | Select-Object -First 1).IPv4Address.IPAddressToString
    $nowGW  = ($cfgNow.IPv4DefaultGateway | Select-Object -First 1).NextHop
    $nowDNS = @($cfgNow.DnsServer.ServerAddresses)

    $dnsEqual = -not (Compare-Object -ReferenceObject $cfg.DnsServers -DifferenceObject $nowDNS)
    $needsIP = ($nowIP -ne $desiredIP) -or ($nowGW -ne $cfg.Gateway) -or (-not $dnsEqual)

    if($needsIP){
      $applyIP = $true
      Write-Host "[*] Configurando IP $desiredIP/$($cfg.SubnetPrefixLength) GW $($cfg.Gateway) DNS $($cfg.DnsServers -join ', ')" -ForegroundColor Yellow
      if(-not $DryRun){
        Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $desiredIP -PrefixLength $cfg.SubnetPrefixLength -DefaultGateway $cfg.Gateway -ErrorAction Stop | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $cfg.DnsServers -ErrorAction Stop
        Ensure-DnsSuffix -ifIndex $nic.ifIndex
      } else { Write-Host "[DryRun] (no se aplican cambios de red)" }
    } else {
      Write-Host "[i] Red ya coincide."
      if(-not $DryRun){ Ensure-DnsSuffix -ifIndex $nic.ifIndex } else { Write-Host "[DryRun] (no se toca sufijo DNS)" }
    }
  }catch{
    Write-Error "Error al configurar red: $($_.Exception.Message)"
    exit 3
  }

  # =======================
  #   RENAME + JOIN LÓGICA
  # =======================
  $needsRename = ($oldHost -ne $desiredHost)
  $applyRename = $false
  $applyJoin   = $false
  $unifiedUsed = $false
  $targetDomain = $cfg.Domain

  if($currentDomain -eq $targetDomain){
    # Ya está en el dominio objetivo
    if($needsRename){
      $applyRename = $true
      if(-not $DryRun){
        Write-Host "[*] Renombrando dentro de dominio: $oldHost -> $desiredHost" -ForegroundColor Yellow
        $user = "{0}\\{1}" -f $cfg.NetbiosDomain, $cfg.JoinUser
        $cred = Get-Credential -UserName $user -Message "Contraseña para $user (renombrar en dominio)"
        try{
          Rename-Computer -NewName $desiredHost -DomainCredential $cred -Force -ErrorAction Stop
        }catch{
          Write-Error "Error al renombrar en dominio: $($_.Exception.Message)"
          exit 1
        }
      } else {
        Write-Host "[DryRun] (no se renombra)"
      }
    } else {
      Write-Host "[i] Ya unido y nombre correcto."
    }
  }
  elseif($partOfDomain -and $currentDomain -and $currentDomain -ne $targetDomain){
    Write-Error "El equipo ya está unido a otro dominio: $currentDomain. Abortando."
    exit 4
  }
  else {
    # No está unido: JOIN (unificado si requiere rename)
    $applyJoin = $true
    if(-not $DryRun){
      Prechecks-Domain $targetDomain | Out-Null
      if($ODJBlobPath){
        if(-not (Test-Path -LiteralPath $ODJBlobPath)){ Write-Error "ODJ blob no encontrado: $ODJBlobPath"; exit 4 }
        $p = Start-Process -FilePath "djoin.exe" -ArgumentList "/requestODJ","/loadfile","$ODJBlobPath","/windowspath","$env:SystemRoot","/localos" -Wait -PassThru -NoNewWindow
        if($p.ExitCode -ne 0){ Write-Error "djoin.exe fallo (code $($p.ExitCode))."; exit 4 }
        Write-Host "[OK] ODJ aplicado."
        if($needsRename){
          $applyRename = $true
          Write-Host "[*] Renombrando (post-ODJ): $oldHost -> $desiredHost" -ForegroundColor Yellow
          try{ Rename-Computer -NewName $desiredHost -Force -ErrorAction Stop }
          catch{ Write-Error "Error al renombrar (post-ODJ): $($_.Exception.Message)"; exit 1 }
        }
      } else {
        $user = "{0}\\{1}" -f $cfg.NetbiosDomain, $cfg.JoinUser
        $cred = Get-Credential -UserName $user -Message "Contraseña para $user (unir al dominio)"
        $try = 0; $ok = $false
        while($try -lt 2 -and -not $ok){
          $try++
          try{
            if($needsRename){
              Write-Host "[*] Join unificado: dominio=$targetDomain, NewName=$desiredHost" -ForegroundColor Yellow
              Add-Computer -DomainName $targetDomain -NewName $desiredHost -Credential $cred -ErrorAction Stop
              $applyRename = $true
              $unifiedUsed = $true
            } else {
              Write-Host "[*] Join simple: dominio=$targetDomain" -ForegroundColor Yellow
              Add-Computer -DomainName $targetDomain -Credential $cred -ErrorAction Stop
            }
            $ok = $true
          }catch{
            if($try -lt 2){
              Write-Warning "Fallo de join (intento $try). Reintentando en 30s... $($_.Exception.Message)"
              Start-Sleep -Seconds 30
            } else {
              Write-Error "No se pudo unir al dominio: $($_.Exception.Message)"
              exit 4
            }
          }
        }
      }
    } else {
      if($needsRename){ Write-Host "[DryRun] (haría join unificado con NewName=$desiredHost)" } else { Write-Host "[DryRun] (haría join simple)" }
    }
  }

  # DNS register
  if(-not $DryRun){
    try{ ipconfig /flushdns | Out-Null; ipconfig /registerdns | Out-Null }catch{}
  }

  # Rehabilitar Wi-Fi
  foreach($w in $wifiDisabled){ try{ if(-not $DryRun){ Enable-NetAdapter -Name $w -Confirm:$false -ErrorAction SilentlyContinue } }catch{} }

  # RESULTADOS
  $oldIPVal = $backup.IpConf.IPv4Address | Select-Object -First 1
  $oldIPStr = if($oldIPVal){ $oldIPVal.IPv4Address.IPAddressToString } else { $null }

  $joined = $applyJoin -and -not $DryRun
  $rebootNeeded = (($applyRename -or $applyJoin) -and -not $DryRun)

  $result = [ordered]@{
    Timestamp        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Machine          = $env:COMPUTERNAME
    MAC              = $nicMac
    DesiredHostname  = $desiredHost
    DesiredIP        = $desiredIP
    OldHostname      = $oldHost
    OldIP            = $oldIPStr
    NICName          = $nic.Name
    AppliedHostname  = [bool]$applyRename
    AppliedIP        = [bool]$applyIP
    JoinedDomain     = $joined
    RebootTriggered  = $false
    ExitCode         = 0
    Message          = if($unifiedUsed){"OK (UnifiedJoin)"}else{"OK"}
    Operator         = ("{0}\\{1}" -f $env:USERDOMAIN,$env:USERNAME)
    LogPath          = $transcript
  }

  ($result | ConvertTo-Json) | Out-File -LiteralPath (Join-Path $LogsDir ("Result_{0}_{1}.json" -f $desiredHost,$ts)) -Encoding UTF8

  Write-Host "----------------------------------------" -ForegroundColor DarkCyan
  Write-Host ("Hostname: {0}  ->  {1}" -f $oldHost,$desiredHost)
  Write-Host ("IP:       {0}  ->  {1}" -f $oldIPStr,$desiredIP)
  Write-Host ("Dominio:  {0}  ->  {1}" -f $currentDomain,$cfg.Domain)
  Write-Host ("NIC:      {0}" -f $nic.Name)
  Write-Host ("Acciones: Hostname={0}  IP={1}  Join={2}  UnifiedJoin={3}" -f $applyRename,$applyIP,$applyJoin,$unifiedUsed)
  Write-Host "----------------------------------------" -ForegroundColor DarkCyan

  if($rebootNeeded){
    if($NoReboot){
      Write-Host "[i] Reinicio requerido, pero -NoReboot solicitado. (ExitCode=3010)"
      $result.ExitCode = 3010; $result.Message = ($result.Message + " - RebootPending")
      Write-ResultRow $result; Stop-Transcript | Out-Null; exit 0
    } elseif($RebootNow){
      Write-Host "[*] Reiniciando de inmediato (5s)..." -ForegroundColor Yellow
      $result.RebootTriggered = $true; Write-ResultRow $result; Stop-Transcript | Out-Null
      shutdown /r /t 5 /f /d p:4:1 /c "Provision: cambios aplicados"
      exit 0
    } else {
      Write-Host ("[*] Reinicio en {0}s (firme)..." -f $RebootDelay) -ForegroundColor Yellow
      $result.RebootTriggered = $true; Write-ResultRow $result; Stop-Transcript | Out-Null
      shutdown /r /t $RebootDelay /f /d p:4:1 /c "Provision: hostname/domain actualizado"
      exit 0
    }
  }

  Write-ResultRow $result
  Stop-Transcript | Out-Null
  exit $result.ExitCode
}
catch{
  $msg = $_.Exception.Message
  Write-Error $msg
  try{
    $fail = [ordered]@{
      Timestamp        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
      Machine          = $env:COMPUTERNAME
      MAC              = $nicMac
      DesiredHostname  = $desiredHost
      DesiredIP        = $desiredIP
      OldHostname      = $oldHost
      OldIP            = $oldIPStr
      NICName          = $nic.Name
      AppliedHostname  = $false
      AppliedIP        = $false
      JoinedDomain     = $false
      RebootTriggered  = $false
      ExitCode         = 1
      Message          = $msg
      Operator         = ("{0}\\{1}" -f $env:USERDOMAIN,$env:USERNAME)
      LogPath          = $transcript
    }
    Write-ResultRow $fail
  }catch{}
  Stop-Transcript | Out-Null
  exit 1
}
