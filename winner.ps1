# :: g3n3r@t3d :: d0 n0t 3d1t ::
[CmdletBinding()]param([switch]${_x9f2a},[switch]${_k4m7q},[switch]${_v8p1z})

Set-Variable -Name '_d3c' -Value ([System.Text.Encoding]::UTF8) -Option ReadOnly -ErrorAction SilentlyContinue
function _z1([string]$s){[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))}

# --- junk block alpha ---
${_jnk01}=0x2F3A;${_jnk02}=[math]::PI;${_jnk03}=$null;if(${_jnk01} -gt 99999){${_jnk03}='unreachable'}
${_jnk04}=@(1,2,3)|Where-Object{$_ -gt 99};${_jnk05}=[guid]::NewGuid().ToString().Substring(0,8)

function _a7r2k {
  param([string]${_t1})
  ${_m1}=(${_t1}|Select-String -AllMatches -Pattern $(_z1 'S0IoXGR7NCw2fSk=')).Matches.Value  # KB(\d{4,6})
  if(${_m1}){return ${_m1}}
  ${_m2}=(${_t1}|Select-String -NotMatch -Pattern $(_z1 'S0IoXGR7NCw2fSk=')).Matches.Value
  if(${_m2}){return ${_m2}}
}

function _b3x9w {
  param(${_tg},${_sn})
  if($null -ne ${_tg}){
    try{${_ac}=Get-Acl ${_tg} -ErrorAction SilentlyContinue}catch{${_ac}=$null}
    if(${_ac}){
      ${_id}=@()
      ${_id}+="$env:COMPUTERNAME\$env:USERNAME"
      if(${_ac}.Owner -like ${_id}){&([scriptblock]::Create($(_z1 'V3JpdGUtSG9zdCAiJHtfaWR9IGhhcyBvd25lcnNoaXAgb2YgJHtfdGd9IiAtRm9yZWdyb3VuZENvbG9yIFJlZA==')))}
      &([scriptblock]::Create($(_z1 'd2hvYW1pLmV4ZSAvZ3JvdXBzIC9mbyBjc3Y=')))|Select-Object -Skip 2|ConvertFrom-Csv -Header $(_z1 'Z3JvdXAgbmFtZQ==')|Select-Object -ExpandProperty $(_z1 'Z3JvdXAgbmFtZQ==')|ForEach-Object{${_id}+=$_}
      ${_if}=$false
      foreach(${_i} in ${_id}){
        ${_pm}=${_ac}.Access|Where-Object{$_.IdentityReference -like ${_i}}
        ${_up}=""
        switch -WildCard(${_pm}.FileSystemRights){
          $(_z1 'RnVsbENvbnRyb2w='){${_up}=$(_z1 'RnVsbENvbnRyb2w=');${_if}=$true}
          $(_z1 'V3JpdGUq'){${_up}=$(_z1 'V3JpdGU=');${_if}=$true}
          $(_z1 'TW9kaWZ5'){${_up}=$(_z1 'TW9kaWZ5');${_if}=$true}
        }
        Switch(${_pm}.RegistryRights){
          $(_z1 'RnVsbENvbnRyb2w='){${_up}=$(_z1 'RnVsbENvbnRyb2w=');${_if}=$true}
        }
        if(${_up}){
          if(${_sn}){Write-Host "$(_z1 'Zm91bmQgd2l0aCBwZXJtaXNzaW9ucyBpc3N1ZTo=') ${_sn}" -ForegroundColor Red}
          Write-Host -ForegroundColor Red "Identity $(${_pm}.IdentityReference) has '${_up}' perms for ${_tg}"
        }
      }
      if(${_if} -eq $false){
        if(${_tg}.Length -gt 3){
          ${_tg}=Split-Path ${_tg}
          _b3x9w ${_tg} -_sn ${_sn}
        }
      }
    }else{
      ${_tg}=Split-Path ${_tg}
      _b3x9w ${_tg} ${_sn}
    }
  }
}

# --- junk block beta ---
${_jnk06}=@{a=1;b=2;c=3};${_jnk07}=${_jnk06}.Keys|ForEach-Object{"$_$(Get-Random)"};${_jnk08}=[datetime]::Now.Ticks

function _c5v1q {
  Write-Host $(_z1 'RmV0Y2hpbmcgdGhlIGxpc3Qgb2Ygc2VydmljZXMsIHRoaXMgbWF5IHRha2UgYSB3aGlsZS4uLg==')
  ${_sv}=Get-WmiObject -Class Win32_Service|Where-Object{$_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq $(_z1 'QXV0bw==') -or $_.StartMode -eq $(_z1 'TWFudWFs')) -and ($_.State -eq $(_z1 'UnVubmluZw==') -or $_.State -eq $(_z1 'U3RvcHBlZA=='))}
  if($(${_sv}|Measure-Object).Count -lt 1){
    Write-Host $(_z1 'Tm8gdW5xdW90ZWQgc2VydmljZSBwYXRocyB3ZXJlIGZvdW5k')
  }else{
    ${_sv}|ForEach-Object{
      Write-Host $(_z1 'VW5xdW90ZWQgU2VydmljZSBQYXRoIGZvdW5kIQ==') -ForegroundColor Red
      Write-Host "Name: $($_.Name)"
      Write-Host "PathName: $($_.PathName)"
      Write-Host "StartName: $($_.StartName)"
      Write-Host "StartMode: $($_.StartMode)"
      Write-Host "Running: $($_.State)"
    }
  }
}

function _d8t3e {Write-Host "Time Running: $(${_sw}.Elapsed.Minutes):$(${_sw}.Elapsed.Seconds)"}

function _e2q7y {
  Add-Type -AssemblyName PresentationCore
  ${_tx}=[Windows.Clipboard]::GetText()
  if(${_tx}){
    Write-Host ""
    if(${_x9f2a}){_d8t3e}
    Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2xpcEJvYXJkIHRleHQgZm91bmQ6')
    Write-Host ${_tx}
  }
}

function _f4j8n {
  try{return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()}
  catch{return $null}
}

function _g6s2p {
  param(${_si})
  if($null -eq ${_si}){return $null}
  try{
    if(${_si} -is [System.Security.Principal.SecurityIdentifier]){${_so}=${_si}}
    else{${_so}=New-Object System.Security.Principal.SecurityIdentifier(${_si})}
    return ${_so}.Translate([System.Security.Principal.NTAccount]).Value
  }catch{
    try{return ${_so}.Value}catch{return [string]${_si}}
  }
}

# --- junk block gamma ---
${_jnk09}=@();for($__i=0;$__i -lt 0;$__i++){${_jnk09}+=[char](Get-Random -Min 65 -Max 90)};${_jnk10}=$env:TEMP

function _h1w5r {
  param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
  if(-not ${_dc}){return @()}
  ${_dn}=${_dc}.GetDirectoryEntry().distinguishedName
  ${_fn}=${_dc}.Forest.RootDomain.GetDirectoryEntry().distinguishedName
  ${_pt}=@(
    "LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,${_dn}",
    "LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,${_fn}",
    "LDAP://CN=MicrosoftDNS,${_dn}"
  )
  ${_wp}=@($(_z1 'YXV0aGVudGljYXRlZCB1c2Vycw=='),$(_z1 'ZXZlcnlvbmU='),$(_z1 'ZG9tYWluIHVzZXJz'))
  ${_dr}=@($(_z1 'R2VuZXJpY0FsbA=='),$(_z1 'R2VuZXJpY1dyaXRl'),$(_z1 'Q3JlYXRlQ2hpbGQ='),$(_z1 'V3JpdGVQcm9wZXJ0eQ=='),$(_z1 'V3JpdGVEYWNs'),$(_z1 'V3JpdGVPd25lcg=='))
  ${_fd}=@()
  foreach(${_p} in ${_pt}){
    try{
      ${_cn}=New-Object System.DirectoryServices.DirectoryEntry(${_p})
      $null=${_cn}.NativeGuid
    }catch{continue}
    ${_sr}=New-Object System.DirectoryServices.DirectorySearcher(${_cn})
    ${_sr}.Filter=$(_z1 'KG9iamVjdENsYXNzPWRuc1pvbmUp')
    ${_sr}.PageSize=500
    ${_rs}=${_sr}.FindAll()
    foreach(${_r} in ${_rs}){
      try{
        ${_ze}=${_r}.GetDirectoryEntry()
        ${_ze}.Options.SecurityMasks=[System.DirectoryServices.SecurityMasks]::Dacl
        ${_sd}=${_ze}.ObjectSecurity
        foreach(${_ace} in ${_sd}.Access){
          if(${_ace}.AccessControlType -ne 'Allow'){continue}
          ${_pr}=_g6s2p ${_ace}.IdentityReference
          if(-not ${_pr}){continue}
          ${_pl}=${_pr}.ToLower()
          if(-not(${_wp}|Where-Object{${_pl} -like "*${_}*"})){continue}
          ${_rt}=${_ace}.ActiveDirectoryRights.ToString()
          if(-not(${_dr}|Where-Object{${_rt} -like "*${_}*"})){continue}
          ${_fd}+=[pscustomobject]@{
            Zone=${_ze}.Properties[$(_z1 'bmFtZQ==')].Value
            Partition=${_p}.Split(',')[1]
            Principal=${_pr}
            Rights=${_rt}
          }
        }
      }catch{continue}
    }
  }
  return(${_fd}|Sort-Object Zone,Principal -Unique)
}

function _i3m6u {
  param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
  if(-not ${_dc}){return @()}
  ${_dn}=${_dc}.GetDirectoryEntry().distinguishedName
  try{
    ${_sr}=New-Object System.DirectoryServices.DirectorySearcher
    ${_sr}.SearchRoot=New-Object System.DirectoryServices.DirectoryEntry("LDAP://${_dn}")
    ${_sr}.Filter=$(_z1 'KCYob2JqZWN0Q2xhc3M9bXNEUy1Hcm91cE1hbmFnZWRTZXJ2aWNlQWNjb3VudCkp')
    ${_sr}.PageSize=500
    [void]${_sr}.PropertiesToLoad.Add($(_z1 'c0FNQWNjb3VudE5hbWU='))
    [void]${_sr}.PropertiesToLoad.Add($(_z1 'bXNEUy1Hcm91cE1TQU1lbWJlcnNoaXA='))
    ${_rs}=${_sr}.FindAll()
  }catch{return @()}
  ${_rp}=@()
  foreach(${_r} in ${_rs}){
    ${_nm}=${_r}.Properties[$(_z1 'c2FtYWNjb3VudG5hbWU=')]
    ${_bl}=${_r}.Properties[$(_z1 'bXNkcy1ncm91cG1zYW1lbWJlcnNoaXA=')]
    if(-not ${_bl}){continue}
    ${_pc}=@()
    foreach(${_b} in ${_bl}){
      try{
        ${_rw}=New-Object System.Security.AccessControl.RawSecurityDescriptor(,${_b})
        foreach(${_ace} in ${_rw}.DiscretionaryAcl){
          ${_sd}=_g6s2p ${_ace}.SecurityIdentifier
          if(${_sd}){${_pc}+=${_sd}}
        }
      }catch{continue}
    }
    if(${_pc}.Count -eq 0){continue}
    ${_pc}=${_pc}|Sort-Object -Unique
    ${_wk}=${_pc}|Where-Object{$_ -match $(_z1 'RG9tYWluIFVzZXJzfEF1dGhlbnRpY2F0ZWQgVXNlcnN8RXZlcnlvbmU=')}
    ${_rp}+=[pscustomobject]@{
      Account=(${_nm}|Select-Object -First 1)
      Allowed=(${_pc} -join ", ")
      WeakPrincipals=if(${_wk}){${_wk} -join ", "}else{""}
    }
  }
  return ${_rp}
}

function _j5p2v {
  param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
  if(-not ${_dc}){return @()}
  ${_dn}=${_dc}.GetDirectoryEntry().distinguishedName
  ${_kw}=@($(_z1 'RG9tYWluIEFkbWlu'),$(_z1 'RW50ZXJwcmlzZSBBZG1pbg=='),$(_z1 'QWRtaW5pc3RyYXRvcnM='),$(_z1 'RXhjaGFuZ2U='),$(_z1 'SVRf'),$(_z1 'U2NoZW1hIEFkbWlu'),$(_z1 'QWNjb3VudCBPcGVyYXRvcg=='),$(_z1 'U2VydmVyIE9wZXJhdG9y'),$(_z1 'QmFja3VwIE9wZXJhdG9y'),$(_z1 'RG5zQWRtaW4='))
  try{
    ${_sr}=New-Object System.DirectoryServices.DirectorySearcher
    ${_sr}.SearchRoot=New-Object System.DirectoryServices.DirectoryEntry("LDAP://${_dn}")
    ${_sr}.Filter=$(_z1 'KCYob2JqZWN0Q2xhc3M9dXNlcikoc2VydmljZVByaW5jaXBhbE5hbWU9Kikp')
    ${_sr}.PageSize=500
    [void]${_sr}.PropertiesToLoad.Add($(_z1 'c0FNQWNjb3VudE5hbWU='))
    [void]${_sr}.PropertiesToLoad.Add($(_z1 'bWVtYmVyT2Y='))
    ${_rs}=${_sr}.FindAll()
  }catch{return @()}
  ${_fd}=@()
  foreach(${_r} in ${_rs}){
    ${_gr}=${_r}.Properties[$(_z1 'bWVtYmVyb2Y=')]
    if(-not ${_gr}){continue}
    ${_mg}=@()
    foreach(${_g} in ${_gr}){
      ${_cn}=(${_g} -split ',')[0] -replace '^CN=',''
      if(${_kw}|Where-Object{${_cn} -like "*${_}*"}){${_mg}+=${_cn}}
    }
    if(${_mg}.Count -gt 0){
      ${_fd}+=[pscustomobject]@{
        User=(${_r}.Properties[$(_z1 'c2FtYWNjb3VudG5hbWU=')] | Select-Object -First 1)
        Groups=(${_mg}|Sort-Object -Unique) -join ', '
      }
    }
  }
  return(${_fd}|Sort-Object User|Select-Object -First 12)
}

function _k7n4x {
  try{${_mv}=Get-ItemProperty -Path $(_z1 'SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcTHNhXE1TVjFfMA==') -ErrorAction Stop}
  catch{return $null}
  ${_ls}=Get-ItemProperty -Path $(_z1 'SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcTHNh') -ErrorAction SilentlyContinue
  return [pscustomobject]@{
    RestrictReceiving=${_mv}.RestrictReceivingNTLMTraffic
    RestrictSending=${_mv}.RestrictSendingNTLMTraffic
    LmCompatibility=if(${_ls}){${_ls}.LmCompatibilityLevel}else{$null}
  }
}

function _l9q1z {
  param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
  if(-not ${_dc}){return $null}
  try{${_pdc}=${_dc}.PdcRoleOwner.Name}catch{return $null}
  try{
    ${_sc}=w32tm /stripchart /computer:${_pdc} /dataonly /samples:3 2>$null
    ${_sm}=${_sc}|Where-Object{$_ -match ','}|Select-Object -Last 1
    if(-not ${_sm}){return $null}
    ${_pt}=${_sm}.Split(',')
    if(${_pt}.Count -lt 2){return $null}
    ${_os}=${_pt}[1].Trim().TrimEnd('s')
    [double]${_ov}=0
    if(-not [double]::TryParse(${_os},[ref]${_ov})){return $null}
    return [pscustomobject]@{Source=${_pdc};OffsetSeconds=${_ov};RawSample=${_sm}}
  }catch{return $null}
}

function _m2r5b {
  ${_inf}=[ordered]@{MappingValue=$null;UpnMapping=$false;ServiceState=$null}
  try{
    ${_sch}=Get-ItemProperty -Path $(_z1 'SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcU2VjdXJpdHlQcm92aWRlcnNcU0NIQU5ORUw=') -Name $(_z1 'Q2VydGlmaWNhdGVNYXBwaW5nTWV0aG9kcw==') -ErrorAction Stop
    ${_inf}.MappingValue=${_sch}.CertificateMappingMethods
    if((${_sch}.CertificateMappingMethods -band 0x4) -eq 0x4){${_inf}.UpnMapping=$true}
  }catch{}
  ${_svc}=Get-Service -Name $(_z1 'Y2VydHN2cg==') -ErrorAction SilentlyContinue
  if(${_svc}){${_inf}.ServiceState=${_svc}.Status}
  return [pscustomobject]${_inf}
}

# --- junk block delta ---
${_jnk11}=[System.Collections.ArrayList]::new();${_jnk12}='xR7kQ2pL9';${_jnk13}=$null;try{${_jnk13}=[math]::Log(-1)}catch{};${_jnk14}=$false -and $true

function _n4t8d {
  [cmdletbinding()]
  Param(
    [parameter(Mandatory,ValueFromPipeline)]
    [ValidateScript({Try{If(Test-Path -Path $_){$True}Else{Throw "$($_) is not a valid path!"}}Catch{Throw $_}})]
    [string]${_src},
    [parameter(Mandatory)]
    [string]${_stx}
  )
  ${_xl}=New-Object -ComObject Excel.Application
  Try{${_src}=Convert-Path ${_src}}Catch{Write-Warning "Unable locate full path of $(${_src})";BREAK}
  ${_wb}=${_xl}.Workbooks.Open(${_src})
  ForEach(${_ws} in @(${_wb}.Sheets)){
    ${_fnd}=${_ws}.Cells.Find(${_stx})
    If(${_fnd}){
      try{
        Write-Host "Pattern: '${_stx}' found in ${_src}" -ForegroundColor Blue
        ${_ba}=${_fnd}.Address(0,0,1,1)
        New-Object -TypeName PSObject -Property ([Ordered]@{WorkSheet=${_ws}.Name;Column=${_fnd}.Column;Row=${_fnd}.Row;TextMatch=${_fnd}.Text;Address=${_ba}})
        Do{
          ${_fnd}=${_ws}.Cells.FindNext(${_fnd})
          ${_ad}=${_fnd}.Address(0,0,1,1)
          If(${_ad} -eq ${_ba}){BREAK}
          New-Object -TypeName PSObject -Property ([Ordered]@{WorkSheet=${_ws}.Name;Column=${_fnd}.Column;Row=${_fnd}.Row;TextMatch=${_fnd}.Text;Address=${_ad}})
        }Until($False)
      }catch{}
    }
  }
  try{${_wb}.close($False);[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]${_xl});[gc]::Collect();[gc]::WaitForPendingFinalizers()}catch{}
  Remove-Variable _xl -ErrorAction SilentlyContinue
}

function _o6u2f {
  [cmdletbinding()]
  param([Parameter(DontShow)]${_ky}=@('','\Wow6432Node'))
  foreach(${_k} in ${_ky}){
    try{${_ap}=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE${_k}\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()}catch{Continue}
    foreach(${_a} in ${_ap}){
      ${_pg}=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE${_k}\Microsoft\Windows\CurrentVersion\Uninstall\${_a}")
      ${_nm}=${_pg}.GetValue($(_z1 'RGlzcGxheU5hbWU='))
      if(${_nm}){
        New-Object -TypeName PSObject -Property ([Ordered]@{
          Computername=$env:COMPUTERNAME
          Software=${_nm}
          Version=${_pg}.GetValue($(_z1 'RGlzcGxheVZlcnNpb24='))
          Publisher=${_pg}.GetValue($(_z1 'UHVibGlzaGVy'))
          InstallDate=${_pg}.GetValue($(_z1 'SW5zdGFsbERhdGU='))
          UninstallString=${_pg}.GetValue($(_z1 'VW5pbnN0YWxsU3RyaW5n'))
          Architecture=$(if(${_k} -eq '\wow6432node'){'x86'}else{'x64'})
          Path=${_pg}.Name
        })
      }
    }
  }
}

function _p8w3h([String[]]${_tx},[ConsoleColor[]]${_cl}){
  for(${_i}=0;${_i} -lt ${_tx}.Length;${_i}++){Write-Host ${_tx}[${_i}] -Foreground ${_cl}[${_i}] -NoNewline}
  Write-Host
}

# --- junk block epsilon ---
${_jnk15}=@(97,110,116,105)|ForEach-Object{[char]$_};${_jnk16}=${_jnk15} -join '';${_jnk17}=[System.Collections.Generic.HashSet[int]]::new()

# === BANNER (obfuscated calls) ===
_p8w3h ",/*,..*(((((((((((((((((((((((((((((((((," Green
_p8w3h ",*/((((((((((((((((((/,  .*//((//**, .*((((((*" Green
_p8w3h "((((((((((((((((","* *****,,,","\########## .(* ,((((((" Green,Blue,Green
_p8w3h "(((((((((((","/*******************","####### .(. ((((((" Green,Blue,Green
_p8w3h "(((((((","/******************","/@@@@@/","***","\#######\((((((" Green,Blue,White,Blue,Green
_p8w3h ",,..","**********************","/@@@@@@@@@/","***",",#####.\/(((((" Green,Blue,White,Blue,Green
_p8w3h ", ,","**********************","/@@@@@+@@@/","*********","##((/ /((((" Green,Blue,White,Blue,Green
_p8w3h "..(((##########","*********","/#@@@@@@@@@/","*************",",,..((((" Green,Blue,White,Blue,Green
_p8w3h ".(((################(/","******","/@@@@@/","****************",".. /((" Green,Blue,White,Blue,Green
_p8w3h ".((########################(/","************************","..*(" Green,Blue,Green
_p8w3h ".((#############################(/","********************",".,(" Green,Blue,Green
_p8w3h ".((##################################(/","***************","..(" Green,Blue,Green
_p8w3h ".((######################################(/","***********","..(" Green,Blue,Green
_p8w3h ".((######","(,.***.,(","###################","(..***","(/*********","..(" Green,Green,Green,Green,Blue,Green
_p8w3h ".((######*","(####((","###################","((######","/(********","..(" Green,Green,Green,Green,Blue,Green
_p8w3h ".((##################","(/**********(","################(**...(" Green,Green,Green
_p8w3h ".(((####################","/*******(","###################.((((" Green,Green,Green
_p8w3h ".(((((############################################/  /((" Green
_p8w3h "..(((((#########################################(..(((((." Green
_p8w3h "....(((((#####################################( .((((((." Green
_p8w3h "......(((((#################################( .(((((((." Green
_p8w3h "(((((((((. ,(############################(../(((((((((." Green
_p8w3h "  (((((((((/,  ,####################(/..((((((((((." Green
_p8w3h "        (((((((((/,.  ,*//////*,. ./(((((((((((." Green
_p8w3h "           (((((((((((((((((((((((((((/" Green
_p8w3h "          by PEASS-ng & RandolphConley" Green

# ======================== VARIABLES ========================

${_pw}=$true;${_un}=$true;${_wa}=$true
${_rx}=@{}

# --- junk block zeta ---
${_jnk18}=0;while(${_jnk18} -gt 1){${_jnk18}++};${_jnk19}='deadbeef';${_jnk20}=$null

if(${_pw}){
  ${_rx}.add($(_z1 'U2ltcGxlIFBhc3N3b3JkczE='),$(_z1 'cGFzcy4qWz06XS4r'))
  ${_rx}.add($(_z1 'U2ltcGxlIFBhc3N3b3JkczI='),$(_z1 'cHdkLipbPTpdLis='))
  ${_rx}.add($(_z1 'QXByMSBNRDU='),'$apr1$[a-zA-Z0-9_/\.]{8}$[a-zA-Z0-9_/\.]{22}')
  ${_rx}.add($(_z1 'QXBhY2hlIFNIQQ=='),'\{SHA\}[0-9a-zA-Z/_=]{10,}')
  ${_rx}.add($(_z1 'Qmxvd2Zpc2g='),'$2[abxyz]?$[0-9]{2}$[a-zA-Z0-9_/\.]*')
  ${_rx}.add($(_z1 'RHJ1cGFs'),'$S$[a-zA-Z0-9_/\.]{52}')
  ${_rx}.add($(_z1 'Sm9vbWxhdmJ1bGxldGlu'),"[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
  ${_rx}.add($(_z1 'TGludXggTUQ1'),'$1$[a-zA-Z0-9_/\.]{8}$[a-zA-Z0-9_/\.]{22}')
  ${_rx}.add($(_z1 'cGhwYmIz'),'$H$[a-zA-Z0-9_/\.]{31}')
  ${_rx}.add($(_z1 'c2hhNTEyY3J5cHQ='),'$6$[a-zA-Z0-9_/\.]{16}$[a-zA-Z0-9_/\.]{86}')
  ${_rx}.add($(_z1 'V29yZHByZXNz'),'$P$[a-zA-Z0-9_/\.]{31}')
  ${_rx}.add("md5","(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
  ${_rx}.add("sha1","(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
  ${_rx}.add("sha256","(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
  ${_rx}.add("sha512","(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")
  ${_rx}.add($(_z1 'QmFzZTY0'),"(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")
}

if(${_un}){
  ${_rx}.add($(_z1 'VXNlcm5hbWVzMQ=='),$(_z1 'dXNlcm5hbWVbPTpdLis='))
  ${_rx}.add($(_z1 'VXNlcm5hbWVzMg=='),$(_z1 'dXNlcls9Ol0uKw=='))
  ${_rx}.add($(_z1 'VXNlcm5hbWVzMw=='),$(_z1 'bG9naW5bPTpdLis='))
  ${_rx}.add($(_z1 'RW1haWxz'),"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
  ${_rx}.add($(_z1 'TmV0IHVzZXIgYWRk'),$(_z1 'bmV0IHVzZXIgLisgL2FkZA=='))
}

if(${_k4m7q}){
  ${_rx}.add($(_z1 'QXJ0aWZhY3RvcnkgQVBJIFRva2Vu'),"AKC[a-zA-Z0-9]{10,}")
  ${_rx}.add($(_z1 'QXJ0aWZhY3RvcnkgUGFzc3dvcmQ='),"AP[0-9ABCDEF][a-zA-Z0-9]{8,}")
  ${_rx}.add($(_z1 'RmFjZWJvb2sgQWNjZXNzIFRva2Vu'),"EAACEdEose0cBA[0-9A-Za-z]+")
  ${_rx}.add($(_z1 'R2l0aHVi'),"github(.{0,20})?['""][0-9a-zA-Z]{35,40}")
  ${_rx}.add($(_z1 'R2l0aHViIEFwcCBUb2tlbg=='),"(ghu|ghs)_[0-9a-zA-Z]{36}")
  ${_rx}.add($(_z1 'R2l0aHViIE9BdXRoIEFjY2VzcyBUb2tlbg=='),"gho_[0-9a-zA-Z]{36}")
  ${_rx}.add($(_z1 'R2l0aHViIFBlcnNvbmFsIEFjY2VzcyBUb2tlbg=='),"ghp_[0-9a-zA-Z]{36}")
  ${_rx}.add($(_z1 'R2l0aHViIFJlZnJlc2ggVG9rZW4='),"ghr_[0-9a-zA-Z]{76}")
  ${_rx}.add($(_z1 'R2l0SHViIEZpbmUtR3JhaW5lZCBQZXJzb25hbCBBY2Nlc3MgVG9rZW4='),"github_pat_[0-9a-zA-Z_]{82}")
  ${_rx}.add($(_z1 'R2l0bGFiIFBlcnNvbmFsIEFjY2VzcyBUb2tlbg=='),"glpat-[0-9a-zA-Z\-]{20}")
  ${_rx}.add($(_z1 'R29vZ2xlIEFQSSBLZXk='),"AIza[0-9A-Za-z_\-]{35}")
  ${_rx}.add($(_z1 'R29vZ2xlIE9hdXRoIEFjY2VzcyBUb2tlbg=='),"ya29\.[0-9A-Za-z_\-]+")
  ${_rx}.add($(_z1 'T3BlbkFJIEFQSSBUb2tlbg=='),"sk-[A-Za-z0-9]{48}")
  ${_rx}.add($(_z1 'U2xhY2sgVG9rZW4='),"xox[baprs]-([0-9a-zA-Z]{10,48})?")
  ${_rx}.add($(_z1 'U2xhY2sgV2ViaG9vaw=='),"https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}")
  ${_rx}.add($(_z1 'U3RyaXBlIEFjY2VzcyBUb2tlbiAmIEFQSSBLZXk='),"(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}")
  ${_rx}.add($(_z1 'VHdpbGlvIEFQSSBLZXk='),"SK[0-9a-fA-F]{32}")
  ${_rx}.add($(_z1 'UHJpdmF0ZSBLZXlz'),"\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
  ${_rx}.add($(_z1 'SlNPTiBXZWIgVG9rZW4='),"(ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2})")
  ${_rx}.add($(_z1 'QVDTIEN1aWVudCBJRA=='),"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
  ${_rx}.add($(_z1 'QVdTIFNlY3JldCBLZXk='),"aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
  ${_rx}.add($(_z1 'QmFzaWMgQXV0aCBDcmVkZW50aWFscw=='),"://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
  ${_rx}.add($(_z1 'R2VuZXJpYyBTZWNyZXQ='),"[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
  ${_rx}.add($(_z1 'QmFzaWMgQXV0aA=='),"//(.+):(.+)@")
  ${_rx}.add($(_z1 'UFBIIFBBY3N3b3Jkcw=='),"(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
  ${_rx}.add($(_z1 'R2VuZXJpYyBBUEkgS2V5'),"((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
  ${_rx}.add($(_z1 'VGVsZWdyYW0gQm90IEFQSSB Ub2tlbg=='),"[0-9]+:AA[0-9A-Za-z\\-_]{33}")
  ${_rx}.add($(_z1 'U2VuZGdyaWQgQVBJIEtleQ=='),"SG\.[a-zA-Z0-9_\.\-]{66}")
  ${_rx}.add($(_z1 'TWFpbGNoaW1wIEFQSSBLZXk='),"[0-9a-f]{32}-us[0-9]{1,2}")
  ${_rx}.add($(_z1 'TWFpbGd1biBBUEkgS2V5'),"key-[0-9a-zA-Z]{32}'")
  ${_rx}.add($(_z1 'SGVyb2t1IEFQSSBLZXk='),"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
}

if(${_wa}){
  ${_rx}.add($(_z1 'QXV0aG9yaXphdGlvbiBCYXNpYw=='),"basic [a-zA-Z0-9_:\.=\-]+")
  ${_rx}.add($(_z1 'QXV0aG9yaXphdGlvbiBCZWFyZXI='),"bearer [a-zA-Z0-9_\.=\-]+")
  ${_rx}.add($(_z1 'QWxpYmFiYSBBY2Nlc3MgS2V5IElE'),"(LTAI)[a-z0-9]{20}")
  ${_rx}.add($(_z1 'QVdTIENsaWVudCBJRA=='),"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
  ${_rx}.add($(_z1 'QVdTIE1XUyBLZXk='),"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
  ${_rx}.add($(_z1 'QVdTIFNlY3JldCBLZXkg'),"aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
  ${_rx}.add($(_z1 'QVdTIEFwcFN5bmMgR3JhcGhRTCBLZXk='),"da2-[a-z0-9]{26}")
  ${_rx}.add($(_z1 'Q2xvdWRpbmFyeSBCYXNpYyBBdXRo'),"cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
  ${_rx}.add($(_z1 'RmFjZWJvb2sgQ2xpZW50IElE'),"([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9]{13,17}")
  ${_rx}.add($(_z1 'SmVua2lucyBDcmVkcw=='),"<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
  ${_rx}.add($(_z1 'Q29uZmlnIFNlY3JldHM='),"passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
}

if(${_k4m7q}){${_v8p1z}=$true}

${_rx}.add("IPs","(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
${_dv}=Get-PSDrive|Where-Object{$_.Root -like "*:\"}
${_fe}=@("*.xml","*.txt","*.conf","*.config","*.cfg","*.ini",".y*ml","*.log","*.bak","*.xls","*.xlsx","*.xlsm")

# ======================== INTRODUCTION ========================
${_sw}=[system.diagnostics.stopwatch]::StartNew()

# --- junk block eta ---
${_jnk21}=[byte[]]@(0xDE,0xAD);${_jnk22}=$null;if(${_jnk21}[0] -eq 0xFF){Write-Host 'phantom'}

if(${_k4m7q}){
  Write-Host $(_z1 'KipGdWxsIENoZWNrIEVuYWJsZWQuIFRoaXMgd2lsbCBzaWduaWZpY2FudGx5IGluY3JlYXNlIGZhbHNlIHBvc2l0aXZlcyBpbiByZWdpc3RyeSAvIGZvbGRlciBjaGVjayBmb3IgVXNlcm5hbWVzIC8gUGFzc3dvcmRzLioq')
}

Write-Host -BackgroundColor Red -ForegroundColor White $(_z1 'QURWSVNPU1k6IFdpblBFQVMgLSBXaW5kb3dzIGxvY2FsIFByaXZpbGVnZSBFc2NhbGF0aW9uIEF3ZXNvbWUgU2NyaXB0')
Write-Host -BackgroundColor Red -ForegroundColor White $(_z1 'V2luUEVBUyBzaG91bGQgYmUgdXNlZCBmb3IgYXV0aG9yaXplZCBwZW5ldHJhdGlvbiB0ZXN0aW5nIGFuZC9vciBlZHVjYXRpb25hbCBwdXJwb3NlcyBvbmx5')
Write-Host -BackgroundColor Red -ForegroundColor White $(_z1 'QW55IG1pc3VzZSBvZiB0aGlzIHNvZnR3YXJlIHdpbGwgbm90IGJlIHRoZSByZXNwb25zaWJpbGl0eSBvZiB0aGUgYXV0aG9yIG9yIG9mIGFueSBvdGhlciBjb2xsYWJvcmF0b3I=')
Write-Host -BackgroundColor Red -ForegroundColor White $(_z1 'VXNlIGl0IGF0IHlvdXIgb3duIG5ldHdvcmtzIGFuZC9vciB3aXRoIHRoZSBuZXR3b3JrIG93bmVyJ3MgZXhwbGljaXQgcGVybWlzc2lvbg==')

Write-Host -ForegroundColor Red $(_z1 'SW5kaWNhdGVzIHNwZWNpYWwgcHJpdmlsZWdlIG92ZXIgYW4gb2JqZWN0IG9yIG1pc2NvbmZpZ3VyYXRpb24=')
Write-Host -ForegroundColor Green $(_z1 'SW5kaWNhdGVzIHByb3RlY3Rpb24gaXMgZW5hYmxlZCBvciBzb21ldGhpbmcgaXMgd2VsbCBjb25maWd1cmVk')
Write-Host -ForegroundColor Cyan $(_z1 'SW5kaWNhdGVzIGFjdGl2ZSB1c2Vycw==')
Write-Host -ForegroundColor Gray $(_z1 'SW5kaWNhdGVzIGRpc2FibGVkIHVzZXJz')
Write-Host -ForegroundColor Yellow $(_z1 'SW5kaWNhdGVzIGxpbmtz')
Write-Host -ForegroundColor Blue $(_z1 'SW5kaWNhdGVzIHRpdGxl')

Write-Host $(_z1 'WW91IGNhbiBmaW5kIGEgV2luZG93cyBsb2NhbCBQRSBDaGVja2xpc3QgaGVyZTogaHR0cHM6Ly9ib29rLmhhY2t0cmlja3Mud2lraS9lbi93aW5kb3dzLWhhcmRlbmluZy9jaGVja2xpc3Qtd2luZG93cy1wcml2aWxlZ2UtZXNjYWxhdGlvbi5odG1s') -ForegroundColor Yellow
Write-Host $(_z1 'QmVzdCBMaW51eCBQRSAmIEhhcmRlbmluZyBjb3Vyc2U6IGh0dHBzOi8vaGFja3RyaWNrcy10cmFpbmluZy5jb20vY291cnNlcy9saGUv') -ForegroundColor Yellow

# ======================== SYSTEM INFORMATION ========================

Write-Host ""
if(${_x9f2a}){_d8t3e}
Write-Host $(_z1 'PT09PT09PT09PT09PT09PT09PT09PT09PT09PT18fFNZU1RFTSBJTkZPUk1BVElPTiB8fD09PT09PT09PT09PT09PT09PT09PT09PT09PT0=')
$(_z1 'VGhlIGZvbGxvd2luZyBpbmZvcm1hdGlvbiBpcyBjdXJhdGVkLiBUbyBnZXQgYSBmdWxsIGxpc3Qgb2Ygc3lzdGVtIGluZm9ybWF0aW9uLCBydW4gdGhlIGNtZGxldCBnZXQtY29tcHV0ZXJpbmZv')

systeminfo.exe

Write-Host ""
if(${_x9f2a}){_d8t3e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgV0lORE9XUyBIT1RGSVhFUw==')
Write-Host $(_z1 'PXwgQ2hlY2sgbWlzc2luZyBwYXRjaGVzIHdpdGggdGhlIGVtYmVkZGVkIHdpbmRvd3MgdnVsbmVyYWJpbGl0eSBkZWZpbml0aW9ucw==') -ForegroundColor Yellow
${_hf}=Get-HotFix|Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue|Select-Object HotfixID,Description,InstalledBy,InstalledOn
${_hf}|Format-Table -AutoSize

# PrintNightmare
Write-Host ""
if(${_x9f2a}){_d8t3e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUFJJTlROSUdIVE1BUkUgUE9JTlRBTkRQUklOVCBQT0xJQ1k=')
${_pnk}=$(_z1 'SEtMTTpcU29mdHdhcmVcUG9saWNpZXNcTWljcm9zb2Z0XFdpbmRvd3MgTlRcUHJpbnRlcnNcUG9pbnRBbmRQcmludA==')
if(Test-Path ${_pnk}){
  ${_pn}=Get-ItemProperty -Path ${_pnk} -ErrorAction SilentlyContinue
  ${_rst}=${_pn}.RestrictDriverInstallationToAdministrators
  ${_nw}=${_pn}.NoWarningNoElevationOnInstall
  ${_up2}=${_pn}.UpdatePromptSettings
  Write-Host "RestrictDriverInstallationToAdministrators: ${_rst}"
  Write-Host "NoWarningNoElevationOnInstall: ${_nw}"
  Write-Host "UpdatePromptSettings: ${_up2}"
  ${_hav}=($null -ne ${_rst}) -and ($null -ne ${_nw}) -and ($null -ne ${_up2})
  if(-not ${_hav}){
    Write-Host $(_z1 'UG9pbnRBbmRQcmludCBwb2xpY3kgdmFsdWVzIGFyZSBtaXNzaW5nIG9yIG5vdCBjb25maWd1cmVk') -ForegroundColor Gray
  }elseif((${_rst} -eq 0) -and (${_nw} -eq 1) -and (${_up2} -eq 2)){
    Write-Host $(_z1 'UG90ZW50aWFsbHkgdnVsbmVyYWJsZSB0byBQcmludE5pZ2h0bWFyZSBtaXNjb25maWd1cmF0aW9u') -ForegroundColor Red
  }else{
    Write-Host $(_z1 'UG9pbnRBbmRQcmludCBwb2xpY3kgaXMgbm90IGluIHRoZSBrbm93biByaXNreSBjb25maWd1cmF0aW9u') -ForegroundColor Green
  }
}else{
  Write-Host $(_z1 'UG9pbnRBbmRQcmludCBwb2xpY3kga2V5IG5vdCBmb3VuZA==') -ForegroundColor Gray
}

# All updates
Write-Host ""
if(${_x9f2a}){_d8t3e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQUxMIFVQREFURVMgSU5TVEFMTEVE')

${_ss}=(New-Object -ComObject $(_z1 'TWljcm9zb2Z0LlVwZGF0ZS5TZXNzaW9u'))
${_hs}=${_ss}.QueryHistory("",0,1000)|Select-Object ResultCode,Date,Title

${_hu}=@()
${_hr}=@()
for(${_i}=0;${_i} -lt ${_hs}.Count;${_i}++){
  ${_ck}=_a7r2k -_t1 ${_hs}[${_i}].Title
  if(${_hu} -like ${_ck}){}
  else{
    ${_hu}+=${_ck}
    ${_hr}+=${_i}
  }
}
${_fl}=@()

# --- junk block theta ---
${_jnk23}=[System.Text.StringBuilder]::new();[void]${_jnk23}.Append('r3d');${_jnk24}=${_jnk23}.ToString().Length

${_hr}|ForEach-Object{
  ${_hi}=${_hs}[$_]
  ${_rc}=${_hi}.ResultCode
  switch(${_rc}){
    1{${_rc}=$(_z1 'TWlzc2luZy9TdXBlcnNlZGVk')}
    2{${_rc}=$(_z1 'U3VjY2VlZGVk')}
    3{${_rc}=$(_z1 'U3VjY2VlZGVkIFdpdGggRXJyb3Jz')}
    4{${_rc}=$(_z1 'RmFpbGVk')}
    5{${_rc}=$(_z1 'Q2FuY2VsZWQ=')}
  }
  ${_fl}+=New-Object -TypeName PSObject -Property ([Ordered]@{Result=${_rc};Date=${_hi}.Date;Title=${_hi}.Title})
}
${_fl}|Format-Table -AutoSize

# Drive Info
Write-Host ""
if(${_x9f2a}){_d8t3e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgRHJpdmUgSW5mbw==')
Add-Type -AssemblyName System.Management
${_ds}=New-Object System.Management.ManagementObjectSearcher($(_z1 'U0VMRUNUICogRlJPTSBXaW4zMl9Mb2dpY2FsRGlzayBXSEVSRSBEcml2ZVR5cGUgPSAz'))
${_sd}=${_ds}.Get()
foreach(${_d} in ${_sd}){
  ${_dl}=${_d}.DeviceID
  ${_lb}=${_d}.VolumeName
  ${_sz}=[math]::Round(${_d}.Size/1GB,2)
  ${_fs}=[math]::Round(${_d}.FreeSpace/1GB,2)
  Write-Output "Drive: ${_dl}"
  Write-Output "Label: ${_lb}"
  Write-Output "Size: ${_sz} GB"
  Write-Output "Free Space: ${_fs} GB"
  Write-Output ""
}

# --- END OF PROVIDED CODE (original was truncated) ---
# Remaining sections would follow the same obfuscation pattern:
# - Function/variable renaming to _[random]
# - String encoding via _z1 (Base64)
# - Junk blocks interspersed
# - All comments stripped
# - Cmdlet calls preserved for runtime compatibility

Write-Host ""
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgT0JGVVNDQVRJT04gQ09NUExFVEUgLSBSZW1haW5pbmcgc2VjdGlvbnMgcmVxdWlyZSBmdWxsIHNvdXJjZQ==')
