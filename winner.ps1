# :: 0xR3C0N :: d0_n0t_3d1t :: g3n_v2 ::
[CmdletBinding()]param([switch]${_x9a},[switch]${_k4q},[switch]${_v8z})
function _z1([string]$s){[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))}
${_jA1}=0x2F3A;${_jA2}=[math]::PI;if(${_jA1} -gt 99999){${_jA2}=$null}
function _a7k{param([string]${_t1})
if((${_t1}|Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value){return((${_t1}|Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value)}
elseif((${_t1}|Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value){return((${_t1}|Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value)}}
function _b3w{param(${_tg},${_sn})
if($null -ne ${_tg}){try{${_ac}=Get-Acl ${_tg} -ErrorAction SilentlyContinue}catch{${_ac}=$null}
if(${_ac}){${_id}=@();${_id}+="$env:COMPUTERNAME\$env:USERNAME"
if(${_ac}.Owner -like ${_id}){Write-Host "$(_z1 'aGFzIG93bmVyc2hpcCBvZg==') ${_tg}" -ForegroundColor Red}
whoami.exe /groups /fo csv|Select-Object -Skip 2|ConvertFrom-Csv -Header $(_z1 'Z3JvdXAgbmFtZQ==')|Select-Object -ExpandProperty $(_z1 'Z3JvdXAgbmFtZQ==')|ForEach-Object{${_id}+=$_}
${_if}=$false
foreach(${_i} in ${_id}){${_pm}=${_ac}.Access|Where-Object{$_.IdentityReference -like ${_i}}
${_up}=""
switch -WildCard(${_pm}.FileSystemRights){"FullControl"{${_up}="FullControl";${_if}=$true}"Write*"{${_up}="Write";${_if}=$true}"Modify"{${_up}="Modify";${_if}=$true}}
Switch(${_pm}.RegistryRights){"FullControl"{${_up}="FullControl";${_if}=$true}}
if(${_up}){if(${_sn}){Write-Host "${_sn} $(_z1 'Zm91bmQgd2l0aCBwZXJtaXNzaW9ucyBpc3N1ZTo=')" -ForegroundColor Red}
Write-Host -ForegroundColor Red "Identity $(${_pm}.IdentityReference) has '${_up}' perms for ${_tg}"}}
if(${_if} -eq $false){if(${_tg}.Length -gt 3){${_tg}=Split-Path ${_tg};_b3w ${_tg} -_sn ${_sn}}}}
else{${_tg}=Split-Path ${_tg};_b3w ${_tg} ${_sn}}}}
${_jB1}=[guid]::NewGuid().ToString().Substring(0,8);${_jB2}=@(1,2,3)|Where-Object{$_ -gt 99}
function _c5q{Write-Host $(_z1 'RmV0Y2hpbmcgdGhlIGxpc3Qgb2Ygc2VydmljZXMsIHRoaXMgbWF5IHRha2UgYSB3aGlsZS4uLg==')
${_sv}=Get-WmiObject -Class Win32_Service|Where-Object{$_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and($_.State -eq "Running" -or $_.State -eq "Stopped")}
if($(${_sv}|Measure-Object).Count -lt 1){Write-Host $(_z1 'Tm8gdW5xdW90ZWQgc2VydmljZSBwYXRocyB3ZXJlIGZvdW5k')}
else{${_sv}|ForEach-Object{Write-Host $(_z1 'VW5xdW90ZWQgU2VydmljZSBQYXRoIGZvdW5kIQ==') -ForegroundColor Red
Write-Host "Name:" $_.Name;Write-Host "PathName:" $_.PathName;Write-Host "StartName:" $_.StartName;Write-Host "StartMode:" $_.StartMode;Write-Host "Running:" $_.State}}}
function _d8e{Write-Host "Time Running: $(${_sw7}.Elapsed.Minutes):$(${_sw7}.Elapsed.Seconds)"}
function _e2y{Add-Type -AssemblyName PresentationCore;${_tx}=[Windows.Clipboard]::GetText()
if(${_tx}){Write-Host "";if(${_x9a}){_d8e};Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2xpcEJvYXJkIHRleHQgZm91bmQ6');Write-Host ${_tx}}}
function _f4n{try{return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()}catch{return $null}}
function _g6p{param(${_si});if($null -eq ${_si}){return $null}
try{if(${_si} -is [System.Security.Principal.SecurityIdentifier]){${_so}=${_si}}else{${_so}=New-Object System.Security.Principal.SecurityIdentifier(${_si})}
return ${_so}.Translate([System.Security.Principal.NTAccount]).Value}catch{try{return ${_so}.Value}catch{return [string]${_si}}}}
${_jC1}=$null;try{${_jC1}=[math]::Log(-1)}catch{};${_jC2}=$false -and $true
function _h1r{param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
if(-not ${_dc}){return @()}
${_dn}=${_dc}.GetDirectoryEntry().distinguishedName;${_fn}=${_dc}.Forest.RootDomain.GetDirectoryEntry().distinguishedName
${_pt}=@("LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,${_dn}","LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,${_fn}","LDAP://CN=MicrosoftDNS,${_dn}")
${_wp}=@($(_z1 'YXV0aGVudGljYXRlZCB1c2Vycw=='),$(_z1 'ZXZlcnlvbmU='),$(_z1 'ZG9tYWluIHVzZXJz'))
${_dr}=@("GenericAll","GenericWrite","CreateChild","WriteProperty","WriteDacl","WriteOwner")
${_fd}=@()
foreach(${_p} in ${_pt}){try{${_cn}=New-Object System.DirectoryServices.DirectoryEntry(${_p});$null=${_cn}.NativeGuid}catch{continue}
${_sr}=New-Object System.DirectoryServices.DirectorySearcher(${_cn});${_sr}.Filter="(objectClass=dnsZone)";${_sr}.PageSize=500;${_rs}=${_sr}.FindAll()
foreach(${_r} in ${_rs}){try{${_ze}=${_r}.GetDirectoryEntry();${_ze}.Options.SecurityMasks=[System.DirectoryServices.SecurityMasks]::Dacl;${_sd}=${_ze}.ObjectSecurity
foreach(${_ace} in ${_sd}.Access){if(${_ace}.AccessControlType -ne 'Allow'){continue};${_pr}=_g6p ${_ace}.IdentityReference;if(-not ${_pr}){continue}
${_pl}=${_pr}.ToLower();if(-not(${_wp}|Where-Object{${_pl} -like "*${_}*"})){continue};${_rt}=${_ace}.ActiveDirectoryRights.ToString()
if(-not(${_dr}|Where-Object{${_rt} -like "*${_}*"})){continue}
${_fd}+=[pscustomobject]@{Zone=${_ze}.Properties["name"].Value;Partition=${_p}.Split(',')[1];Principal=${_pr};Rights=${_rt}}}}catch{continue}}}
return(${_fd}|Sort-Object Zone,Principal -Unique)}
function _i3u{param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
if(-not ${_dc}){return @()};${_dn}=${_dc}.GetDirectoryEntry().distinguishedName
try{${_sr}=New-Object System.DirectoryServices.DirectorySearcher;${_sr}.SearchRoot=New-Object System.DirectoryServices.DirectoryEntry("LDAP://${_dn}")
${_sr}.Filter="(&(objectClass=msDS-GroupManagedServiceAccount))";${_sr}.PageSize=500
[void]${_sr}.PropertiesToLoad.Add("sAMAccountName");[void]${_sr}.PropertiesToLoad.Add("msDS-GroupMSAMembership");${_rs}=${_sr}.FindAll()}catch{return @()}
${_rp}=@()
foreach(${_r} in ${_rs}){${_nm}=${_r}.Properties["samaccountname"];${_bl}=${_r}.Properties["msds-groupmsamembership"];if(-not ${_bl}){continue}
${_pc}=@();foreach(${_b} in ${_bl}){try{${_rw}=New-Object System.Security.AccessControl.RawSecurityDescriptor(,${_b})
foreach(${_ace} in ${_rw}.DiscretionaryAcl){${_sd2}=_g6p ${_ace}.SecurityIdentifier;if(${_sd2}){${_pc}+=${_sd2}}}}catch{continue}}
if(${_pc}.Count -eq 0){continue};${_pc}=${_pc}|Sort-Object -Unique
${_wk}=${_pc}|Where-Object{$_ -match 'Domain Users|Authenticated Users|Everyone'}
${_rp}+=[pscustomobject]@{Account=(${_nm}|Select-Object -First 1);Allowed=(${_pc} -join ", ");WeakPrincipals=if(${_wk}){${_wk} -join ", "}else{""}}}
return ${_rp}}
function _j5v{param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
if(-not ${_dc}){return @()};${_dn}=${_dc}.GetDirectoryEntry().distinguishedName
${_kw}=@($(_z1 'RG9tYWluIEFkbWlu'),$(_z1 'RW50ZXJwcmlzZSBBZG1pbg=='),$(_z1 'QWRtaW5pc3RyYXRvcnM='),$(_z1 'RXhjaGFuZ2U='),"IT_",$(_z1 'U2NoZW1hIEFkbWlu'),$(_z1 'QWNjb3VudCBPcGVyYXRvcg=='),$(_z1 'U2VydmVyIE9wZXJhdG9y'),$(_z1 'QmFja3VwIE9wZXJhdG9y'),$(_z1 'RG5zQWRtaW4='))
try{${_sr}=New-Object System.DirectoryServices.DirectorySearcher;${_sr}.SearchRoot=New-Object System.DirectoryServices.DirectoryEntry("LDAP://${_dn}")
${_sr}.Filter="(&(objectClass=user)(servicePrincipalName=*))";${_sr}.PageSize=500
[void]${_sr}.PropertiesToLoad.Add("sAMAccountName");[void]${_sr}.PropertiesToLoad.Add("memberOf");${_rs}=${_sr}.FindAll()}catch{return @()}
${_fd}=@()
foreach(${_r} in ${_rs}){${_gr}=${_r}.Properties["memberof"];if(-not ${_gr}){continue};${_mg}=@()
foreach(${_g} in ${_gr}){${_cn2}=(${_g} -split ',')[0] -replace '^CN=','';if(${_kw}|Where-Object{${_cn2} -like "*${_}*"}){${_mg}+=${_cn2}}}
if(${_mg}.Count -gt 0){${_fd}+=[pscustomobject]@{User=(${_r}.Properties["samaccountname"]|Select-Object -First 1);Groups=(${_mg}|Sort-Object -Unique) -join ', '}}}
return(${_fd}|Sort-Object User|Select-Object -First 12)}
function _k7x{try{${_mv}=Get-ItemProperty -Path $(_z1 'SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcTHNhXE1TVjFfMA==') -ErrorAction Stop}catch{return $null}
${_ls}=Get-ItemProperty -Path $(_z1 'SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcTHNh') -ErrorAction SilentlyContinue
return [pscustomobject]@{RestrictReceiving=${_mv}.RestrictReceivingNTLMTraffic;RestrictSending=${_mv}.RestrictSendingNTLMTraffic;LmCompatibility=if(${_ls}){${_ls}.LmCompatibilityLevel}else{$null}}}
function _l9z{param([System.DirectoryServices.ActiveDirectory.Domain]${_dc})
if(-not ${_dc}){return $null};try{${_pdc}=${_dc}.PdcRoleOwner.Name}catch{return $null}
try{${_sc}=w32tm /stripchart /computer:${_pdc} /dataonly /samples:3 2>$null
${_sm}=${_sc}|Where-Object{$_ -match ','}|Select-Object -Last 1;if(-not ${_sm}){return $null}
${_pt2}=${_sm}.Split(',');if(${_pt2}.Count -lt 2){return $null};${_os}=${_pt2}[1].Trim().TrimEnd('s')
[double]${_ov}=0;if(-not [double]::TryParse(${_os},[ref]${_ov})){return $null}
return [pscustomobject]@{Source=${_pdc};OffsetSeconds=${_ov};RawSample=${_sm}}}catch{return $null}}
function _m2b{${_inf}=[ordered]@{MappingValue=$null;UpnMapping=$false;ServiceState=$null}
try{${_sch}=Get-ItemProperty -Path $(_z1 'SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcU2VjdXJpdHlQcm92aWRlcnNcU0NIQU5ORUw=') -Name 'CertificateMappingMethods' -ErrorAction Stop
${_inf}.MappingValue=${_sch}.CertificateMappingMethods;if((${_sch}.CertificateMappingMethods -band 0x4) -eq 0x4){${_inf}.UpnMapping=$true}}catch{}
${_svc}=Get-Service -Name certsrv -ErrorAction SilentlyContinue;if(${_svc}){${_inf}.ServiceState=${_svc}.Status}
return [pscustomobject]${_inf}}
${_jD1}=[byte[]]@(0xDE,0xAD);${_jD2}=$null;if(${_jD1}[0] -eq 0xFF){Write-Host 'phantom'}
function _n4d{[cmdletbinding()]Param([parameter(Mandatory,ValueFromPipeline)][ValidateScript({Try{If(Test-Path -Path $_){$True}Else{Throw "$($_) is not a valid path!"}}Catch{Throw $_}})][string]${_src},[parameter(Mandatory)][string]${_stx})
${_xl}=New-Object -ComObject Excel.Application;Try{${_src}=Convert-Path ${_src}}Catch{Write-Warning "Unable locate full path of $(${_src})";BREAK}
${_wb}=${_xl}.Workbooks.Open(${_src})
ForEach(${_ws} in @(${_wb}.Sheets)){${_fnd}=${_ws}.Cells.Find(${_stx})
If(${_fnd}){try{Write-Host "Pattern: '${_stx}' found in ${_src}" -ForegroundColor Blue;${_ba}=${_fnd}.Address(0,0,1,1)
New-Object -TypeName PSObject -Property([Ordered]@{WorkSheet=${_ws}.Name;Column=${_fnd}.Column;Row=${_fnd}.Row;TextMatch=${_fnd}.Text;Address=${_ba}})
Do{${_fnd}=${_ws}.Cells.FindNext(${_fnd});${_ad}=${_fnd}.Address(0,0,1,1);If(${_ad} -eq ${_ba}){BREAK}
New-Object -TypeName PSObject -Property([Ordered]@{WorkSheet=${_ws}.Name;Column=${_fnd}.Column;Row=${_fnd}.Row;TextMatch=${_fnd}.Text;Address=${_ad}})}Until($False)}catch{}}}
try{${_wb}.close($False);[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]${_xl});[gc]::Collect();[gc]::WaitForPendingFinalizers()}catch{}
Remove-Variable _xl -ErrorAction SilentlyContinue}
function _o6f{[cmdletbinding()]param([Parameter(DontShow)]${_ky}=@('','\Wow6432Node'))
foreach(${_k} in ${_ky}){try{${_ap}=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE${_k}\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()}catch{Continue}
foreach(${_a} in ${_ap}){${_pg}=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE${_k}\Microsoft\Windows\CurrentVersion\Uninstall\${_a}")
${_nm2}=${_pg}.GetValue('DisplayName')
if(${_nm2}){New-Object -TypeName PSObject -Property([Ordered]@{Computername=$env:COMPUTERNAME;Software=${_nm2};Version=${_pg}.GetValue("DisplayVersion");Publisher=${_pg}.GetValue("Publisher");InstallDate=${_pg}.GetValue("InstallDate");UninstallString=${_pg}.GetValue("UninstallString");Architecture=$(if(${_k} -eq '\wow6432node'){'x86'}else{'x64'});Path=${_pg}.Name})}}}}
function _p8h([String[]]${_tx2},[ConsoleColor[]]${_cl}){for(${_i}=0;${_i} -lt ${_tx2}.Length;${_i}++){Write-Host ${_tx2}[${_i}] -Foreground ${_cl}[${_i}] -NoNewline};Write-Host}
${_jE1}=@{a=1;b=2};${_jE2}=${_jE1}.Keys|ForEach-Object{"$_$(Get-Random)"}
_p8h ",/*,..*(((((((((((((((((((((((((((((((((," Green
_p8h ",*/((((((((((((((((((/,  .*//((//**, .*((((((*" Green
_p8h "((((((((((((((((","* *****,,,","\########## .(* ,((((((" Green,Blue,Green
_p8h "(((((((((((","/*******************","####### .(. ((((((" Green,Blue,Green
_p8h "(((((((","/******************","/@@@@@/","***","\#######\((((((" Green,Blue,White,Blue,Green
_p8h ",,..","**********************","/@@@@@@@@@/","***",",#####.\/(((((" Green,Blue,White,Blue,Green
_p8h ", ,","**********************","/@@@@@+@@@/","*********","##((/ /((((" Green,Blue,White,Blue,Green
_p8h "..(((##########","*********","/#@@@@@@@@@/","*************",",,..((((" Green,Blue,White,Blue,Green
_p8h ".(((################(/","******","/@@@@@/","****************",".. /((" Green,Blue,White,Blue,Green
_p8h ".((########################(/","************************","..*(" Green,Blue,Green
_p8h ".((#############################(/","********************",".,(" Green,Blue,Green
_p8h ".((##################################(/","***************","..(  " Green,Blue,Green
_p8h ".((######################################(/","***********","..(  " Green,Blue,Green
_p8h ".((######","(,.***.,(","###################","(..***","(/*********","..(  " Green,Green,Green,Green,Blue,Green
_p8h ".((######*","(####((","###################","((######","/(********","..(  " Green,Green,Green,Green,Blue,Green
_p8h ".((##################","(/**********(","################(**...(  " Green,Green,Green
_p8h ".(((####################","/*******(","###################.((((  " Green,Green,Green
_p8h ".(((((############################################/  /((" Green
_p8h "..(((((#########################################(..(((((." Green
_p8h "....(((((#####################################( .((((((.  " Green
_p8h "......(((((#################################( .(((((((." Green
_p8h "(((((((((. ,(############################(../(((((((((." Green
_p8h "  (((((((((/,  ,####################(/..((((((((((." Green
_p8h "        (((((((((/,.  ,*//////*,. ./(((((((((((." Green
_p8h "           (((((((((((((((((((((((((((/" Green
_p8h "          by PEASS-ng & RandolphConley" Green
${_pw3}=$true;${_un5}=$true;${_wa8}=$true;${_rx2}=@{}
${_jF1}=0;while(${_jF1} -gt 1){${_jF1}++}
if(${_pw3}){
${_rx2}.add($(_z1 'U2ltcGxlIFBhc3N3b3JkczE='),"pass.*[=:].+")
${_rx2}.add($(_z1 'U2ltcGxlIFBhc3N3b3JkczI='),"pwd.*[=:].+")
${_rx2}.add($(_z1 'QXByMSBNRDU='),'$apr1$[a-zA-Z0-9_/\.]{8}$[a-zA-Z0-9_/\.]{22}')
${_rx2}.add($(_z1 'QXBhY2hlIFNIQQ=='),"\{SHA\}[0-9a-zA-Z/_=]{10,}")
${_rx2}.add($(_z1 'Qmxvd2Zpc2g='),'$2[abxyz]?$[0-9]{2}$[a-zA-Z0-9_/\.]*')
${_rx2}.add($(_z1 'RHJ1cGFs'),'$S$[a-zA-Z0-9_/\.]{52}')
${_rx2}.add($(_z1 'Sm9vbWxhdmJ1bGxldGlu'),"[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
${_rx2}.add($(_z1 'TGludXggTUQ1'),'$1$[a-zA-Z0-9_/\.]{8}$[a-zA-Z0-9_/\.]{22}')
${_rx2}.add("phpbb3",'$H$[a-zA-Z0-9_/\.]{31}')
${_rx2}.add($(_z1 'c2hhNTEyY3J5cHQ='),'$6$[a-zA-Z0-9_/\.]{16}$[a-zA-Z0-9_/\.]{86}')
${_rx2}.add($(_z1 'V29yZHByZXNz'),'$P$[a-zA-Z0-9_/\.]{31}')
${_rx2}.add("md5","(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
${_rx2}.add("sha1","(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
${_rx2}.add("sha256","(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
${_rx2}.add("sha512","(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")
${_rx2}.add($(_z1 'QmFzZTY0'),"(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")}
if(${_un5}){
${_rx2}.add($(_z1 'VXNlcm5hbWVzMQ=='),"username[=:].+")
${_rx2}.add($(_z1 'VXNlcm5hbWVzMg=='),"user[=:].+")
${_rx2}.add($(_z1 'VXNlcm5hbWVzMw=='),"login[=:].+")
${_rx2}.add($(_z1 'RW1haWxz'),"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
${_rx2}.add($(_z1 'TmV0IHVzZXIgYWRk'),"net user .+ /add")}
if(${_k4q}){
${_rx2}.add($(_z1 'QXJ0aWZhY3RvcnkgQVBJIFRva2Vu'),"AKC[a-zA-Z0-9]{10,}")
${_rx2}.add($(_z1 'QXJ0aWZhY3RvcnkgUGFzc3dvcmQ='),"AP[0-9ABCDEF][a-zA-Z0-9]{8,}")
${_rx2}.add($(_z1 'QWRhZnJ1aXQgQVBJIEtleQ=='),"([a-z0-9_-]{32})")
${_rx2}.add($(_z1 'RmFjZWJvb2sgQWNjZXNzIFRva2Vu'),"EAACEdEose0cBA[0-9A-Za-z]+")
${_rx2}.add($(_z1 'R2l0aHVi'),"github(.{0,20})?['""][0-9a-zA-Z]{35,40}")
${_rx2}.add($(_z1 'R2l0aHViIEFwcCBUb2tlbg=='),"(ghu|ghs)_[0-9a-zA-Z]{36}")
${_rx2}.add($(_z1 'R2l0aHViIE9BdXRoIEFjY2VzcyBUb2tlbg=='),"gho_[0-9a-zA-Z]{36}")
${_rx2}.add($(_z1 'R2l0aHViIFBlcnNvbmFsIEFjY2VzcyBUb2tlbg=='),"ghp_[0-9a-zA-Z]{36}")
${_rx2}.add($(_z1 'R2l0aHViIFJlZnJlc2ggVG9rZW4='),"ghr_[0-9a-zA-Z]{76}")
${_rx2}.add($(_z1 'R2l0SHViIEZpbmUtR3JhaW5lZA=='),"github_pat_[0-9a-zA-Z_]{82}")
${_rx2}.add($(_z1 'R2l0bGFiIFBBVA=='),"glpat-[0-9a-zA-Z\-]{20}")
${_rx2}.add($(_z1 'R2l0TGFiIFBpcGVsaW5l'),"glptt-[0-9a-f]{40}")
${_rx2}.add($(_z1 'R2l0TGFiIFJ1bm5lcg=='),"GR1348941[0-9a-zA-Z_\-]{20}")
${_rx2}.add($(_z1 'R29vZ2xlIEFQSSBLZXk='),"AIza[0-9A-Za-z_\-]{35}")
${_rx2}.add($(_z1 'R29vZ2xlIE9hdXRo'),"ya29\.[0-9A-Za-z_\-]+")
${_rx2}.add($(_z1 'T3BlbkFJIEFQSQ=='),"sk-[A-Za-z0-9]{48}")
${_rx2}.add($(_z1 'U2xhY2sgVG9rZW4='),"xox[baprs]-([0-9a-zA-Z]{10,48})?")
${_rx2}.add($(_z1 'U2xhY2sgV2ViaG9vaw=='),"https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}")
${_rx2}.add($(_z1 'U3RyaXBl'),"(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}")
${_rx2}.add($(_z1 'VHdpbGlv'),"SK[0-9a-fA-F]{32}")
${_rx2}.add($(_z1 'UHJpdmF0ZSBLZXlz'),"\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
${_rx2}.add($(_z1 'SldU'),"(ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2})")
${_rx2}.add($(_z1 'QVDTIEN1aWVudA=='),"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
${_rx2}.add($(_z1 'QVdTIFNlY3JldA=='),"aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
${_rx2}.add($(_z1 'U2VuZGdyaWQ='),"SG\.[a-zA-Z0-9_\.\-]{66}")
${_rx2}.add($(_z1 'TWFpbGNoaW1w'),"[0-9a-f]{32}-us[0-9]{1,2}")
${_rx2}.add($(_z1 'TWFpbGd1bg=='),"key-[0-9a-zA-Z]{32}'")
${_rx2}.add($(_z1 'SGVyb2t1'),"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
${_rx2}.add($(_z1 'VGVsZWdyYW0='),"[0-9]+:AA[0-9A-Za-z\\-_]{33}")
${_rx2}.add($(_z1 'R2VuZXJpYyBBUEkgS2V5'),"((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")}
if(${_wa8}){
${_rx2}.add($(_z1 'QXV0aG9yaXphdGlvbiBCYXNpYw=='),"basic [a-zA-Z0-9_:\.=\-]+")
${_rx2}.add($(_z1 'QXV0aG9yaXphdGlvbiBCZWFyZXI='),"bearer [a-zA-Z0-9_\.=\-]+")
${_rx2}.add($(_z1 'QWxpYmFiYQ=='),"(LTAI)[a-z0-9]{20}")
${_rx2}.add($(_z1 'QVdTIENsaWVudCBJRA=='),"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
${_rx2}.add($(_z1 'QVdTIE1XUw=='),"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
${_rx2}.add($(_z1 'QVdTIFNlY3JldCBLZXk='),"aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
${_rx2}.add($(_z1 'QVdTIEFwcFN5bmM='),"da2-[a-z0-9]{26}")
${_rx2}.add($(_z1 'QmFzaWMgQXV0aCBDcmVkcw=='),"://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
${_rx2}.add($(_z1 'Q2xvdWRpbmFyeQ=='),"cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
${_rx2}.add($(_z1 'RmFjZWJvb2sgQ2xpZW50'),"([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9]{13,17}")
${_rx2}.add($(_z1 'SmVua2lucw=='),"<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
${_rx2}.add($(_z1 'R2VuZXJpYyBTZWNyZXQ='),"[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
${_rx2}.add($(_z1 'QmFzaWMgQXV0aA=='),"//(.+):(.+)@")
${_rx2}.add($(_z1 'UEhQIFBhc3N3b3Jkcw=='),"(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
${_rx2}.add($(_z1 'Q29uZmlnIFNlY3JldHM='),"passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
${_rx2}.add($(_z1 'R2VuZXJpYyBBUEkgdG9rZW5z'),"(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")}
if(${_k4q}){${_v8z}=$true}
${_rx2}.add("IPs","(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
${_dv6}=Get-PSDrive|Where-Object{$_.Root -like "*:\"}
${_fe4}=@("*.xml","*.txt","*.conf","*.config","*.cfg","*.ini",".y*ml","*.log","*.bak","*.xls","*.xlsx","*.xlsm")
${_sw7}=[system.diagnostics.stopwatch]::StartNew()
${_jG1}=[System.Collections.ArrayList]::new();${_jG2}='xR7kQ2pL9'
if(${_k4q}){Write-Host $(_z1 'KipGdWxsIENoZWNrIEVuYWJsZWQuIFRoaXMgd2lsbCBzaWduaWZpY2FudGx5IGluY3JlYXNlIGZhbHNlIHBvc2l0aXZlcyBpbiByZWdpc3RyeSAvIGZvbGRlciBjaGVjayBmb3IgVXNlcm5hbWVzIC8gUGFzc3dvcmRzLioq')}
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
Write-Host "";if(${_x9a}){_d8e}
Write-Host $(_z1 'PT09PT09PT09PT09PT09PT09PT09PT09PT09PT18fFNZU1RFTSBJTkZPUk1BVElPTiB8fD09PT09PT09PT09PT09PT09PT09PT09PT09PT0=')
$(_z1 'VGhlIGZvbGxvd2luZyBpbmZvcm1hdGlvbiBpcyBjdXJhdGVkLiBUbyBnZXQgYSBmdWxsIGxpc3Qgb2Ygc3lzdGVtIGluZm9ybWF0aW9uLCBydW4gdGhlIGNtZGxldCBnZXQtY29tcHV0ZXJpbmZv')
systeminfo.exe
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgV0lORE9XUyBIT1RGSVhFUw==')
Write-Host $(_z1 'PXwgQ2hlY2sgbWlzc2luZyBwYXRjaGVzIHdpdGggdGhlIGVtYmVkZGVkIHdpbmRvd3MgdnVsbmVyYWJpbGl0eSBkZWZpbml0aW9ucw==') -ForegroundColor Yellow
${_hf3}=Get-HotFix|Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue|Select-Object HotfixID,Description,InstalledBy,InstalledOn
${_hf3}|Format-Table -AutoSize
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUFJJTlROSUdIVE1BUkUgUE9JTlRBTkRQUklOVCBQT0xJQ1k=')
${_pk8}=$(_z1 'SEtMTTpcU29mdHdhcmVcUG9saWNpZXNcTWljcm9zb2Z0XFdpbmRvd3MgTlRcUHJpbnRlcnNcUG9pbnRBbmRQcmludA==')
if(Test-Path ${_pk8}){${_pn}=Get-ItemProperty -Path ${_pk8} -ErrorAction SilentlyContinue
${_rst}=${_pn}.RestrictDriverInstallationToAdministrators;${_nw}=${_pn}.NoWarningNoElevationOnInstall;${_up2}=${_pn}.UpdatePromptSettings
Write-Host "RestrictDriverInstallationToAdministrators: ${_rst}";Write-Host "NoWarningNoElevationOnInstall: ${_nw}";Write-Host "UpdatePromptSettings: ${_up2}"
${_hav}=($null -ne ${_rst}) -and ($null -ne ${_nw}) -and ($null -ne ${_up2})
if(-not ${_hav}){Write-Host $(_z1 'UG9pbnRBbmRQcmludCBwb2xpY3kgdmFsdWVzIGFyZSBtaXNzaW5nIG9yIG5vdCBjb25maWd1cmVk') -ForegroundColor Gray}
elseif((${_rst} -eq 0) -and (${_nw} -eq 1) -and (${_up2} -eq 2)){Write-Host $(_z1 'UG90ZW50aWFsbHkgdnVsbmVyYWJsZSB0byBQcmludE5pZ2h0bWFyZSBtaXNjb25maWd1cmF0aW9u') -ForegroundColor Red}
else{Write-Host $(_z1 'UG9pbnRBbmRQcmludCBwb2xpY3kgaXMgbm90IGluIHRoZSBrbm93biByaXNreSBjb25maWd1cmF0aW9u') -ForegroundColor Green}}
else{Write-Host $(_z1 'UG9pbnRBbmRQcmludCBwb2xpY3kga2V5IG5vdCBmb3VuZA==') -ForegroundColor Gray}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQUxMIFVQREFURVMgSU5TVEFMTEVE')
${_ss9}=(New-Object -ComObject 'Microsoft.Update.Session')
${_hs1}=${_ss9}.QueryHistory("",0,1000)|Select-Object ResultCode,Date,Title
${_hu2}=@();${_hr4}=@()
for(${_i}=0;${_i} -lt ${_hs1}.Count;${_i}++){${_ck}=_a7k -_t1 ${_hs1}[${_i}].Title;if(${_hu2} -like ${_ck}){}else{${_hu2}+=${_ck};${_hr4}+=${_i}}}
${_fl6}=@()
${_hr4}|ForEach-Object{${_hi}=${_hs1}[$_];${_rc}=${_hi}.ResultCode
switch(${_rc}){1{${_rc}=$(_z1 'TWlzc2luZy9TdXBlcnNlZGVk')}2{${_rc}=$(_z1 'U3VjY2VlZGVk')}3{${_rc}=$(_z1 'U3VjY2VlZGVkIFdpdGggRXJyb3Jz')}4{${_rc}=$(_z1 'RmFpbGVk')}5{${_rc}=$(_z1 'Q2FuY2VsZWQ=')}}
${_fl6}+=New-Object -TypeName PSObject -Property([Ordered]@{Result=${_rc};Date=${_hi}.Date;Title=${_hi}.Title})}
${_fl6}|Format-Table -AutoSize
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgRHJpdmUgSW5mbw==')
Add-Type -AssemblyName System.Management
${_ds}=New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")
${_sd3}=${_ds}.Get()
foreach(${_d} in ${_sd3}){${_dl}=${_d}.DeviceID;${_lb}=${_d}.VolumeName;${_sz}=[math]::Round(${_d}.Size/1GB,2);${_fs}=[math]::Round(${_d}.FreeSpace/1GB,2)
Write-Output "Drive: ${_dl}";Write-Output "Label: ${_lb}";Write-Output "Size: ${_sz} GB";Write-Output "Free Space: ${_fs} GB";Write-Output ""}
${_jH1}=@(97,110,116,105)|ForEach-Object{[char]$_};${_jH2}=${_jH1} -join ''
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQW50aXZpcnVzIERldGVjdGlvbiAoYXR0ZW1waW5nIHRvIHJlYWQgZXhjbHVzaW9ucyBhcyB3ZWxsKQ==')
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTkVUIEFDQ09VTlRTIEluZm8=')
net accounts
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUkVHSVNUUlkgU0VUVElOR1MgQ0hFQ0s=')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQXVkaXQgTG9nIFNldHRpbmdz')
if((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property){Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\}
else{Write-Host $(_z1 'Tm8gQXVkaXQgTG9nIHNldHRpbmdzLCBubyByZWdpc3RyeSBlbnRyeSBmb3VuZC4=')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgV2luZG93cyBFdmVudCBGb3J3YXJkIChXRUYpIHJlZ2lzdHJ5')
if(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager){Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager}
else{Write-Host $(_z1 'TG9ncyBhcmUgbm90IGJlaW5nIGZvd2FyZGVkLCBubyByZWdpc3RyeSBlbnRyeSBmb3VuZC4=')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTEFQUyBDaGVjaw==')
if(Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll'){Write-Host $(_z1 'TEFQUyBkbGwgZm91bmQgb24gdGhpcyBtYWNoaW5lIGF0IEM6XFByb2dyYW0gRmlsZXNcTEFQU1xDU0Vc') -ForegroundColor Green}
elseif(Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'){Write-Host $(_z1 'TEFQUyBkbGwgZm91bmQgb24gdGhpcyBtYWNoaW5lIGF0IEM6XFByb2dyYW0gRmlsZXMgKHg4NilcTEFQU1xDU0Vc') -ForegroundColor Green}
else{Write-Host $(_z1 'TEFQUyBkbGxzIG5vdCBmb3VuZCBvbiB0aGlzIG1hY2hpbmU=')}
if((Get-ItemProperty HKLM:\Software\Policies\Microsoft` Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1){Write-Host $(_z1 'TEFQUyByZWdpc3RyeSBrZXkgZm91bmQgb24gdGhpcyBtYWNoaW5l') -ForegroundColor Green}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgV0RpZ2VzdCBDaGVjaw==')
${_wd}=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential
switch(${_wd}){0{Write-Host $(_z1 'VmFsdWUgMCBmb3VuZC4gUGxhaW4tdGV4dCBQYXNzd29yZHMgYXJlIG5vdCBzdG9yZWQgaW4gTFNBU1M=')}1{Write-Host $(_z1 'VmFsdWUgMSBmb3VuZC4gUGxhaW4tdGV4dCBQYXNzd29yZHMgbWF5IGJlIHN0b3JlZCBpbiBMU0FTUw==') -ForegroundColor Red}Default{Write-Host $(_z1 'VGhlIHN5c3RlbSB3YXMgdW5hYmxlIHRvIGZpbmQgdGhlIHNwZWNpZmllZCByZWdpc3RyeSB2YWx1ZTogVXNlTG9nb25DcmVkZW50aWFs')}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTFNBIFByb3RlY3Rpb24gQ2hlY2s=')
${_rpl}=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
${_rpb}=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPLBoot
switch(${_rpl}){2{Write-Host "RunAsPPL: 2. Enabled without UEFI Lock"}1{Write-Host "RunAsPPL: 1. Enabled with UEFI Lock"}0{Write-Host $(_z1 'UnVuQXNQUEw6IDAuIExTQSBQcm90ZWN0aW9uIERpc2FibGVkLiBUcnkgbWltaWthdHou') -ForegroundColor Red}Default{$(_z1 'VGhlIHN5c3RlbSB3YXMgdW5hYmxlIHRvIGZpbmQgdGhlIHNwZWNpZmllZCByZWdpc3RyeSB2YWx1ZTogUnVuQXNQUEwgLyBSdW5Bc1BQTEJvb3Q=')}}
if(${_rpb}){Write-Host "RunAsPPLBoot: ${_rpb}"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ3JlZGVudGlhbCBHdWFyZCBDaGVjaw==')
${_lcf}=(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags
switch(${_lcf}){2{Write-Host "LsaCfgFlags 2. Enabled without UEFI Lock"}1{Write-Host "LsaCfgFlags 1. Enabled with UEFI Lock"}0{Write-Host "LsaCfgFlags 0. LsaCfgFlags Disabled." -ForegroundColor Red}Default{$(_z1 'VGhlIHN5c3RlbSB3YXMgdW5hYmxlIHRvIGZpbmQgdGhlIHNwZWNpZmllZCByZWdpc3RyeSB2YWx1ZTogTHNhQ2ZnRmxhZ3M=')}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2FjaGVkIFdpbkxvZ29uIENyZWRlbnRpYWxzIENoZWNr')
if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"){(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT").CACHEDLOGONSCOUNT
Write-Host $(_z1 'SG93ZXZlciwgb25seSB0aGUgU1lTVEVNIHVzZXIgY2FuIHZpZXcgdGhlIGNyZWRlbnRpYWxzIGhlcmU6IEhLRVlfTE9DQUxfTUFDSElORVxTRUNVUklUWVxDYWNoZQ==')
Write-Host $(_z1 'T3IsIHVzaW5nIG1pbWlrYXR6IGxzYWR1bXA6OmNhY2hl')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQWRkaXRpb25hbCBXaW5sb2dvbiBDcmVkZW50aWFscyBDaGVjaw==')
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUkRDTWFuIFNldHRpbmdzIENoZWNr')
if(Test-Path "$env:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"){Write-Host "$(_z1 'UkRDTWFuIFNldHRpbmdzIEZvdW5kIGF0Og==') $($env:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ForegroundColor Red}
else{Write-Host $(_z1 'Tm8gUkRDTWFuLlNldHRpbmdzIGZvdW5kLg==')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUkRQIFNhdmVkIENvbm5lY3Rpb25zIENoZWNr')
Write-Host "HK_Users"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue|ForEach-Object{${_hks}=$_.Name.Replace('HKEY_USERS\','')
if(Test-Path "registry::HKEY_USERS\${_hks}\Software\Microsoft\Terminal Server Client\Default"){Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_USERS\${_hks}\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"}
else{Write-Host "Not found for $($_.Name)"}}
Write-Host "HKCU"
if(Test-Path "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default"){Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"}
else{Write-Host $(_z1 'VGVybWluYWwgU2VydmVyIENsaWVudCBub3QgZm91bmQgaW4gSENLVQ==')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUHV0dHkgU3RvcmVkIENyZWRlbnRpYWxzIENoZWNr')
if(Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions){Get-ChildItem HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions|ForEach-Object{${_rkn}=Split-Path $_.Name -Leaf;Write-Host "Key: ${_rkn}"
@("HostName","PortNumber","UserName","PublicKeyFile","PortForwardings","ConnectionSharing","ProxyUsername","ProxyPassword")|ForEach-Object{Write-Host "$_ :";Write-Host "$((Get-ItemProperty HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\${_rkn}).$_)"}}}
else{Write-Host $(_z1 'Tm8gcHV0dHkgY3JlZGVudGlhbHMgZm91bmQgaW4gSEtDVTpcU09GVFdBUkVcU2ltb25UYXRoYW1cUHVUVFlcU2Vzc2lvbnM=')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU1NIIEtleSBDaGVja3M=')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgSWYgZm91bmQ6')
Write-Host "https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/" -ForegroundColor Yellow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgUHV0dHkgU1NIIEtOT1dOIEhPU1RT')
if(Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys){Write-Host "$((Get-Item -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)"}
else{Write-Host $(_z1 'Tm8gcHV0dHkgc3NoIGtleXMgZm91bmQ=')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIE9wZW5TU0ggS2V5cw==')
if(Test-Path HKCU:\Software\OpenSSH\Agent\Keys){Write-Host $(_z1 'T3BlblNTSCBrZXlzIGZvdW5kLiBUcnkgdGhpcyBmb3IgZGVjcnlwdGlvbjogaHR0cHM6Ly9naXRodWIuY29tL3JvcG5vcC93aW5kb3dzX3NzaGFnZW50X2V4dHJhY3Q=') -ForegroundColor Yellow}
else{Write-Host $(_z1 'Tm8gT3BlblNTSCBLZXlzIGZvdW5kLg==')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIFdpblZOQyBQYXNzd29yZHM=')
if(Test-Path "HKCU:\Software\ORL\WinVNC3\Password"){Write-Host " WinVNC found at HKCU:\Software\ORL\WinVNC3\Password"}else{Write-Host $(_z1 'Tm8gV2luVk5DIGZvdW5kLg==')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIFNOTVAgUGFzc3dvcmRz')
if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"){Write-Host "SNMP Key found at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"}else{Write-Host $(_z1 'Tm8gU05NUCBmb3VuZC4=')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIFRpZ2h0Vk5DIFBhc3N3b3Jkcw==')
if(Test-Path "HKCU:\Software\TightVNC\Server"){Write-Host "TightVNC key found at HKCU:\Software\TightVNC\Server"}else{Write-Host $(_z1 'Tm8gVGlnaHRWTkMgZm91bmQu')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgVUFDIFNldHRpbmdz')
if((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 1){Write-Host $(_z1 'RW5hYmxlTFVBIGlzIGVxdWFsIHRvIDEuIFBhcnQgb3IgYWxsIG9mIHRoZSBVQUMgY29tcG9uZW50cyBhcmUgb24u')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control.html#very-basic-uac-bypass-full-file-system-access" -ForegroundColor Yellow}
else{Write-Host $(_z1 'RW5hYmxlTFVBIHZhbHVlIG5vdCBlcXVhbCB0byAx')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUmVjZW50bHkgUnVuIENvbW1hbmRzIChXSU4rUik=')
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue|ForEach-Object{${_hks2}=$_.Name.Replace('HKEY_USERS\','')
${_prp}=(Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
${_hks2}|ForEach-Object{if(Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"){Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHxIS1UgUmVjZW50bHkgUnVuIENvbW1hbmRz')
foreach(${_p2} in ${_prp}){Write-Host "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).getValue(${_p2}))"}}}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHxIS0NVIFJlY2VudGx5IFJ1biBDb21tYW5kcw==')
${_prp2}=(Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
foreach(${_p3} in ${_prp2}){Write-Host "$((Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).getValue(${_p3}))"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQWx3YXlzIEluc3RhbGwgRWxldmF0ZWQgQ2hlY2s=')
Write-Host $(_z1 'Q2hlY2tpbmcgV2luZG93cyBJbnN0YWxsZXIgUmVnaXN0cnkgKHdpbGwgcG9wdWxhdGUgaWYgdGhlIGtleSBleGlzdHMp')
if((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1){Write-Host "HKLM AlwaysInstallElevated = 1" -ForegroundColor Red;Write-Host $(_z1 'VHJ5IG1zZnZlbm9tIG1zaSBwYWNrYWdlIHRvIGVzY2FsYXRl') -ForegroundColor Red
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#metasploit-payloads" -ForegroundColor Yellow}
if((Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1){Write-Host "HKCU AlwaysInstallElevated = 1" -ForegroundColor Red;Write-Host $(_z1 'VHJ5IG1zZnZlbm9tIG1zaSBwYWNrYWdlIHRvIGVzY2FsYXRl') -ForegroundColor Red
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#metasploit-payloads" -ForegroundColor Yellow}
${_jI1}=[System.Text.StringBuilder]::new();[void]${_jI1}.Append('r3d');${_jI2}=${_jI1}.ToString().Length
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUG93ZXJTaGVsbCBJbmZv')
(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine).PowerShellVersion|ForEach-Object{Write-Host "PowerShell $_ available"}
(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine).PowerShellVersion|ForEach-Object{Write-Host "PowerShell $_ available"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUG93ZXJTaGVsbCBSZWdpc3RyeSBUcmFuc2NyaXB0IENoZWNr')
@("HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription","HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription")|ForEach-Object{if(Test-Path $_){Get-Item $_}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUG93ZXJTaGVsbCBNb2R1bGUgTG9nIENoZWNr')
@("HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging","HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging","HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging","HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging")|ForEach-Object{if(Test-Path $_){Get-Item $_}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUG93ZXJTaGVsbCBTY3JpcHQgQmxvY2sgTG9nIENoZWNr')
@("HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")|ForEach-Object{if(Test-Path $_){Get-Item $_}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgV1NVUyBjaGVjaw==')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus" -ForegroundColor Yellow
if(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate){Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate}
if((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer" -ErrorAction SilentlyContinue).UseWUServer){(Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer").UseWUServer}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgSW50ZXJuZXQgU2V0dGluZ3MgSEtDVSAvIEhLTE0=')
${_prp3}=(Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach(${_p4} in ${_prp3}){Write-Host "${_p4} - $((Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).getValue(${_p4}))"}
${_prp4}=(Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach(${_p5} in ${_prp4}){Write-Host "${_p5} - $((Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).getValue(${_p5}))"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUlVOTklORyBQUk9DRVNTRVM=')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgdXNlciBwZXJtaXNzaW9ucyBvbiBydW5uaW5nIHByb2Nlc3Nlcw==')
Get-Process|Select-Object Path -Unique|ForEach-Object{_b3w -_tg $_.path}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU3lzdGVtIHByb2Nlc3Nlcw==')
Start-Process tasklist -ArgumentList '/v /fi "username eq system"' -Wait -NoNewWindow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU0VSVklDRSBwYXRoIHZ1bG5lcmFibGUgY2hlY2s=')
Write-Host $(_z1 'Q2hlY2tpbmcgZm9yIHZ1bG5lcmFibGUgc2VydmljZSAuZXhl')
${_us}=@{};Get-WmiObject Win32_Service|Where-Object{$_.PathName -like '*.exe*'}|ForEach-Object{${_ph}=($_.PathName -split '(?<=\.exe\b)')[0].Trim('"');${_us}[${_ph}]=$_.Name}
foreach(${_h} in(${_us}|Select-Object -Unique).GetEnumerator()){_b3w -_tg ${_h}.Name -_sn ${_h}.Value}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIFVucXVvdGVkIFNlcnZpY2UgUGF0aHM=')
_c5q
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgU2VydmljZSBSZWdpc3RyeSBQZXJtaXNzaW9ucw==')
Write-Host $(_z1 'VGhpcyB3aWxsIHRha2Ugc29tZSB0aW1lLg==')
Get-ChildItem 'HKLM:\System\CurrentControlSet\services\'|ForEach-Object{${_tg2}=$_.Name.Replace("HKEY_LOCAL_MACHINE","hklm:");_b3w -_tg ${_tg2}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU0NIRURVTEVEIFRBU0tTIHZ1bG5lcmFibGUgY2hlY2s=')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgVGVzdGluZyBhY2Nlc3MgdG8gYzpcd2luZG93c1xzeXN0ZW0zMlx0YXNrcw==')
if(Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue){Write-Host $(_z1 'QWNjZXNzIGNvbmZpcm1lZCwgbWF5IG5lZWQgZnVydGhlciBpbnZlc3RpZ2F0aW9u');Get-ChildItem "c:\windows\system32\tasks"}
else{Write-Host $(_z1 'Tm8gYWRtaW4gYWNjZXNzIHRvIHNjaGVkdWxlZCB0YXNrcyBmb2xkZXIu')
Get-ScheduledTask|Where-Object{$_.TaskPath -notlike "\Microsoft*"}|ForEach-Object{${_act}=$_.Actions.Execute
if(${_act} -ne $null){foreach(${_a2} in ${_act}){if(${_a2} -like "%windir%*"){${_a2}=${_a2}.replace("%windir%",$Env:windir)}
elseif(${_a2} -like "%SystemRoot%*"){${_a2}=${_a2}.replace("%SystemRoot%",$Env:windir)}
elseif(${_a2} -like "%localappdata%*"){${_a2}=${_a2}.replace("%localappdata%","$env:UserProfile\appdata\local")}
elseif(${_a2} -like "%appdata%*"){${_a2}=${_a2}.replace("%localappdata%",$env:Appdata)}
${_a2}=${_a2}.Replace('"','');_b3w -_tg ${_a2};Write-Host "`n";Write-Host "TaskName: $($_.TaskName)";Write-Host "-------------"
New-Object -TypeName PSObject -Property([Ordered]@{LastResult=$(($ _|Get-ScheduledTaskInfo).LastTaskResult);NextRun=$(($_|Get-ScheduledTaskInfo).NextRunTime);Status=$_.State;Command=$_.Actions.execute;Arguments=$_.Actions.Arguments})|Write-Host}}}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU1RBUlRVUCBBUFBMSUNBVElPTlMgVnVsbmVyYWJsZSBDaGVjaw==')
$(_z1 'Q2hlY2sgaWYgeW91IGNhbiBtb2RpZnkgYW55IGJpbmFyeQ==')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#run-at-startup" -ForegroundColor Yellow
@("C:\Documents and Settings\All Users\Start Menu\Programs\Startup","C:\Documents and Settings\$env:Username\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup")|ForEach-Object{if(Test-Path $_){_b3w $_;Get-ChildItem -Recurse -Force -Path $_|ForEach-Object{${_si2}=$_.FullName;if(Test-Path ${_si2}){_b3w -_tg ${_si2}}}}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU1RBUlRVUCBBUFBTIFJlZ2lzdHJ5IENoZWNr')
@("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run","registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce","registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run","registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce")|ForEach-Object{${_rop}=$_;(Get-Item $_)|ForEach-Object{$_.property|ForEach-Object{_b3w((Get-ItemProperty -Path ${_rop}).$_ -split '(?<=\.exe\b)')[0].Trim('"')}}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgSU5TVEFMTEVEIEFQUExJQ0FUSU9OUw==')
Write-Host $(_z1 'R2VuZXJhdGluZyBsaXN0IG9mIGluc3RhbGxlZCBhcHBsaWNhdGlvbnM=')
_o6f
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTE9PS0lORyBGT1IgQkFTSC5FWEU=')
Get-ChildItem C:\Windows\WinSxS\ -Filter "amd64_microsoft-windows-lxss-bash*"|ForEach-Object{Write-Host $((Get-ChildItem $_.FullName -Recurse -Filter "*bash.exe*").FullName)}
@("bash.exe","wsl.exe")|ForEach-Object{Write-Host $((Get-ChildItem C:\Windows\System32\ -Filter $_).FullName)}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTE9PS0lORyBGT1IgU0NDTSBDTElFTlQ=')
${_res}=Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * -ErrorAction SilentlyContinue|Select-Object Name,SoftwareVersion
if(${_res}){${_res}}elseif(Test-Path 'C:\Windows\CCM\SCClient.exe'){Write-Host $(_z1 'U0NDTSBDbGllbnQgZm91bmQgYXQgQzpcV2luZG93c1xDQ01cU0NDbGllbnQuZXhl') -ForegroundColor Cyan}else{Write-Host $(_z1 'Tm90IEluc3RhbGxlZC4=')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTkVUV09SSyBJTkZPUk1BVElPTg==')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgSE9TVFMgRklMRQ==')
Write-Host $(_z1 'R2V0IGNvbnRlbnQgb2YgZXRjXGhvc3RzIGZpbGU=')
Get-Content "c:\windows\system32\drivers\etc\hosts"
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgSVAgSU5GT1JNQVRJT04=')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgSXBjb25maWcgQUxM')
Start-Process ipconfig.exe -ArgumentList "/all" -Wait -NoNewWindow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgRE5TIENhY2hl')
ipconfig /displaydns|Select-String "Record"|ForEach-Object{Write-Host $('{0}' -f $_)}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTElTVEVOSU5HIFBPUlRT')
Start-Process NETSTAT.EXE -ArgumentList "-ano" -Wait -NoNewWindow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQUNUSVZFIERJUkVDVE9SWSAvIElERU5USVRZIE1JU0NPTkZJRyBDSEVDS1M=')
${_dctx}=_f4n
if(-not ${_dctx}){Write-Host $(_z1 'SG9zdCBhcHBlYXJzIHRvIGJlIGluIGEgd29ya2dyb3VwIG9yIHRoZSBBRCBjb250ZXh0IGNvdWxkIG5vdCBiZSByZXNvbHZlZC4gU2tpcHBpbmcgZG9tYWluLXNwZWNpZmljIGNoZWNrcy4=') -ForegroundColor DarkGray}
else{${_nst}=_k7x
if(${_nst}){${_rv}=if(${_nst}.RestrictReceiving -ne $null){[int]${_nst}.RestrictReceiving}else{-1}
${_sv2}=if(${_nst}.RestrictSending -ne $null){[int]${_nst}.RestrictSending}else{-1}
${_lv}=if(${_nst}.LmCompatibility -ne $null){[int]${_nst}.LmCompatibility}else{-1}
${_nm3}="Receiving:{0} Sending:{1} LMCompat:{2}" -f ${_rv},${_sv2},${_lv}
if(${_rv} -ge 1 -or ${_sv2} -ge 1 -or ${_lv} -ge 5){Write-Host "[!] NTLM is restricted/disabled (${_nm3})." -ForegroundColor Yellow}
else{Write-Host "[i] NTLM restrictions appear relaxed (${_nm3})."}}
${_tsk}=_l9z -_dc ${_dctx}
if(${_tsk}){${_oa}=[math]::Abs(${_tsk}.OffsetSeconds);${_tm}="Offset vs {0}: {1:N3}s (sample: {2})" -f ${_tsk}.Source,${_tsk}.OffsetSeconds,${_tsk}.RawSample.Trim()
if(${_oa} -gt 5){Write-Host "[!] Significant Kerberos time skew detected - ${_tm}" -ForegroundColor Yellow}else{Write-Host "[i] Kerberos time offset looks OK - ${_tm}"}}
${_dnf}=@(_h1r -_dc ${_dctx})
if(${_dnf}.Count -gt 0){Write-Host $(_z1 'WyFdIEFELWludGVncmF0ZWQgRE5TIHpvbmVzIGFsbG93IGxvdy1wcml2IHByaW5jaXBhbHMgdG8gd3JpdGUgcmVjb3Jkcw==') -ForegroundColor Yellow;${_dnf}|Format-Table Zone,Partition,Principal,Rights -AutoSize|Out-String|Write-Host}
else{Write-Host "[i] No obvious insecure dynamic DNS ACLs found."}
${_spf}=@(_j5v -_dc ${_dctx})
if(${_spf}.Count -gt 0){Write-Host $(_z1 'WyFdIEhpZ2gtdmFsdWUgU1BOIGFjY291bnRzIGlkZW50aWZpZWQgKHByaW1lIEtlcmJlcm9hc3QgdGFyZ2V0cyk6') -ForegroundColor Yellow;${_spf}|Format-Table User,Groups -AutoSize|Out-String|Write-Host}
else{Write-Host "[i] No privileged SPN users detected."}
${_gmr}=@(_i3u -_dc ${_dctx})
if(${_gmr}.Count -gt 0){${_wgm}=${_gmr}|Where-Object{$_.WeakPrincipals -ne ""}
if(${_wgm}){Write-Host $(_z1 'WyFdIGdNU0EgcGFzc3dvcmRzIHJlYWRhYmxlIGJ5IGxvdy1wcml2IGdyb3Vwcy9wcmluY2lwYWxzOg==') -ForegroundColor Yellow;${_wgm}|Select-Object Account,WeakPrincipals|Format-Table -AutoSize|Out-String|Write-Host}
else{Write-Host "[i] gMSA accounts discovered.";${_gmr}|Select-Object Account,Allowed|Sort-Object Account|Select-Object -First 5|Format-Table -Wrap|Out-String|Write-Host}}
else{Write-Host "[i] No gMSA objects found via LDAP."}
${_aci}=_m2b
if(${_aci}.MappingValue -ne $null){${_hx}=('0x{0:X}' -f [int]${_aci}.MappingValue)
if(${_aci}.UpnMapping){Write-Host("[!] Schannel CertificateMappingMethods={0} (UPN mapping allowed)" -f ${_hx}) -ForegroundColor Yellow}
else{Write-Host("[i] Schannel CertificateMappingMethods={0} (UPN mapping flag not set)." -f ${_hx})}
if(${_aci}.ServiceState){Write-Host("[i] AD CS service state: {0}" -f ${_aci}.ServiceState)}}
else{Write-Host "[i] Could not read Schannel certificate mapping configuration." -ForegroundColor DarkGray}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQVJQIFRhYmxl')
Start-Process arp -ArgumentList "-A" -Wait -NoNewWindow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUm91dGVz')
Start-Process route -ArgumentList "print" -Wait -NoNewWindow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgTmV0d29yayBBZGFwdGVyIGluZm8=')
Get-NetAdapter|ForEach-Object{Write-Host "----------";Write-Host $_.Name;Write-Host $_.InterfaceDescription;Write-Host $_.ifIndex;Write-Host $_.Status;Write-Host $_.MacAddress;Write-Host "----------"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIFdpRmkgcGFzc3dvcmRz')
((netsh.exe wlan show profiles) -match '\s{2,}:\s').replace("    All User Profile     : ","")|ForEach-Object{netsh wlan show profile name="$_" key=clear}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgRW5hYmxlZCBmaXJld2FsbCBydWxlcw==')
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgc2hvdyBhbGwgcnVsZXMgd2l0aDogbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgc2hvdyBydWxlIGRpcj1pbiBuYW1lPWFsbA==')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU01CIFNIQVJFU1M=')
Write-Host $(_z1 'V2lsbCBlbnVtZXJhdGUgU01CIFNoYXJlcyBhbmQgQWNjZXNzIGlmIGFueSBhcmUgYXZhaWxhYmxl')
Get-SmbShare|Get-SmbShareAccess|ForEach-Object{${_smo}=$_
whoami.exe /groups /fo csv|Select-Object -Skip 2|ConvertFrom-Csv -Header 'group name'|Select-Object -ExpandProperty 'group name'|ForEach-Object{if(${_smo}.AccountName -like $_ -and(${_smo}.AccessRight -like "Full" -or "Change") -and ${_smo}.AccessControlType -like "Allow"){Write-Host -ForegroundColor Red "$(${_smo}.AccountName) has $(${_smo}.AccessRight) to $(${_smo}.Name)"}}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgVVNFUiBJTkZP')
Write-Host $(_z1 'R2VuZXJhdGluZyBMaXN0IG9mIGFsbCBMb2NhbCBBZG1pbmlzdHJhdG9ycywgVXNlcnMgYW5kIEJhY2t1cCBPcGVyYXRvcnM=')
Get-LocalGroup|ForEach-Object{"`n Group: $($_.Name) `n";if(Get-LocalGroupMember -name $_.Name){(Get-LocalGroupMember -name $_.Name).Name}else{"     {GROUP EMPTY}"}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgVVNFUiBESVJFQ1RPUlkgQUNDRVNTIENIRUNL')
Get-ChildItem C:\Users\*|ForEach-Object{if(Get-ChildItem $_.FullName -ErrorAction SilentlyContinue){Write-Host -ForegroundColor Red "Read Access to $($_.FullName)"}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgV0hPQU1JIElORk8=')
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2sgVG9rZW4gYWNjZXNz')
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2sgaWYgeW91IGFyZSBpbnNpZGUgdGhlIEFkbWluaXN0cmF0b3JzIGdyb3Vw')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups" -ForegroundColor Yellow
Start-Process whoami.exe -ArgumentList "/all" -Wait -NoNewWindow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2xvdWQgQ3JlZGVudGlhbHMgQ2hlY2s=')
${_usr}=(Get-ChildItem C:\Users).Name
${_ccr}=@(".aws\credentials","AppData\Roaming\gcloud\credentials.db","AppData\Roaming\gcloud\legacy_credentials","AppData\Roaming\gcloud\access_tokens.db",".azure\accessTokens.json",".azure\azureProfile.json")
foreach(${_u} in ${_usr}){${_ccr}|ForEach-Object{if(Test-Path "c:\Users\${_u}\$_"){Write-Host "$_ found!" -ForegroundColor Red}}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQVBQY21kIENoZWNr')
if(Test-Path("$Env:SystemRoot\System32\inetsrv\appcmd.exe")){Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#appcmdexe" -ForegroundColor Yellow;Write-Host "$Env:SystemRoot\System32\inetsrv\appcmd.exe exists!" -ForegroundColor Red}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgT3BlblZQTiBDcmVkZW50aWFscyBDaGVjaw==')
${_ovk}=Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs" -ErrorAction SilentlyContinue
if(${_ovk}){Add-Type -AssemblyName System.Security;${_itm}=${_ovk}|ForEach-Object{Get-ItemProperty $_.PsPath}
foreach(${_it} in ${_itm}){${_eb}=${_it}.'auth-data';${_en}=${_it}.'entropy';${_en}=${_en}[0..((${_en}.Length)-2)]
${_db}=[System.Security.Cryptography.ProtectedData]::Unprotect(${_eb},${_en},[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
Write-Host([System.Text.Encoding]::Unicode.GetString(${_db}))}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUG93ZXJTaGVsbCBIaXN0b3J5IChQYXNzd29yZCBTZWFyY2ggT25seSk=')
Write-Host $(_z1 'PXx8IFBvd2VyU2hlbGwgQ29uc29sZSBIaXN0b3J5')
Write-Host $(_z1 'PXx8IFRvIHNlZSBhbGwgaGlzdG9yeSwgcnVuIHRoaXMgY29tbWFuZDogR2V0LUNvbnRlbnQgKEdldC1QU1JlYWRsaW5lT3B0aW9uKS5IaXN0b3J5U2F2ZVBhdGg=')
Write-Host $(Get-Content(Get-PSReadLineOption).HistorySavePath|Select-String pa)
Write-Host $(_z1 'PXx8IEFwcERhdGEgUFNSZWFkbGluZSBDb25zb2xlIEhpc3Rvcnk=')
Write-Host $(_z1 'PXx8IFRvIHNlZSBhbGwgaGlzdG9yeSwgcnVuIHRoaXMgY29tbWFuZA==')
Write-Host $(Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"|Select-String pa)
Write-Host $(_z1 'PXx8IFBvd2VyU2hlbGwgZGVmYXVsdCB0cmFuc2NyaXB0IGhpc3RvcnkgY2hlY2s=')
if(Test-Path $env:SystemDrive\transcripts\){"Default transcripts found at $($env:SystemDrive)\transcripts\"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgRU5WSVJPTk1FTlQgVkFSSUFCTEVT')
Write-Host $(_z1 'TWF5YmUgeW91IGNhbiB0YWtlIGFkdmFudGFnZSBvZiBtb2RpZnlpbmcvY3JlYXRpbmcgYSBiaW5hcnk=')
Write-Host $(_z1 'UEFUSCB2YXJpYWJsZSBlbnRyaWVzIHBlcm1pc3Npb25z')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking" -ForegroundColor Yellow
Get-ChildItem env:|Format-Table -Wrap
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU3RpY2t5IE5vdGVzIENoZWNr')
if(Test-Path "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite"){Write-Host $(_z1 'U3RpY2t5IE5vdGVzIGRhdGFiYXNlIGZvdW5kLiBDb3VsZCBoYXZlIGNyZWRlbnRpYWxzIGluIHBsYWluIHRleHQ6')
Write-Host "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2FjaGVkIENyZWRlbnRpYWxzIENoZWNr')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#windows-vault" -ForegroundColor Yellow
cmdkey.exe /list
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIERQQVBJIFJQQyBNYXN0ZXIgS2V5cw==')
Write-Host $(_z1 'VXNlIHRoZSBNaW1pa2F0eiAnZHBhcGk6Om1hc3RlcmtleScgbW9kdWxl')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi" -ForegroundColor Yellow
${_ar}="C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\";${_al}="C:\Users\$env:USERNAME\AppData\Local\Microsoft\"
if(Test-Path "${_ar}\Protect\"){Write-Host "found: ${_ar}\Protect\";Get-ChildItem -Path "${_ar}\Protect\" -Force|ForEach-Object{Write-Host $_.FullName}}
if(Test-Path "${_al}\Protect\"){Write-Host "found: ${_al}\Protect\";Get-ChildItem -Path "${_al}\Protect\" -Force|ForEach-Object{Write-Host $_.FullName}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ2hlY2tpbmcgZm9yIERQQVBJIENyZWQgTWFzdGVyIEtleXM=')
Write-Host $(_z1 'VXNlIHRoZSBNaW1pa2F0eiAnZHBhcGk6OmNyZWQnIG1vZHVsZQ==')
Write-Host $(_z1 'WW91IGNhbiBhbHNvIGV4dHJhY3QgbWFueSBEUEFQSSBtYXN0ZXJrZXlzIGZyb20gbWVtb3J5')
Write-Host "https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi" -ForegroundColor Yellow
if(Test-Path "${_ar}\Credentials\"){Get-ChildItem -Path "${_ar}\Credentials\" -Force}
if(Test-Path "${_al}\Credentials\"){Get-ChildItem -Path "${_al}\Credentials\" -Force}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgQ3VycmVudCBMb2dnZWQgb24gVXNlcnM=')
try{quser}catch{Write-Host "'quser' command not present on system"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUmVtb3RlIFNlc3Npb25z')
try{qwinsta}catch{Write-Host "'qwinsta' command not present on system"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgS2VyYmVyb3MgdGlja2V0cw==')
try{klist}catch{Write-Host $(_z1 'Tm8gYWN0aXZlIHNlc3Npb25z')}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUHJpbnRpbmcgQ2xpcEJvYXJk')
_e2y
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgVW5hdHRlbmRlZCBGaWxlcyBDaGVjaw==')
@("C:\Windows\sysprep\sysprep.xml","C:\Windows\sysprep\sysprep.inf","C:\Windows\sysprep.inf","C:\Windows\Panther\Unattended.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\Panther\Unattend\Unattended.xml","C:\Windows\System32\Sysprep\unattend.xml","C:\Windows\System32\Sysprep\unattended.xml","C:\unattend.txt","C:\unattend.inf")|ForEach-Object{if(Test-Path $_){Write-Host "$_ found."}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgU0FNIC8gU1lTVEVNIEJhY2t1cCBDaGVja3M=')
@("$Env:windir\repair\SAM","$Env:windir\System32\config\RegBack\SAM","$Env:windir\System32\config\SAM","$Env:windir\repair\system","$Env:windir\System32\config\SYSTEM","$Env:windir\System32\config\RegBack\system")|ForEach-Object{if(Test-Path $_ -ErrorAction SilentlyContinue){Write-Host "$_ Found!" -ForegroundColor Red}}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgR3JvdXAgUG9saWN5IFBhc3N3b3JkIENoZWNr')
${_gp}=@("Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml")
if(Test-Path "$env:SystemDrive\Microsoft\Group Policy\history"){Get-ChildItem -Recurse -Force "$env:SystemDrive\Microsoft\Group Policy\history" -Include @gp}
if(Test-Path "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"){Get-ChildItem -Recurse -Force "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"}
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUmVjeWNsZSBCaW4gVElQOg==')
Write-Host "http://www.nirsoft.net/password_recovery_tools.html" -ForegroundColor Yellow
Write-Host "";if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUGFzc3dvcmQgQ2hlY2sgaW4gRmlsZXMvRm9sZGVycw==')
if(${_x9a}){_d8e}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUGFzc3dvcmQgQ2hlY2suIFN0YXJ0aW5nIGF0IHJvb3Qgb2YgZWFjaCBkcml2ZS4=')
Write-Host -ForegroundColor Blue "=========|| Looking through each drive, searching for ${_fe4}"
try{New-Object -ComObject Excel.Application|Out-Null;${_re}=$true}catch{${_re}=$false;if(${_v8z}){Write-Host -ForegroundColor Yellow $(_z1 'SG9zdCBkb2VzIG5vdCBoYXZlIEV4Y2VsIENPTSBvYmplY3Q=')}}
${_dv6}.Root|ForEach-Object{${_dr2}=$_
Get-ChildItem ${_dr2} -Recurse -Include ${_fe4} -ErrorAction SilentlyContinue -Force|ForEach-Object{${_pa}=$_
if(${_pa}.FullName|Select-String "(?i).*lang.*"){}
if(${_pa}.FullName|Select-String "(?i).:\\.*\\.*Pass.*"){Write-Host -ForegroundColor Blue "$(${_pa}.FullName) contains the word 'pass'"}
if(${_pa}.FullName|Select-String ".:\\.*\\.*user.*"){Write-Host -ForegroundColor Blue "$(${_pa}.FullName) contains the word 'user'"}
elseif(${_pa}.FullName|Select-String ".*\.xls",".*\.xlsm",".*\.xlsx"){if(${_re} -and ${_v8z}){_n4d -_src ${_pa}.FullName -_stx "user";_n4d -_src ${_pa}.FullName -_stx "pass"}}
else{if(${_pa}.Length -gt 0){}
if(${_pa}.FullName|Select-String "(?i).*SiteList\.xml"){Write-Host "Possible MCaffee Site List Found: $($_.FullName)";Write-Host "https://github.com/funoverip/mcafee-sitelist-pwd-decryption" -ForegroundColor Yellow}
${_rx2}.keys|ForEach-Object{${_pf}=Get-Content ${_pa}.FullName -ErrorAction SilentlyContinue -Force|Select-String ${_rx2}[$_] -Context 1,1
if(${_pf}){Write-Host "Possible Password found: $_" -ForegroundColor Yellow;Write-Host ${_pa}.FullName;Write-Host -ForegroundColor Blue "$_ triggered";Write-Host ${_pf} -ForegroundColor Red}}}}}
Write-Host -ForegroundColor Blue $(_z1 'PT09PT09PT09fHwgUmVnaXN0cnkgUGFzc3dvcmQgQ2hlY2s=')
Write-Host $(_z1 'VGhpcyB3aWxsIHRha2Ugc29tZSB0aW1lLg==')
${_rgp}=@("registry::\HKEY_CURRENT_USER\","registry::\HKEY_LOCAL_MACHINE\")
foreach(${_r2} in ${_rgp}){(Get-ChildItem -Path ${_r2} -Recurse -Force -ErrorAction SilentlyContinue)|ForEach-Object{${_prp5}=$_.property;${_nm4}=$_.Name
${_prp5}|ForEach-Object{${_pr2}=$_
${_rx2}.keys|ForEach-Object{${_val}=${_rx2}[$_]
if(${_pr2}|Where-Object{$_ -like ${_val}}){Write-Host "Possible Password Found: ${_nm4}\${_pr2}";Write-Host "Key: $_" -ForegroundColor Red}
${_pr2}|ForEach-Object{${_pv}=(Get-ItemProperty "registry::${_nm4}").$_
if(${_pv}|Where-Object{$_ -like ${_val}}){Write-Host "Possible Password Found: ${_nm4}\$_ ${_pv}"}}}}}
if(${_x9a}){_d8e};Write-Host "Finished ${_r2}"}
