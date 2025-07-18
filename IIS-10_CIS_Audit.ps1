#
# IIS 10 CIS Becnchmark v1.2.1 - ETUDE PERSO version 1.0
# Clement MAILLIOUX - 13/11/2024
#
﻿$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$currentpath = Get-location
$myFolder = New-Item "$($currentpath)\IIS_Audit\" -itemtype Directory -force
$mySite = Read-Host "Please enter website Name"


Import-Module Webadministration 

#region 1 Basic Configurations

"1.1 Ensure web content is on non-system partition (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt
Get-Website | Format-List Name, PhysicalPath | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"1.2 Ensure 'host headers' are on all sites (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebBinding -Port * | Format-List bindingInformation | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"1.3 Ensure 'directory browsing' is set to disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath
iis:\ -Name Enabled | select Value | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"1.4 Ensure 'application pool identity' is configured for all application pools (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ChildItem -Path IIS:\AppPools\ | Select-Object name, state, <#@{e={$_.processModel.password};l="password"}, #> @{e={$_.processModel.identityType};l="identityType"} | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"1.5 Ensure 'unique application pools' is set for sites (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-Website | Select-Object Name, applicationPool | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"1.6 Ensure 'application pool identity' is configured for anonymous user identity (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -Recurse | where {$_.enabled -eq $true} | format-list location | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"1.7 Ensure' WebDav' feature is disabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"Please check %SystemRoot%\System32\inetsrv\config file" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#2 Configure Authentication and Authorization
"2.1 Ensure 'global authorization rule' is set to restrict access (Not Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfiguration -pspath 'IIS:\'  -filter "system.webServer/security/authorization" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"2.2 Ensure access to sensitive site features is restricted to authenticated principals only (Not Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfiguration system.webServer/security/authentication/* -Recurse | Where-Object {$_.enabled -eq $true} | Format-Table | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"2.3 Ensure 'forms authentication' require SSL (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-
Table Name, Value | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"2.4 Ensure 'forms authentication' is set to use cookies (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web
Site' -filter 'system.web/authentication/forms' -Recurse -name 'cookieless' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append



#
"2.5 Ensure 'cookie protection mode' is configured for forms authentication (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$mySite" -filter 'system.web/authentication/forms' -name 'protection' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"2.6 Ensure transport layer security for 'basic authentication' is configured (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$mySite" -filter 'system.webServer/security/access' -name 'sslFlags' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
Write-host "2.7 Ensure 'passwordFormat' is not set to clear (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$mySite" -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
# L2	2.8 Ensure 'credentials' are not stored in configuration files (Scored)
#   Audit, TODO

#   Remediation,TODO 


#region 3 ASP.NET Configuration Recommendations
"3.1 Ensure 'deployment method retail' is set (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"Please check %SystemRoot%\System32\inetsrv\config file" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
#
#	3.2 Ensure 'debug' is turned off (Scored)
#TODO
#
#	3.3 Ensure custom error messages are not off (Scored)
#TODO

#
"3.4 Ensure IIS HTTP detailed errors are hidden from displaying remotely (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$mySite" -filter "system.webServer/httpErrors" -name "errorMode" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#	3.5 Ensure ASP.NET stack tracing is not enabled (Scored)
#TODO

#
"3.6 Ensure 'httpcookie' mode is configured for session state (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$mySite" -filter "system.web/sessionState" -name "mode" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"3.7 Ensure 'cookies' are set with HttpOnly attribute (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Write-host "Please check the Web.config file of the application" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#   Remediation,TODO 

#
#	3.8 Ensure 'MachineKey validation method - .Net 3.5' is configured (Scored)
#TODO

#
"3.9 Ensure 'MachineKey validation method - .Net 4.5' is configured (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/machineKey" -name "validation"  | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"3.10 Ensure global .NET trust level is configured (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/trust" -name "level" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
#	3.11 Ensure 'encryption providers' are locked down (Scored)
#TODO 

"3.12 Ensure Server Header is removed (Manual)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath machine/webroot/apphost -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#region 4 Request Filtering and Other Restriction Modules
#	4.1 Ensure 'maxAllowedContentLength' is configured (Not Scored)
#TODO 

#
#	4.2 Ensure 'maxURL request filter' is configured (Scored)
#TODO 

#
#	4.3 Ensure 'MaxQueryString request filter' is configured (Scored)
#TODO 

#
#	4.4 Ensure non-ASCII characters in URLs are not allowed (Scored)
#TODO

#
"4.5 Ensure Double-Encoded requests will be rejected (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append


#
"4.6 Ensure 'HTTP Trace Method' is disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/verbs" -name "." -value @{verb='TRACE';allowed='False'} | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"4.7 Ensure Unlisted File Extensions are not allowed (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"4.8 Ensure Handler is not granted Write and Script/Execute (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "accessPolicy" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"4.9 Ensure 'notListedIsapisAllowed' is set to false (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"4.10 Ensure 'notListedCgisAllowed' is set to false (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"4.11 Ensure 'Dynamic IP Address Restrictions' is enabled (Not Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append


#region 5 IIS Logging Recommendations
"5.1 Ensure Default IIS web log location is moved (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "directory" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
#	5.2 Ensure Advanced IIS logging is enabled (Scored)
# Check logs.

#
#	5.3 Ensure 'ETW Logging' is enabled (Not Scored)
# Check logs.


#region 6 FTP Requests
"6.1 Ensure FTP requests are encrypted (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "controlChannelPolicy" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "dataChannelPolicy" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"6.2 Ensure FTP Logon attempt restrictions is enabled (Not Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.ftpServer/security/authentication/denyByFailure" -name "enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append


#region 7 Transport Encryption
#	7.1 Ensure HSTS Header is set (Not Scored)
#TODO 

#
"7.2 Ensure SSLv2 is disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\DisabledbyDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client\DisabledbyDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"7.3 Ensure SSLv3 is disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\DisabledByDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\DisabledByDefault' -name 'DisabledByDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"7.4 Ensure TLS 1.0 is disabled (Not Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\DisabledByDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\DisabledByDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"7.5 Ensure TLS 1.1 is enabled (Not Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\DisabledByDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\DisabledByDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
#
"7.6 Ensure TLS 1.2 is enabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\enaled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledbyDefault" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"7.7 Ensure NULL Cipher Suites is disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"7.8 Ensure DES Cipher Suites is disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
#
"7.9 Ensure RC4 Cipher Suites is disabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128\enbled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

#
"7.10 Ensure AES 128/128 Cipher Suite is Disabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 0" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append

"7.11 Ensure AES 256/256 Cipher Suite is enabled (Scored)" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256\enabled" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -name 'Enabled' | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
"-- Expected Value : 1" | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
" " | Out-File -FilePath $myFolder\IIS_Audit.txt -Append
#
#	7.14 Ensure TLS Cipher Suite ordering is configured (Scored)
#TODO
