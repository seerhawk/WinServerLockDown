# Security script by Yaron Vanhulst
# 
# Based on the CIS Windows 2012 R2 Security benchmark.
# This is meant for a clean windows 2012 install.
#
# A good way to customize this script is by looking up the Registry setting names in the CIS Benchmark
# 

function Set-PasswordSettings
{
    [CmdletBinding()]
    param
    (
        [int]$HistorySize,
        [int]$MinimumAge,
        [int]$MaximumAge,
        [int]$MinimumLength,
        [bool]$Complex,
        [int]$LockoutCount,
        [int]$LockoutDuration,
        [int]$LockoutResetCount,
        [switch]$Recommended
    )

    process
    {
        if (Test-RunAsLevel -Admin)
        {
            secedit /export /cfg "$PSScriptRoot\secpol.cfg" | Out-Null
            $SecPol = Get-Content -Path "$PSScriptRoot\secpol.cfg"

            if ($RecommendedSettings)
            {
                if (!$HistorySize) {$HistorySize = 24}
                if (!$MinimumAge) {$MinimumAge = 1}
                if (!$MaximumAge) {$MaximumAge = 60}
                if (!$MinimumLength) {$MinimumLength=14}
                if (!$Complex) {$Complex = $true}
                if (!$LockOutCount) {$LockoutCount=10}
                if (!$LockoutDuration) {$LockoutDuration=15}
                if (!$LockoutResetCount) {$LockoutResetCount=15}
            }

            $CurrentSettings = Get-IniFileContent -Path "$PSScriptRoot\secpol.cfg"

            if ($HistorySize)
            {
                $CurrentHistorySize = ($CurrentSettings | Where-Object {$_.SettingName -eq "PasswordHistorySize"}).Value
                $SecPol = $SecPol.replace("PasswordHistorySize = $CurrentHistorySize", "PasswordHistorySize = $HistorySize")
            }

            if ($MinimumAge)
            {
                $CurrentMinimumAge = ($CurrentSettings | Where-Object {$_.SettingName -eq "MinimumPasswordAge"}).Value
                $SecPol = $SecPol.replace("MinimumPasswordAge = $CurrentMinimumAge","MinimumPasswordAge = $MinimumAge")
            }

            if ($MaximumAge)
            {
                $CurrentMaximumAge = ($CurrentSettings | Where-Object {$_.SettingName -eq "MaximumPasswordAge"}).Value
                $SecPol = $SecPol.replace("MaximumPasswordAge = $CurrentMaximumAge", "MaximumPasswordAge = $MaximumAge")
            }

            if ($MinimumLength)
            {
                $CurrentMinimumLength = ($CurrentSettings | Where-Object {$_.SettingName -eq "MinimumPasswordLength"}).Value
                $SecPol = $SecPol.replace("MinimumPasswordLength = $CurrentMinimumLength","MinimumPasswordLength = $MinimumLength")
            }
            
            $CurrentComplex = ($CurrentSettings | Where-Object {$_.SettingName -eq "PasswordComplexity"}).Value
            if ($Complex)
            {
                $SecPol = $SecPol.replace("PasswordComplexity = $CurrentComplex","PasswordComplexity = 1")
            } else {
                $SecPol = $SecPol.replace("PasswordComplexity = $CurrentComplex","PasswordComplexity = 0")
            }
            
            # LockoutRules
            $CurrentLouckoutCount = ($CurrentSettings | Where-Object {$_.SettingName -eq "PasswordComplexity"}).Value

            if ($LockoutCount)
            {
                $Lockout = "LockoutBadCount = $LockoutCount"
            } else {
                $Lockout = "LockoutBadCount = $CurrentLouckoutCount"
            }
            
            if ($LockoutDuration)
            {
                if (!($CurrentSettings | Where-Object {$_.SettingName -eq "LockoutDuration"}).Value)
                {
                    $Lockout += "`nLockoutDuration = $LockoutDuration"
                } else {
                    $CurrentLockoutDuration = ($CurrentSettings | Where-Object {$_.SettingName -eq "LockoutDuration"}).Value
                    $SecPol = $SecPol.replace("LockoutDuration = $CurrentLockoutDuration","LockoutDuration = $LockoutDuration")
                }
            }

            if ($LockoutResetCount)
            {
                if (!($CurrentSettings | Where-Object {$_.SettingName -eq "ResetLockoutCount"}).Value)
                {
                    $Lockout += "`nResetLockoutCount = $LockoutResetCount"
                } else {
                    $CurrentLockoutDuration = ($CurrentSettings | Where-Object {$_.SettingName -eq "LockoutDuration"}).Value
                    $SecPol = $SecPol.replace("LockoutDuration = $CurrentLockoutDuration","LockoutDuration = $LockoutDuration")
                }
            }
            $SecPol = $SecPol.replace("LockoutBadCount =$CurrentLouckoutCount",$Lockout)
            secedit /configure /db c:\windows\security\local.sdb /cfg "$PSScriptRoot\secPol.cfg" /areas SECURITYPOLICY | Out-Null
            Remove-Item "$PSScriptRoot\secpol.cfg"

        } Else {
            Write-Error "You are not running as Admin, cannot set password settings"
        }
    }
}

function Set-SecureUserRights
{
    if (Test-RunAsLevel -Admin)
    {
        secedit /export /cfg "$PSScriptRoot\secpol.cfg" | Out-Null
        $SecPol = Get-Content -Path "$PSScriptRoot\secpol.cfg"

        $SecPol = $SecPol.replace("SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551","SeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544")
        $SecPol = $SecPol.Replace("SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551","SeInteractiveLogonRight = *S-1-5-32-544")
        $SecPol = $SecPol.Replace("SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551","SeBackupPrivilege = *S-1-5-32-544")
        $SecPol = $SecPol.Replace("SeCreateSymbolicLinkPrivilege = *S-1-5-32-544","SeCreateSymbolicLinkPrivilege = *S-1-5-32-544,*S-1-5-83-0")
        $SecPol = $SecPol.Replace("SeDenyNetworkLogonRight = Guest","SeDenyNetworkLogonRight = Guest`nSeDenyBatchLogonRight = Guest`nSeDenyServiceLogonRight = Guest`nSeDenyServiceLogonRight = Guest`nSeDenyRemoteInteractiveLogonRight = *S-1-5-113,Guest")
        $SecPol = $SecPol.Replace("SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551","SeBatchLogonRight = *S-1-5-32-544")
        $SecPol = $SecPol.Replace("SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551","SeRestorePrivilege = *S-1-5-32-544")

        secedit /configure /db c:\windows\security\local.sdb /cfg "$PSScriptRoot\secPol.cfg" /areas SECURITYPOLICY | Out-Null
        Remove-Item "$PSScriptRoot\secpol.cfg"

    } Else {
        Write-Error "You are not running as Admin, cannot set password settings"
    }
}

function Rename-BuiltinAccount
{
    [CmdletBinding()]
    param
    (
        [string]$Name,
        [string]$NewName
    )

    process
    {
        if (Test-RunAsLevel -Admin)
        {
            $Adsi = [adsi]"WinNT://./$Name,user"
            $Adsi.psbase.rename($NewName)
        } Else {
            Write-Error "You are not running as Admin, cannot rename BuiltinAccount"
        }
    }
}

function Set-LegalText
{
    param
    (
        [string]$Path,
        [string]$Caption
    )

    process
    {
        if (Test-RunAsLevel -Admin)
        {
            if ((Test-Path $Path) -and ((Get-Item $Path) -is [system.io.fileinfo]))
            {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name legalnoticecaption -Value $Caption
                $LegalText = Get-IniFileContent $Path

                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name legalnoticetext -Value $LegalText

            } else {
                Write-Error "Please provide a path to clear text file."
            }
        } else {
            Write-Error "You are not running as Admin, cannot set LegalText"
        }
    }
}

function Set-FirewallLogging
{
    param
    (
        [switch]$LogSuccesfull=$true,
        [switch]$LogDenied=$true
    )

    process
    {
        if (Test-RunAsLevel -Admin)
        {
            # Originally transformed $LogSuccesfull and $LogDenied to "True" or "False"
            # This seemed to not work, using other vars isntead worked fine
            if ($LogSuccesfull) {$Log1 = "True"} else {$Log1 = "False"}
            if ($LogDenied) {$Log2 = "True"} else {$Log2 = "False"}

            Set-NetFirewallProfile -Name 'Domain' -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName "%systemroot%\system32\logfiles\firewall\domainfw.log" -LogMaxSizeKilobytes 16384 -LogBlocked $Log2 -LogAllowed $Log1 -Enabled True
            Set-NetFirewallProfile -Name 'Private' -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName "%systemroot%\system32\logfiles\firewall\privatefw.log" -LogMaxSizeKilobytes 16384 -LogBlocked $Log2 -LogAllowed $Log1 -Enabled True
            Set-NetFirewallProfile -Name 'public' -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName "%systemroot%\system32\logfiles\firewall\publicfw.log" -LogMaxSizeKilobytes 16384 -LogBlocked $Log2 -LogAllowed $Log1 -Enabled True
        } else {
            Write-Error "You are not running as Admin, cannot turn on FirewallLogging"
        }
    }
}

function Set-AuditPolicies
{
    process
    {
        if (Test-RunAsLevel -Admin)
        {
            $Subcategories = @("Credential Validation","Application Group Management","Computer Account Management","Other Account Management Events","Security Group Management","User Account Management","Logon","Other Logon/Logoff Events","Removable Storage","Audit Policy Change","Sensitive Privilege Use","IPsec Driver","Security System Extension")

            foreach ($Subcategory in $Subcategories)
            {
                auditpol /set /subcategory:$Subcategory /success:enable /failure:enable | Out-Null
            }
        
            auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
            auditpol /set /subcategory:"Account Lockout" /success:enable | Out-Null
        } else {
            Write-Error "You are not running as Admin, cannot set AuditPolicies"
        }
    }
}

function Set-GPOAutoRefresh
{
    if (Test-RunAsLevel -Admin)
    {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name 'Group Policy' -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy' -Name '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name NoBackgroundPolicy -Value 0
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name NoGPOListChanges -Value 0
    } else {
        Write-Error "You are not running as Admin, cannot set GPOAutoRefresh"
    }
}

function Set-CISSecuritySettings
{
    [CmdletBinding()]
    param
    (
        [switch]$Level2,
        [switch]$DomainController,
        [switch]$RDGateway,
        [int]$InactivityTimeoutSecs=900,
        [switch]$DisableRouterDiscovery,
        [switch]$DisableP2P,
        [switch]$DisableIPv6,
        [switch]$DisableNonDomainConnections,
        [switch]$DisablePrintSettings,
        [switch]$DisableOnlineRegistration,
        [switch]$EnableADLogging
    )

    process
    {
        if (Test-RunAsLevel -Admin)
        {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -Name NoConnectedUser -Value 3
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Value 1

            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value $InactivityTimeoutSecs

            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name RequireSecuritySignature -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoDisconnect -Value 15
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name EnableSecuritySignature -Value 15

            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name UseMachineId -Value 15
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinServerSec -Value 537395200
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinClientSec -Value 537395200
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ShutdownWithoutLogon -Value 0
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken  -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 2
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Value 0
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableInstallerDetection -value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name NoLockScreenCamera -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name NoLockScreenSlideshow -Value 1
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name DisableIPSourceRouting -value 1
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name EnableICMPRedirect -value 0
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name NoNameReleaseOnDemand -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name ScreenSaverGracePeriod -Value 5
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name TcpMaxDataRetransmissions -Value 3
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name WarningLevel -Value 90

            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name NC_AllowNetBridge_NLA -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name NC_StdDomainUserSetLocation -Value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Value "RequireMutualAuthentication=1, RequireIntegrity=1"
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Value "RequireMutualAuthentication=1, RequireIntegrity=1"

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutoplayfornonVolume -Value 1 

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name Disabled -Value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Control Panel' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name DontDisplayNetworkSelectionUI -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name DontEnumerateConnectedUsers -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name DisableLockScreenAppNotifications -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fAllowToGetHelp -Value 0

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' -Name ScenarioExecutionEnabled -Value 0

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name DisabledByGroupPolicy -Value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name MSAOptional -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\CredUI' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\CredUI' -Name DisablePasswordReveal -Value 1

            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\system' -Name EnableSmartScreen -Value 2

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\OneDrive' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\OneDrive' -Name DisableFileSyncNGSC -Value 1
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\Skydrive' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\Skydrive' -Name DisableFileSync -Value 1

            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name DisablePasswordSaving -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fPromptForPassword -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fEncryptRPCTraffic -Value 3
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MinEncryptionLevel -Value 3

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name DisableEnclosureDownload -Value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name AutoDownload -Value 0
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name DisableOSUpgrade -Value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Error Reporting' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Error Reporting' -Name AutoApproveOSDumps -Value 0

            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableAutomaticRestartSignOn -Value 1

            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 0
        
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Value 0
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Services' -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Services' -Name 'DisableRunAs' -Value 1

            if (!$DomainController)
            {
                if (Get-WindowsFeature AD-Domain-Services)
                {
                    $DomainController = $true
                } else {
                    $DomainController = $false
                }
            }

            # Not for DC
            if ($DomainController)
            {
                if ($EnableADLogging)
                {
                    auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable | Out-Null
                    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
                    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
                }

            } else {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name ForceUnlockLogon -Value 0
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name SmbServerNameHardeningLevel -Value 1

                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\rpc'
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\rpc' -Name EnableAuthEpResolution -Value 1
            }

            # RDG
            if (!(Get-WindowsFeature RDS-Gateway).installed -and !($RDGateway))
            {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name NullSessionPipes -Value "LSARPC, NETLOGON, SAMR"
            }

            # Level2 stuff
            if ($Level2)
            {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name disabledomaincreds -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 4
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name KeepAliveTime -Value 300000
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name TcpMaxDataRetransmissions -Value 3
            
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN' -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Name DisableWcnUI -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name EnableRegistrars -Value 0
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name DisableUPnPRegistrar -Value 0
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name DisableInBand802DOT11Registrar -Value 0
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name DisableFlashConfigRegistrar -Value 0
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name DisableWPDRegistrar -Value 0

                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoUseStoreOpenWith -Value 1
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name PreventHandwritingDataSharing -Value 1
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReport' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReport' -Name PreventHandwritingErrorReports -Value 1
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' -Name ExitOnMSICW -Value 1

                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name DisableContentFileUpdates -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoOnlinePrintsWizard -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoPublishingWizard -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoWebServices -Value 1

                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International' -Name BlockUserInputMethodsForSignIn -Value 1

                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider' -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' -Name DisableQueryRemoteServer -Value 0
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time' -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders' -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' -Name Enabled -Value 1

                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\LocationAndSensors' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\LocationAndSensors' -Name DisableLocation -Value 1

                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fSingleSessionPerUser -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCcm -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableLPT -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisablePNPRedir -Value 1
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -Value 900000
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxDisconnectionTime -Value 60000

                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name ConnectedSearchPrivacy -Value 3
            
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -ErrorAction SilentlyContinue | Out-Null
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -Name NoGenTicket -Value 1

                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name RemoveWindowsStore -Value 1

                if (!$DomainController)
                {
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\rpc' -Name RestrictRemoteClients -Value 1

                    if ($DisableNonDomainConnections)
                    {
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc' -Name GroupPolicy -ErrorAction SilentlyContinue | Out-Null
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name fBlockNonDomain -Value 1
                    }
                }

                if ($DisablePrintSettings)
                {
                    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Printers' -ErrorAction SilentlyContinue | Out-Null
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Printers' -Name DisableWebPnPDownload -Value 1
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Printers' -Name DisableHTTPPrinting -Value 1
                }

                if ($DisableOnlineRegistration)
                {
                    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' -ErrorAction SilentlyContinue | Out-Null
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' -Name NoRegistration -Value 1
                }

                if ($DisableP2P)
                {
                    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -ErrorAction SilentlyContinue | Out-Null
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name Disabled -Value 1
                }

                if ($DisableRouterDiscovery) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name PerformRouterDiscovery -Value 0}
                if ($DisableIPv6) {Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -Value '0xff'}
            }
        } else {
            Write-Error "You are not running as Admin, cannot set CISSecuritySettings"
        }
    }
}

function Set-CISLoggingSettings
{
    if (Test-RunAsLevel -Admin)
    {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog' -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\Application' -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\Application' -Name MaxSize -Value 32768
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\Security' -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\Security' -Name MaxSize -Value 196608
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\Setup' -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\Setup' -Name MaxSize -Value 32768
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\System' -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\windows\EventLog\System' -Name MaxSize -Value 32768
    } else {
        Write-Error "You are not running as Admin, cannot turn on CISLoggingSettings"
    }
}

function Disable-WindowsFeatureInstalations
{
    if (Test-RunAsLevel -Admin)
    {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Services\WinRS' -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Services\WinRS' -Name 'AllowRemoteShellAccess' -Value 0
    } else {
        Write-Error "You are not running as Admin, cannot disable WindowsFeatureInstalations"
    }
}

function Set-CISLocalUserSettings
{
    if (Test-RunAsLevel -Admin)
    {
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Where-Object {$_.Disabled -eq $false}
        New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

        foreach ($LocalUser in $LocalUsers.SID)
        {
            New-Item "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\Control Panel" -ErrorAction SilentlyContinue | Out-Null
            New-Item "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name 'ScreenSaveActive' -Value 1
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name 'SCRNSAVE.EXE' -Value 1
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name 'ScreenSaverIsSecure' -Value 1
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name 'ScreenSaveTimeOut' -Value 90

            New-Item "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Policies\Microsoft\Windows\CurrentVersion" -Name 'NoToastApplicationNotificationOnLockScreen' -Value 1

            New-Item "HKU:\$LocalUser\Software\Policies\Microsoft\Assistance" -ErrorAction SilentlyContinue | Out-Null
            New-Item "HKU:\$LocalUser\Software\Policies\Microsoft\Assistance\Client" -ErrorAction SilentlyContinue | Out-Null
            New-Item "HKU:\$LocalUser\Software\Policies\Microsoft\Assistance\Client\1.0" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Policies\Microsoft\Assistance\Client\1.0" -Name 'NoImplicitFeedback' -Value 1

            New-Item "HKU:\$LocalUser\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name 'ScanWithAntiVirus' -Value 1

            New-Item "HKU:\$LocalUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoInplaceSharing' -Value 1

            New-Item "HKU:\$LocalUser\Software\Microsoft\WindowsMediaPlayer" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKU:\$LocalUser\Software\Microsoft\WindowsMediaPlayer" -Name 'PreventCodecDownload' -Value 1
        }

        Remove-PSDrive HKU
        
    } else {
        Write-Error "You are not running as Admin, cannot set CISLocalUserSettings"
    }
}

####################
# Helper Functions #
####################

# Rudimentary ini reader
# Returns a PS object containing Ini settings
# 

function Get-IniFileContent
{
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    Process
    {
        $ini = @{}
        $section = "NO_SECTION"
        $ini[$section] = @{}

        switch -Regex -File $Path
        {
            "^\[(.+)\]$"
            {
                $Section = $Matches[1].Trim()
                $Ini[$Section] = @{}
            }

            "^\s*([^#].+?)\s*=\s*(.*)"
            {
                $Name,$Value = $Matches[1..2]

                if (!($name.StartsWith(";")))
                {
                    $Ini[$Section][$Name] = $Value.Trim()
                }
            }
        }

        $IniObjectCollection = @()
        $IniProperties = @{SettingName=''; Value=''; Section=''}
        $IniObjectTemplate = New-Object -TypeName PSObject -Property $IniProperties

        foreach ($IniSection in $Ini.Keys)
        {
            $TempSection = $Ini[$IniSection]

            foreach ($IniSetting in $TempSection.Keys)
            {
                $CurrentObject = $IniObjectTemplate.PSObject.Copy()
                $CurrentObject.SettingName = $IniSetting
                $CurrentObject.Value = $TempSection[$IniSetting]
                $CurrentObject.Section = $IniSection

                $IniObjectCollection += $CurrentObject
            }
        }

        return $IniObjectCollection
    }
}

# Checks if current session is admin or not. If 
function Test-RunAsLevel ([switch]$Admin)
{  
    $CU = [Security.Principal.WindowsIdentity]::GetCurrent()
    $RE = (New-Object Security.Principal.WindowsPrincipal $CU).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($Admin)
    {
        return $RE
    } else {
        return !$RE
    }
}
