# Windows Security Module by Yaron Vanhulst
# 
# Based on the CIS Windows Security benchmark.
# Currently tested and maintained for:
#     - Windows Server 2012 R2
#

## main functions ##
# Gets a specific or all password settings from the in memory stored object.
function Get-PasswordSetting {
	[CmdletBinding()]
    param (
		[Parameter(
            ParameterSetName='Name'
        )]
		[string]$Name,
		[Parameter(
            ParameterSetName='Section'
        )]
		[string]$Section
	)
	begin {
		Test-EnvSettings
		if (!$Script:PasswordSettings) {
			$Script:PasswordSettings = Export-SecPolSettings
		}
	}

	process {
		if ($Name){
			$Setting = $Script:PasswordSettings | Where-Object {$_.SettingName -eq $Name}

			return $Setting
		}

		if ($Section) {
			$Setting = $Script:PasswordSettings | Where-Object {$_.Section -eq $Section}

			return $Setting
		}
	}
}

# Changes the value of a setting in memory. Is only actually changed writen to disk OS if Save-PasswordSettings is called after.
function Set-PasswordSetting {
	[CmdletBinding()]
    param (
		[parameter(Mandatory=$true)]
		[string]$Name,
		[parameter(Mandatory=$true)]
		[string]$Value
	)
	begin {
		Test-EnvSettings
		if (!$Script:PasswordSettings) {
			$Script:PasswordSettings = Export-SecPolSettings
		}
	}

	process {

	}
}

# Commits any changes made by Set-PasswordSetting to memory
function Save-PasswordSettings {
	
}

## Helper Functions ##
# A bunch of functions that will help internal functioning of cmdlets but aren't otherwise all that usefull

# Exports password settings and turns them in to a PS object
function Export-SecPolSettings {
    [CmdletBinding()]
    param (
		[switch]$ExcludeRegistryValues,
		[switch]$KeepFile
    )
	
	begin {
		Test-RunAsLevel
	}

    process {
        secedit /export /cfg "$PSScriptRoot\secpol.cfg" | Out-Null
        $PWSettings = Get-IniFileContent -Path "$PSScriptRoot\secpol.cfg"
		Remove-Item "$PSScriptRoot\secpol.cfg"

		if ($ExcludeRegistryValues){
			$PWSettings = $PWSettings | Where-Object {$_.Section -ne "Registry Values"}
		}

        return $PWSettings
    }
}

# Rudimentary ini reader
# Returns a PS object containing Ini settings
function Get-IniFileContent
{
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    Process {
        $ini = @{}
        $section = "NO_SECTION"
        $ini[$section] = @{}

        switch -Regex -File $Path
        {
            "^\[(.+)\]$" {
                $Section = $Matches[1].Trim()
                $Ini[$Section] = @{}
            }

            "^\s*([^#].+?)\s*=\s*(.*)" {
                $Name,$Value = $Matches[1..2]

                if (!($name.StartsWith(";"))) {
                    $Ini[$Section][$Name] = $Value.Trim()
                }
            }
        }

        $IniObjectCollection = @()
        $IniProperties = @{SettingName=''; Value=''; Section=''}
        $IniObjectTemplate = New-Object -TypeName PSObject -Property $IniProperties

        foreach ($IniSection in $Ini.Keys) {
            $TempSection = $Ini[$IniSection]

            foreach ($IniSetting in $TempSection.Keys) {
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

function Out-IniFile {
	
}

# Checks if current session is admin or not.
function Test-RunAsLevel {  
    $CU = [Security.Principal.WindowsIdentity]::GetCurrent()
    $RE = (New-Object Security.Principal.WindowsPrincipal $CU).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    if ($RE) {
        return $true
    } else {
        $NOT_ADMIN_ERROR = [string]"Not running as admin. Insufficient rights. Please run from an elevated prompt."
        throw $NOT_ADMIN_ERROR
    }
}

# Checks to see if windows version is supported
function Test-WinVersion {
    $Version = [System.Environment]::OSVersion.Version

    switch ($Version.Major) {
        6 { if ($Version.minor -eq 3) { Break }}

        10 { Break }

        default {
            $UNSUPORTED_VERSION_ERROR = [string]"This version of Windows is untested and unssuported"
            throw $UNSUPORTED_VERSION_ERROR
        }
    }
}

# To be ran at the start of every function
function Test-EnvSettings {
	param (
		[switch]$IgnoreUnsuportedOS
	)

	process {
		if (!$Script:TestedEnvSettings) {
			
			Test-RunAsLevel | Out-Null

			if (!$IgnoreUnsuportedOS) {
				Test-WinVersion
			}

			$Script:TestedEnvSettings = $true
		}
	}
}
