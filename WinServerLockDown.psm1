# Windows Security Module by Yaron Vanhulst
# 
# Based on the CIS Windows Security benchmark.
# Currently tested and maintained for:
#     - Windows Server 2012 R2 (CIS Version 2.3.0)
#

# 1.1.1 - Level 1
function Get-PasswordHistory {
	param (
		[switch]$DefaultValue
	)
	process {
		$Default = 24
		if ($DefaultValue) {
			return $Default
		} else {
			$Current = Get-SecPolSetting -Name 'PasswordHistory'
			if ($Current) {
				return $Current
			} else {
				return $Default
			}
		}
	}
}

function Set-PasswordHistory {
	[CmdletBinding()]
	param (
		[parameter(ParameterSet="Value")]
		[int]$Value,
		[parameter(ParameterSet="DefaultValue")]
		[switch]$DefaultValue,
		[parameter(ParameterSet="RecommendedValue")]
		[switch]$CISRecommendedValue
	)

	process {
		if ($DefaultValue) {
			$Value = 0
		}

		if ($CISRecommendedValue) {
			$Value = 24
		}

		Set-SecPolSetting -Name 'PasswordHistory' -Value $Value -ManualCommit:$ManualCommit
	}
}

# 1.1.2 - Level 1
function Get-MaximumPasswordAge {
	param (
		[switch]$DefaultValue
	)
	process {
		$Default= 42
		if ($DefaultValue) {
			return $Default
		} else {
			$current = Get-SecPolSetting -Name 'MaximumPasswordAge'
			if ($Current) {
				return $Current
			} else {
				return $Default
			}
		}
	}
}

function Set-MaximumPasswordAge {
	param (
		[Parameter(Position=0, ParameterSet="Value")]
		[int]$Value,
		[parameter(ParameterSet="DefaultValue")]
		[switch]$DefaultValue,
		[parameter(ParameterSet="RecommendedValue")]
		[switch]$CISRecommendedValue,
		[switch]$ManualCommit
	)
	process {
		if ($DefaultValue) {
			$Value = 42
		}

		if ($CISRecommendedValue) {
			$Value = 60
		}

		Set-SecPolSetting -Name 'MaximumPasswordAge' -Value $Value -ManualCommit:$ManualCommit
	}
}

# 1.1.3 - Level 1
function Get-MinimumPasswordAge {
	param (
		[switch]$DefaultValue
	)
	process {
		$Default = 0
		if ($DefaultValue) {
			return $Default
		} else {
			$Current = Get-SecPolSetting -Name 'MinimumPasswordAge'
			if ($Current) {
				return $Current
			} else {
				return $Default
			}
		}
	}
}

function Set-MinimumPasswordAge {
	param (
		[Parameter(Position=0, ParameterSet="Value")]
		[int]$Value,
		[parameter(ParameterSet="DefaultValue")]
		[switch]$DefaultValue,
		[parameter(ParameterSet="RecommendedValue")]
		[switch]$CISRecommendedValue,
		[switch]$ManualCommit
	)
	process {
		if ($DefaultValue) {
			$Value = 0
		}

		if ($CISRecommendedValue) {
			$Value = 1
		}

		Set-SecPolSetting -Name 'MinimumPasswordAge' -Value $Value -ManualCommit:$ManualCommit
	}
}

# 1.1.4 - Level 1
function Get-MinimumPasswordLength {
	param (
		[switch]$DefaultValue
	)
	process {
		$Default = 7
		if ($DefaultValue) {
			return $Default
		} else {
			$Current = Get-SecPolSetting -Name 'MinimumPasswordLength'
			if ($Current) {
				return $Current
			} else {
				return $Default
			}
		}
	}
}

function Set-MinimumPasswordLength {
	param (
		[Parameter(Position=0, ParameterSet="Value")]
		[int]$Value,
		[parameter(ParameterSet="DefaultValue")]
		[switch]$DefaultValue,
		[parameter(ParameterSet="RecommendedValue")]
		[switch]$CISRecommendedValue,
		[switch]$ManualCommit
	)
	process {
		if ($DefaultValue) {
			$Value = 7
		}

		if ($CISRecommendedValue) {
			$Value = 14
		}

		Set-SecPolSetting -Name 'MinimumPasswordLength' -Value $Value -ManualCommit:$ManualCommit
	}
}

# 1.1.5 - Level 1
function Get-PasswordComplexity {
	param (
		[switch]$DefaultValue
	)
	process {
		$Default = 0
		if ($DefaultValue) {
			return $Default
		} else {
			$Current = Get-SecPolSetting -Name 'PasswordComplexity'
			if ($Current) {
				return $Current
			} else {
				return $Default
			}
		}
	}
}

function Set-PasswordComplexity {
	param (
		[Parameter(Position=0, ParameterSet="Value")]
		[validateset(0,1)]
		[int]$Value,
		[parameter(ParameterSet="DefaultValue")]
		[switch]$DefaultValue,
		[parameter(ParameterSet="RecommendedValue")]
		[switch]$CISRecommendedValue,
		[switch]$ManualCommit
	)
	process {
		if ($DefaultValue) {
			$Value = 0
		}

		if ($CISRecommendedValue) {
			$Value = 1
		}

		Set-SecPolSetting -Name 'PasswordComplexity' -Value $Value -ManualCommit:$ManualCommit
	}
}

# 1.1.6 - Level 1
function Get-PasswordReversibleEncryption {
	param (
		[switch]$DefaultValue
	)
	process {
		$Default = $true
		if ($DefaultValue) {
			return $Default
		} else {
			$Current = Get-SecPolSetting -Name 'ClearTextPassword'
			if ($Current) {
				return $Current
			} else {
				return $Default
			}
		}
	}
}

function Set-PasswordReversibleEncryption {
	param (
		[Parameter(Position=0, ParameterSet="Value")]
		[validateset(0,1,$true,$false)]
		$Value,
		[parameter(ParameterSet="DefaultValue")]
		[switch]$DefaultValue,
		[parameter(ParameterSet="RecommendedValue")]
		[switch]$CISRecommendedValue,
		[switch]$ManualCommit
	)
	process {
		if ($DefaultValue) {
			$Value = 0
		}

		if ($CISRecommendedValue) {
			$Value = 1
		}

		if (!($DefaultValue -or $CISRecommendedValue)) {
			if ($Value) {
				$Value = 1
			} else {
				$Value = 0
			}
		}

		Set-SecPolSetting -Name 'ClearTextPassword' -Value $Value -ManualCommit:$ManualCommit
	}
}

## SecPol functions ##
# Gets a specific or all password settings from the in memory stored object.
function Get-SecPolSetting {
	[CmdletBinding()]
    param (
		[string]$Name,
		[string]$Section
	)
	begin {
		if ($Name -and $Section){
			throw [string]"the -Name and -Section paramaters are mutualy exclusive."
		}
		Test-EnvSettings
		if (!$Script:SecPolSettings) {
			$Script:SecPolSettings = Export-SecPolSettings
		}
	}

	process {
		if ($Name){
			$Setting = $Script:SecPolSettings | Where-Object {$_.Name -eq $Name}

			return $Setting
		}

		if ($Section) {
			$Settings = $Script:SecPolSettings | Where-Object {$_.Section -eq $Section}

			return $Settings
		} else {
			return $Script:SecPolSettings
		}
	}
}

# Changes the value of a setting in memory. Is only actually writen to disk OS if Save-PasswordSettings is called after.
function Set-SecPolSetting {
	[CmdletBinding()]
    param (
		[parameter(Mandatory=$true)]
		[string]$Name,
		[parameter(Mandatory=$true)]
		[string]$Value,
		[switch]$ManualCommit
	)
	begin {
		Test-EnvSettings
		if (!$Script:SecPolSettings) {
			$Script:SecPolSettings = Export-SecPolSettings
		}
	}

	process {
		$Script:SecPolSettings | Where-Object {$_.Name -eq $Name} | % {$_.Value = $Value}
		
		if (!$ManualCommit) {
			Save-SecPolSettings
		}
	}
}

# Commits any changes made by Set-PasswordSetting to memory
function Save-SecPolSettings {
	[CmdletBinding()]
	param()
	process {
		if ($Script:SecPolSettings) {
			Out-IniFile -Path "$script:PSScriptRoot\secpol.cfg" -PSIniObject $Script:SecPolSettings
			secedit /configure /db c:\windows\security\local.sdb /cfg "$PSScriptRoot\secpol.cfg" /areas SECURITYPOLICY | Out-Null
			Remove-Item $script:PSScriptRoot\secpol.cfg
		}
	}
}

# Exports password settings and turns them in to a PS object
function Export-SecPolSettings {
    [CmdletBinding()]
    param (
		[switch]$ExcludeRegistryValues,
		[switch]$KeepFile
    )
	
	begin {
		Test-RunAsLevel | Out-Null
	}

    process {
        secedit /export /cfg "$PSScriptRoot\secpol.cfg" | Out-Null
        $SecPolSettings = Get-IniFileContent -Path "$PSScriptRoot\secpol.cfg"
		if (!$KeepFile) {
			Remove-Item "$PSScriptRoot\secpol.cfg"
		}

		if ($ExcludeRegistryValues){
			$SecPolSettings = $SecPolSettings | Where-Object {$_.Section -ne "Registry Values"}
		}

        return $SecPolSettings
    }
}

## Helper Functions ##
# A bunch of functions that will help internal functioning of cmdlets but aren't otherwise all that usefull

# Rudimentary ini reader
# Returns a PS object containing Ini settings
function Get-IniFileContent
{
    param (
        [Parameter(Mandatory=$true, Position=0)]
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
        $IniProperties = @{Name=''; Value=''; Section=''}
        $IniObjectTemplate = New-Object -TypeName PSObject -Property $IniProperties

        foreach ($IniSection in $Ini.Keys) {
            $TempSection = $Ini[$IniSection]

            foreach ($IniSetting in $TempSection.Keys) {
                $CurrentObject = $IniObjectTemplate.PSObject.Copy()
                $CurrentObject.Name = $IniSetting
                $CurrentObject.Value = $TempSection[$IniSetting]
                $CurrentObject.Section = $IniSection

                $IniObjectCollection += $CurrentObject
            }
        }

        return $IniObjectCollection
    }
}

function Out-IniFile {
	param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
		[string]$Path,
		[Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
		$PSIniObject
    )

	process {
		$Sections = @{}
		$Ini = @()

		foreach ($Object in $PSIniObject) {
			if ($Object.Section -notin $Sections.Keys) {
				$Section = @()
				$Sections[$Object.Section] = $Section
			}

			$Sections[$Object.Section] += [string]($Object.Name + " = " + $Object.Value)

		}

		foreach ($Section in $Sections.Keys) {
			$Ini += "[$Section]"
			foreach ($Setting in $Sections[$Section]) {
				$Ini += $Setting
			}
		}

		$Ini | Out-File $Path

	}
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
            $UNSUPORTED_VERSION_ERROR = [string]"This version of Windows is currently untested and unssuported."
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
