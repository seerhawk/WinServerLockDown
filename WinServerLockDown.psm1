# Security script by Yaron Vanhulst
# 
# Based on the CIS Windows Security benchmark.
#

## Templates ##


## main functions ##


## Helper Functions ##
# A bunch of functions that will help but aren't otherwise usefull

# Rudimentary ini reader
# Returns a PS object containing Ini settings
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

# Checks if current session is admin or not.
function Test-RunAsLevel {  
    $CU = [Security.Principal.WindowsIdentity]::GetCurrent()
    $RE = (New-Object Security.Principal.WindowsPrincipal $CU).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    if ($RE) {
        return $true
    } else {
        $NOT_ADMIN_ERROR = [string]"Not running as admin. Insufficient rights"
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
            $UNSUPORTED_VERSION_ERROR = [string]"This version of Windows is untested and unssuported."
            throw $UNSUPORTED_VERSION_ERROR
        }
    }
}
