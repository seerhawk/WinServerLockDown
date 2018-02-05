# Security script by Yaron Vanhulst
# 
# Based on the CIS Windows Security benchmark.
#

## Templates ##


## main functions ##


## Helper Functions ##

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
function Test-RunAsLevel ([switch]$Admin) {  
    $CU = [Security.Principal.WindowsIdentity]::GetCurrent()
    $RE = (New-Object Security.Principal.WindowsPrincipal $CU).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($Admin) {
        return $RE
    } else {
        return !$RE
    }
}

# Checks to see if windows version is supported
function Test-WindowsVersion {
    $Version = [System.Environment]::OSVersion.Version

    switch ($Version.Major) {
        10 { return $true }
        6 { if ($Version.minor -eq 3) { return $True }}
    }
}
