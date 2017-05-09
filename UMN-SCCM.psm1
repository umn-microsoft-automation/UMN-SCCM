###
# Copyright 2017 University of Minnesota, Office of Information Technology

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
###
function Get-CMDeploymentTypePath {
    <#
        .SYNOPSIS
            Gets the paths for all deployment types on an application.
        .DESCRIPTION
            Takes in a IResultObject#SMS_Application object and then returns the paths for each deployment type.
        .EXAMPLE
            Get-CMApplication -Name "MyApp" | Get-CMDeploymentTypePath
        .PARAMETER CMApplication
            This is the application returned from the Get-CMApplication cmdlet.
    #>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
		[PSObject]$CMApplication
	)

	begin {
		$ReturnObject = New-Object System.Collections.ArrayList
	}

	process {
		$ApplicationName = $CMApplication.LocalizedDisplayName
		Write-Verbose -Message "Application: $ApplicationName"

		$AppXml = [xml]$CMApplication.SDMPackageXML
		$DeploymentTypes = $AppXml.AppMgmtDigest.DeploymentType
		
		foreach($DeploymentType in $DeploymentTypes) {
			$ReturnType = New-Object PSObject

			$DeploymentTypeName = $DeploymentType.Title.'#text'
			$DeploymentTypeLocation = $DeploymentType.Installer.Contents.Content.Location
			Write-Verbose -Message "Content Location: $DeploymentTypeLocation"

			$ReturnType | Add-Member -MemberType NoteProperty -Name "ApplicationName" -Value $ApplicationName
			$ReturnType | Add-Member -MemberType NoteProperty -Name "DeploymentType" -Value $DeploymentTypeName
			$ReturnType | Add-Member -MemberType NoteProperty -Name "DeploymentTypeLocation" -Value $DeploymentTypeLocation
			$null = $ReturnObject.Add($ReturnType)
		}
	}

	end {
		return $ReturnObject
	}
}

function Get-PendingReboot {
	<#
		.SYNOPSIS
			Simply returns what possible pending reboots there are on the current machine.

		.DESCRIPTION
			Takes in no values and returns a hashtable of what reboots are pending and which are not.

		.NOTES
			Name: Get-PendingReboot
			Author: Jeff Bolduan
			LASTEDIT: 09/01/2016

			Based on xPendingReboot DSC functions
			https://github.com/PowerShell/xPendingReboot
		.EXAMPLE

	#>
	[CmdletBinding()]
	[OutputType([Hashtable])]
	param(
		
	)

	# Check the Componenet Based Servicing registry location for a pending reboot
	$ComponentBasedServicingKeys = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing").Name
	if($ComponentBasedServicingKeys) {
		$ComponentBasedServicing = $ComponentBasedServicingKeys.Split("\") -contains "RebootPending"
	} else {
		$ComponentBasedServicing = $false
	}

	$WindowsUpdateKeys = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update").Name
	if($WindowsUpdateKeys) {
		$WindowsUpdate = $WindowsUpdateKeys.Split("\") -contains "RebootRequired"
	} else {
		$WindowsUpdate = $false
	}

	$PendingFileRename = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager").PendingFileRenameOperations.Length -gt 0
	$ActiveComputerName = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName").ComputerName
	$PendingComputerName = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName").ComputerName
	$PendingComputerRename = $ActiveComputerName -ne $PendingComputerName

	try {
		$CCMClientSDK = Invoke-WmiMethod -Namespace "root\ccm\ClientSDK" -Class "CCM_ClientUtilities" -Name "DetermineIfRebootPending" -ErrorAction Stop
	} catch {
		Write-Warning -Message "Unable to query CCM_ClientUtilities: $_"
	}

	$SCCMSDK = ($CCMClientSDK.ReturnVal -eq 0) -and ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)

	return @{
		ComponenetBasedServicing = $ComponentBasedServicing
		WindowsUpdate = $WindowsUpdate
		PendingFileRename = $PendingFileRename
		PendingComputerRename = $PendingComputerRename
		CCMClientSDK = $SCCMSDK
	}
}

function New-ComputerObjectSCCM
{
    <#
        .Synopsis
            Add computer object to sccm, add to a collection
        .DESCRIPTION
            Add computer object to sccm, add to a collection and waits to return until the device is in the collection
            Uses direct add and accepts smsbiosGuid or Mac Address.
    
        .PARAMETER computer
            Name of computer object to be added

        .PARAMETER siteserver
            FQDN of the site server

        .PARAMETER smBiosGuid
            If the computer is a vm from VMWARE use Get-SMBiosGuidVmware from our module UMN-VMWare to get the UUID and convert it to smsbiosguild

        .PARAMETER macAddress
            If you don't have the smasbiosguild, you can use the mac address
        
        .PARAMETER CollectionName
            Device Collection to add the computer object to.

        .PARAMETER sitecode
            SCCM Site Code

        .EXAMPLE
            New-ComputerObjectSCCM -computer $computer -smBiosGUID $smBiosGUID -siteserver "siteserver.mysite.org" - sitecode "Site"
    #>

    [CmdletBinding()]
    Param
    (
        [ValidateNotNullOrEmpty()]
        [string]$computer,

        [ValidateNotNullOrEmpty()]
        [string] $siteserver,

        [Parameter(ParameterSetName='smbios')]
        [string]$smBiosGUID,

        [Parameter(ParameterSetName='mac')][ValidatePattern("([a-zA-Z0-9]{2}:){5}[a-zA-Z0-9]{2}")]
        [string]$macAddress,

        [ValidateNotNullOrEmpty()]
        [string]$CollectionName,

        [ValidateNotNullOrEmpty()]
        [string] $sitecode

    )

    Begin
    {
        Push-Location
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1" -Force
        $location = $sitecode+":"
        set-location $location # see wiki about creating the PS-Drive in the first place
    }
    Process
    {
        if ($smBiosGUID){$null = Import-CMComputerInformation -CollectionName $CollectionName -ComputerName $computer -SMBiosGuid $smBiosGUID}
        else{$null = Import-CMComputerInformation -CollectionName $CollectionName -ComputerName $computer -MacAddress $macAddress}
        # Force collection updates.  Since the collection is limited by All Systems collection, it has to be in there first
        $CollectionQueryAllS = Get-WmiObject -Namespace "Root\SMS\Site_$sitecode" -Class SMS_Collection -Filter "Name='All Systems'" -computername $siteserver
        $null = $CollectionQueryAllS.RequestRefresh()
        start-sleep 60

        # Right now the lag on colleciton refresh is around 5 minutes, loop to wait until the computer object finally shows up in the collection
        # hour cap, after that .. error
        $count = 0
        do {
            start-sleep 60
            $count++
            $device = Get-CMDevice -CollectionName $CollectionName -Name $computer 
        } while ($device -eq $null -and $count -lt 60)
        if ($device -eq $null){Pop-Location;Throw "$computer never added to $CollectionName"}
        
    }
    End
    {
        Pop-Location
    }
}

function New-ComputerVariablesSCCM
{
    <#
        .Synopsis
            Add variables to a computer object in SCCM
        .DESCRIPTION
            Add variables to a computer object in SCCM
    
        .PARAMETER computer
            Name of computer object to be added

        .PARAMETER deviceVariables
            Hastable of variable to add.  Key = variable name, Value = Value of the variable
        
        .PARAMETER CollectionName
            Device Collection to search for computer object, defaults to "All Systems"

        .PARAMETER sitecode
            SCCM Site Code
    
        .EXAMPLE
            Example of how to use this cmdlet
    #>

    [CmdletBinding()]
    Param
    (
        [ValidateNotNullOrEmpty()]
        [string]$computer,

        [ValidateNotNullOrEmpty()]
        [string]$CollectionName = "All Systems",

        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$deviceVariables,

        [ValidateNotNullOrEmpty()]
        [string] $sitecode

    )

    Begin
    {
        Push-Location
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1" -Force
        $location = $sitecode+":"
        set-location $location # see wiki about creating the PS-Drive in the first place
    }
    Process
    {
        $deviceID = (Get-CMDevice -CollectionName $CollectionName -Name $computer).ResourceID
        if(-not($deviceID)){Pop-Location;throw "Unable to find $computer in $CollectionName"}
        
        foreach ($key in $deviceVariables.Keys)
        {
            $null = New-CMDeviceVariable -DeviceID $deviceID -VariableName $key -VariableValue $deviceVariables[$key]
            Write-Verbose "$key -- $($deviceVariables[$key])"
        }
        
    }
    End
    {
        Pop-Location
    }
}

function get-ClientMaintWindow
{
    <#
        .Synopsis
            Requires SCCM PowerShell cmdlet to convert WMI class to readable schedule
        .DESCRIPTION
            Requires SCCM PowerShell cmdlet to convert WMI class to readable schedule

        .PARAMETER computer
            Name of computer object to be added

        .PARAMETER sitecode
            SCCM Site Code

        .EXAMPLE
            get-ClientMaintWindow -computer 'test-machine' -sitecode 'sccmsite'
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]$computer,

        [Parameter(Mandatory)]
        [string]$sitecode

    )
 
    Begin
    {
        $Future = @()
        $location = $sitecode+":"
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1" -Force
        Push-Location
        set-location $location # see wiki about creating the PS-Drive in the first place

    }   

    Process
    {
        Get-WmiObject -query "SELECT * FROM CCM_ServiceWindow " -namespace "root\CCM\Policy\Machine\ActualConfig" -ComputerName $computer
        If ($wmiClass -eq $Null){throw "$VM WMI call failed"}

        Push-Location
        set-location $location # see wiki about creating the PS-Drive in the first place

        $wmiClass.schedules | % {
            $MaintWindow = Convert-CMSchedule -ScheduleString $_
            If ($MaintWindow.Starttime -ge (get-date)){$Future += $MaintWindow}
        }
    } 
       
    End
    {
    
        If ($Future -eq $Null) {Pop-Location;throw "$vm has no future mainteanance windows"}
        Else {$Future |Select-Object -Property HourDuration,StartTime}
        Pop-Location
    }
}

function Remove-sccmDevice
{
    <#
        .Synopsis
            Remove computer object from SCCM
        .DESCRIPTION
            Remove computer object from SCCM
        .EXAMPLE
            Example of how to use this cmdlet
        .EXAMPLE
            Another example of how to use this cmdlet
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]$computer,

        [Parameter(Mandatory)]
        [string]$sitecode

    )

    Begin
    {
        $location = $sitecode+":"
        Push-Location
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1" -Force
        set-location $location # see wiki about creating the PS-Drive in the first place
    }
    Process
    {
        try{Remove-CMDevice -DeviceName $computer -Force}
        catch{Pop-Location;throw ($_.Exception.Message + $_.InvocationInfo.Line + $_.InvocationInfo.PositionMessage)}
    }
    End
    {
        Pop-Location
    }
}

function Remove-sccmDeviceFromCollection
{
    <#
        .Synopsis
            Remove Computer Object from specific device collection
        .DESCRIPTION
            Remove Computer Object from specific device collection
        .EXAMPLE
            Example of how to use this cmdlet
        .EXAMPLE
            Another example of how to use this cmdlet
    #>

    [CmdletBinding()]
    Param
    (
        [ValidateNotNullOrEmpty()]
        [string]$computer,

        [ValidateNotNullOrEmpty()]
        [string]$sitecode,

        [ValidateNotNullOrEmpty()]
        [string]$siteserver,

        [ValidateNotNullOrEmpty()]
        [string]$colName
    )

    Begin
    {
        $location = $sitecode+":"
        Push-Location
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1" -Force
        set-location $location # see wiki about creating the PS-Drive in the first place
    }
    Process
    {
        ## sccm is case sensative but -mathc is not so ... yeah. Fetch list of vms, match and remove with valid case
        $found = $false
        ## Fetch list of vms
        $rules = Get-CMDeviceCollectionDirectMembershipRule -CollectionName $colName
        foreach ($rule in $rules)
        {
            if($rule.RuleName -match $computer)
            {
                $found = $true
                Remove-CMDeviceCollectionDirectMembershipRule -CollectionName $colName -ResourceName $rule.RuleName -Confirm:$false -Force
                Start-Sleep -Seconds 5
                $CollectionQueryAllS = Get-WmiObject -Namespace "Root\SMS\Site_$sitecode" -Class SMS_Collection -Filter "Name='$colName'" -computername $siteserver
                $null = $CollectionQueryAllS.RequestRefresh()
                break
            }
        }
        if (!($found)){Pop-Location;return (throw "Failed to find $computer in $colName" )}
        else
        {
            ## neither success nor failure seems to return anything, so have to rerun and make sure no match.
            $rules = Get-CMDeviceCollectionDirectMembershipRule -CollectionName $colName
            foreach ($rule in $rules)
            {
                if($rule.RuleName -match $computer){Pop-Location;return (throw "$computer NOT removed from $colName")}
            }
            $true
        }
        
    }
    End
    {
        Pop-Location
    }
}

Export-ModuleMember -Function *
