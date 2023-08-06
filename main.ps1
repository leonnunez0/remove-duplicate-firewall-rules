<#
.SYNOPSIS
    Identify and remove all duplicate firewall rules in Windows OS

.DESCRIPTION
    Search the system to find duplicate firewall rules & are deleted.
    Duplicate rules are saved in JSON format to review.
    A -Test switch is added in the removal function to simulate the deletion. This will print which rules will be deleted.


.AUTHOR
    Leon Nunez

.VERSION
    0.1

.LASTEDIT
    2023-08-07


.EXAMPLE
    & .\main.ps1
#>
function Find-DuplicateFirewallRules
{
<#
.SYNOPSIS
    Finds duplicate firewall rules based on specified parameters.

.DESCRIPTION
    This function retrieves firewall rules based on the parameters Action, Direction, and Enabled, and then identifies duplicate rules by comparing their properties, such as 
    Port, Application, Interface, NetAddress, InterfaceType, Security, and Service. If rules have identical properties, they are considered duplicates.

.PARAMETER Action
    Specifies the action (Allow or Block) of the firewall rules to search for duplicates.

.PARAMETER Direction
    Specifies the direction (Inbound or Outbound) of the firewall rules to search for duplicates.

.PARAMETER Enabled
    Specifies whether the firewall rules should be enabled or disabled (True or False) to search for duplicates.

.OUTPUTS
    Returns a hashtable containing duplicate firewall rules. The hashtable keys are the names of the duplicate rules, and the values are arrays of duplicate rule objects.

.EXAMPLE
    Find-DuplicateFirewallRules -Action Allow -Direction Outbound -Enabled True
#>
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Allow", "Block")]
        [string] $Action,

        [Parameter(Mandatory)]
        [ValidateSet("Inbound","Outbound")]
        [string] $Direction,

        [Parameter(Mandatory)]
        [ValidateSet("True","False")]
        [string] $Enabled
    )
    $allRules = $(Get-NetFirewallRule -Direction $Direction -Enabled $Enabled -Action $Action)
    $valid_rules = @{}
    $duplicate_rules = @{}
    $i=0
    $rules = foreach($rule in $allRules)
    {
        [pscustomobject]@{
            "InstanceID" = $rule.InstanceID
            "Name" = $rule.DisplayName
            "Port" = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule | Select Protocol,LocalPort, RemotePort, IcmpType, DynamicTarget
            "Application" = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule|Select Program, Package
            "Interface" = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule | Select InterfaceAlias
            "NetAddress" = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule |Select LocalAddress, RemoteAddress
            "InterfaceType" = Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule |Select InterfaceType
            "Security" = Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule |Select Authentication, Encryption, OverrideBlockRules, LocalUser, Remoteuser, RemoteMachine 
            "Service" = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule |Select Service

        }
        $i++
        Try{
        Write-Progress -Activity "Parsing Rules into array. Fetching Port and Program information." -PercentComplete (($i/$($allRules.count))*100)
        }
        Catch [System.Management.Automation.RuntimeException]
        {}
    }

    foreach($rule in $rules)
    {
        $key = $rule.Name
        if ($valid_rules.ContainsKey($($rule.Name)))
        {
            # check if it contains the same parameters like Name, Port & Program
            $is_same_port = -not(Compare-Object -ReferenceObject $($rule.Port.PSObject.Properties) -DifferenceObject $($valid_rules[$key].Port.PSObject.Properties))
            $is_same_application = -not(Compare-Object -ReferenceObject $($rule.Application.PSObject.Properties) -DifferenceObject $($valid_rules[$key].Application.PSObject.Properties))
            $is_same_interface = -not(Compare-Object -ReferenceObject $($rule.Interface.PSObject.Properties)  -DifferenceObject $($valid_rules[$key].Interface.PSObject.Properties))
            $is_same_address = -not(Compare-Object -ReferenceObject $($rule.NetAddress.PSObject.Properties)  -DifferenceObject $($valid_rules[$key].NetAddress.PSObject.Properties))
            $is_same_interfacetype = -not(Compare-Object -ReferenceObject $($rule.InterfaceType.PSObject.Properties)  -DifferenceObject $($valid_rules[$key].InterfaceType.PSObject.Properties))
            $is_same_security = -not(Compare-Object -ReferenceObject $($rule.Security.PSObject.Properties)  -DifferenceObject $($valid_rules[$key].Security.PSObject.Properties))
            $is_same_service = -not(Compare-Object -ReferenceObject $($rule.Service.PSObject.Properties)  -DifferenceObject $($valid_rules[$key].Service.PSObject.Properties))


            if ($is_same_port -and $is_same_application -and $is_same_interface -and $is_same_address -and $is_same_interfacetype -and `
            $is_same_security -and $is_same_service)
            {
                [array] $duplicate_rules[$key]+=$rule
            }
            else {continue}
        }
        else
        {
            $valid_rules[$key] = @($rule)
        }
        }
$duplicate_rules | ConvertTo-Json -Depth 99 | Out-File duplicateRules.json utf8 -Force
return $duplicate_rules
}

function Remove-DuplicateFirewallRules
{
<#
.SYNOPSIS
    Removes duplicate firewall rules from the system.

.DESCRIPTION
    This function takes a hashtable of duplicate firewall rules as input and removes it from system. 
    It can perform a test run using the -Test switch to simulate the removal without actually deleting the rules.

.PARAMETER RulesArray
    Specifies a hashtable containing the duplicate firewall rules to be removed.
    The hashtable keys should be the names of the duplicate rules, and the values should be arrays of duplicate rule objects.

.PARAMETER Test
    If specified, the function performs a test run, simulating the removal of duplicate rules without actually executing the removal.

.EXAMPLE
    $duplicates = Find-DuplicateFirewallRules -Action Allow -Direction Outbound -Enabled True
    Remove-DuplicateFirewallRules -RulesArray $duplicates -Test
#>
    param(
        [Parameter(Mandatory)][hashtable]$RulesArray,
        [Parameter()][switch] $Test
    )

    foreach($key in $RulesArray.Keys){
        $rule = $($RulesArray[$key])
        if ($Test)
        {
            Get-NetFirewallRule -Name $($rule.InstanceID) | Remove-NetFirewallRule -WhatIf -OutVariable $null
            Write-Output "Removing $($rule.Name)"
            continue    
        }
        $rule | % {
        Get-NetFirewallRule -Name $($_.InstanceID) | Remove-NetFirewallRule
        
        if (-not (Test-FirewallRuleExist -InstanceID $($_.InstanceID)))
        {
            $text =  "InstanceID: `"$($_.InstanceID)`": Removed :'$($_.Name)'."
        }
        else{
            $text =  "InstanceID: `"$($_.InstanceID)`": Failed to remove :'$($_.Name)'"
        }
        Write-Output $text
        }
        
    }

}

function Test-FirewallRuleExist
{
<#
.SYNOPSIS
    Checks if a firewall rule with the specified InstanceID exists.

.DESCRIPTION
    This function checks if a firewall rule with the specified InstanceID exists in the system.

.PARAMETER InstanceID
    Specifies the InstanceID of the firewall rule to check.

.OUTPUTS
    Returns $true if  rule with the specified InstanceID exists; otherwise, returns $false.

.EXAMPLE
    Test-FirewallRuleExist -InstanceID "MyFirewallRule"
#>
    param(
        [Parameter(Mandatory)][string]$InstanceID
    )
    Try{
        Get-NetFirewallRule -Name $InstanceID -ErrorAction Stop
        return $true
    }

    Catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException]
    {
        return $false    
    }
    Catch
    {
        $_.Exception.GetType().FullName
        return $false
    }
}

function Main
{
<#
.SYNOPSIS
    Main function to find and remove duplicate firewall rules.

.DESCRIPTION
    This function serves as the entry point of the script. It calls the Find-DuplicateFirewallRules function to find duplicate firewall rules and then calls the Remove-DuplicateFirewallRules function to remove the duplicates. The removal can be simulated using the -Test switch.

.EXAMPLE
    Main
#>
    Start-Transcript -Path DuplicateFirewallRulesRemoval.log -Append
    $duplicates = Find-DuplicateFirewallRules -Action Allow -Direction Outbound -Enabled True
    
    # If you'd like to simulate deletion before actually doing it
    # Remove-DuplicateFirewallRules -RulesArray $duplicates -Test

    Remove-DuplicateFirewallRules -RulesArray $duplicates 
    Stop-Transcript
}
Main