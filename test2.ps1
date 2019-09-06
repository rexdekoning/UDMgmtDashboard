

Get-WmiObject -Class Win32_Service -Filter {State != 'Running' and StartMode = 'Auto'} | ForEach-Object {
    [PSCustomObject]@{ 
        DisplayName = $_.DisplayName;
        Name = $_.Name;
        StartMode = $_.StartMode;
        State = $_.State;
        Delayed = [bool](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)").DelayedAutoStart
        Triggered = (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\TriggerInfo\").ToString()
    } 
} | where-object { $_.State -eq "Stopped" -and $_.Delayed -eq $false -and $_.triggered -eq $false } | FT
<#
Select-Object -Property DisplayName, Name, StartMode, State



Get-WmiObject -Class Win32_Service -Filter {State != 'Running' and StartMode = 'Auto'} |
ForEach-Object {Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" |
Where-Object {$_.Start -eq 2 -and $_.DelayedAutoStart -ne 1}} |
Select-Object -Property @{label='ServiceName';expression={$_.PSChildName}}
<#
function Get-TriggerStartService {
    [CmdletBinding(DefaultParameterSetName='Name')]
    param (
        [Parameter(ParameterSetName='Name',  Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name = '*',
        [Parameter(ParameterSetName='DisplayName')]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName = '*'
    )
    $Services = Get-WmiObject -Class Win32_Service -Filter "StartMode = 'Auto' and Name like '$($Name -replace '\*', '%')' and DisplayName like '$($DisplayName -replace '\*', '%')'"
    foreach ($Service in $Services) {
        if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.Name)\TriggerInfo\") {
            New-Object -TypeName PSObject -Property @{
                Status = $Service.State
                Name = $Service.Name
                DisplayName = $Service.DisplayName
                StartMode = "$($Service.StartMode) (Trigger Start)"
            }
        }
    }
}

Get-TriggerStartService

#>