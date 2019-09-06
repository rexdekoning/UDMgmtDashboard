$Dashboard = New-UDDashboard -Title "System Information Dashboard" -NavBarColor Green -Content {
    New-UdRow {
        New-UdColumn -Size 12 -Content {
            New-UdTable -Title "Server Information" -Headers @(" ", " ") -Endpoint {
                @{
                    'Computer Name' = $env:COMPUTERNAME
                    'Operating System' = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
                    'Total Disk Space (C:)' = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB | ForEach-Object { "$([Math]::Round($_, 2)) GBs " }
                    'Free Disk Space (C:)' = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB | ForEach-Object { "$([Math]::Round($_, 2)) GBs " }
                }.GetEnumerator() | Out-UDTableData -Property @("Name", "Value")
            }
        }
    }
    New-UDRow {
        New-UDColumn -LargeSize 4 -Content {
            New-UdMonitor -Title "Localhost - CPU (% processor time)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
            }

        }
        New-UDColumn -LargeSize 4 -Content {
            New-UdMonitor -Title "LocalHost - Memory Available %" -Type Line -DataPointHistory 20 -RefreshInterval 60 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                $os = Get-Ciminstance Win32_OperatingSystem
                $pctFree = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)
                $pctFree | Out-UDMonitorData

            }
        }
        New-UDColumn -LargeSize 4 -Content {
            New-UdMonitor -Title "LocalHost - Memory in use %" -Type Line -DataPointHistory 20 -RefreshInterval 30 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                $os = Get-Ciminstance Win32_OperatingSystem
                $pctFree = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)
                (100-$pctFree) | Out-UDMonitorData
            }
        }
        New-UDColumn -LargeSize 4 -Content { }
    } 
    New-UDRow {
        New-UDColumn -LargeSize 4 -Content {
            New-UdMonitor -Title "Network received Kbps" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                $bytesr = (Get-Ciminstance Win32_PerfFormattedData_Tcpip_NetworkInterface)
                (($bytesr.BytesReceivedPersec * 8) | Measure-Object -Sum).Sum/1KB | Out-UDMonitorData
            }

        }
        New-UDColumn -LargeSize 4 -Content {
            New-UdMonitor -Title "Network sent Kbps" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                $bytess = (Get-Ciminstance Win32_PerfFormattedData_Tcpip_NetworkInterface)
                (($bytess.BytesSentPersec * 8) | Measure-Object -Sum).Sum/1KB | Out-UDMonitorData
            }
        }
        New-UDColumn -LargeSize 4 -Content {
            New-UdMonitor -Title "Network total Kbps" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80FF6B63' -ChartBorderColor '#FFFF6B63'  -Endpoint {
                $bytess = (Get-Ciminstance Win32_PerfFormattedData_Tcpip_NetworkInterface)
                (($bytess.BytesTotalPersec * 8) | Measure-Object -Sum).Sum/1KB | Out-UDMonitorData
            }
        }
    }
    New-UdRow {
        New-UdColumn -Size 3 -Content {
            New-UdChart -Title "Memory by Process" -Type Doughnut -RefreshInterval 5 -Endpoint {
                Get-Process | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; WorkingSet = [Math]::Round($_.WorkingSet / 1MB, 2) }} |  Out-UDChartData -DataProperty "WorkingSet" -LabelProperty Name
            } -Options @{
                legend = @{
                    display = $false
                }
            }
        }
        New-UdColumn -Size 3 -Content {
            New-UdChart -Title "CPU by Process" -Type Doughnut -RefreshInterval 5 -Endpoint {
                Get-Process | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; CPU = $_.CPU } } |  Out-UDChartData -DataProperty "CPU" -LabelProperty Name
            } -Options @{
                legend = @{
                    display = $false
                }
            }
        }
        New-UdColumn -Size 3 -Content {
            New-UdChart -Title "Handle Count by Process" -Type Doughnut -RefreshInterval 5 -Endpoint {
                Get-Process | Out-UDChartData -DataProperty "HandleCount" -LabelProperty Name
            } -Options @{
                legend = @{
                    display = $false
                }
            }
        }
        New-UdColumn -Size 3 -Content {
            New-UdChart -Title "Threads by Process" -Type Doughnut -RefreshInterval 5 -Endpoint {
                Get-Process | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Threads = $_.Threads.Count } } |  Out-UDChartData -DataProperty "Threads" -LabelProperty Name
            } -Options @{
                legend = @{
                    display = $false
                }
            }
        }
    }
    New-UdRow {
        New-UdColumn -Size 6 -Content {
            New-UdChart -Title "Disk Space by Drive" -Type Bar -AutoRefresh -Endpoint {
                Get-CimInstance -ClassName Win32_LogicalDisk | ForEach-Object {
                        [PSCustomObject]@{ DeviceId = $_.DeviceID;
                                           Size = [Math]::Round($_.Size / 1GB, 2);
                                           FreeSpace = [Math]::Round($_.FreeSpace / 1GB, 2); } } | Out-UDChartData -LabelProperty "DeviceID" -Dataset @(
                    New-UdChartDataset -DataProperty "Size" -Label "Size" -BackgroundColor "#80962F23" -HoverBackgroundColor "#80962F23"
                    New-UdChartDataset -DataProperty "FreeSpace" -Label "Free Space" -BackgroundColor "#8014558C" -HoverBackgroundColor "#8014558C"
                )
            }
        }
        New-UdColumn -Size 6 -Content {
            New-UdMonitor -Title "Disk (% disk time)" -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor '#80E8611D' -ChartBorderColor '#FFE8611D'  -Endpoint {
                try {
                    Get-Counter '\physicaldisk(_total)\% disk time' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue | Out-UDMonitorData
                }
                catch {
                    0 | Out-UDMonitorData
                }
            }
        }
    }
    New-UdRow {
        New-UdColumn -Size 12 {
            New-UdGrid -Title "Processes" -Headers @("Name", "% CPU TIme") -Properties @("Name", "PercentProcessorTime") -NoExport -NoFilter -AutoRefresh -RefreshInterval 10 -Endpoint {
                Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -filter "PercentProcessorTime > 10" | Sort-Object PercentProcessorTime -Descending | Select-Object -First 10  | ForEach-Object {
                    [PSCustomObject]@{ 
                        Name = $_.Name;
                        PercentProcessorTime = $_.PercentProcessorTime;
                    } 
                } | Out-UDGridData
            }
        }
    }

    New-UdRow {
        New-UdColumn -Size 12 {
            New-UdGrid -Title "Scheduled Tasks" -Headers @("Name", "Last run", "result", "State") -Properties @("Name", "LastRunTime", "LastTaskResult", "State") -NoExport -NoFilter -AutoRefresh -RefreshInterval 10 -Endpoint {
                try {
                Get-ScheduledTask -TaskPath "\" | Get-ScheduledTaskInfo  | ForEach-Object {
                    [PSCustomObject]@{ 
                        Name = $_.TaskName;
                        LastRunTime = $_.LastRunTime;
                        LastTaskResult = "0x{0:x}" -f $_.LastTaskResult;
                        State = (Get-ScheduledTask -TaskName $_.TaskName).State.ToString()
                    } 
                } | Sort-Object -Property state,Name | Out-UDGridData
             } catch { "None" | Out-UDGridData }
            }
        }
    }

    New-UdRow {
        New-UdColumn -Size 12 {
            New-UdGrid -Title "Stopped service where mode=automatic and not delayed and triggered" -Headers @("Name", "State") -Properties @("DisplayName", "State") -NoExport -NoFilter -AutoRefresh -RefreshInterval 10 -Endpoint {
                Get-WmiObject -Class Win32_Service -Filter {State != 'Running' and StartMode = 'Auto'} | ForEach-Object {
                    [PSCustomObject]@{ 
                        DisplayName = $_.DisplayName;
                        Name = $_.Name;
                        StartMode = $_.StartMode;
                        State = $_.State;
                        Delayed = [bool](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)").DelayedAutoStart
                        Triggered = (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\TriggerInfo\").ToString()
                    } 
                } | where-object { $_.State -eq "Stopped" -and $_.Delayed -eq $false -and $_.triggered -eq $false } | Out-UDGridData
            }
        }
    }

    New-UDColumn -LargeSize 4 -Content { }
} 


Get-UDDashboard | Stop-UDDashboard
Start-UDDashboard -Dashboard $Dashboard -Port 10001 -AutoReload

