<#
.SYNOPSIS  
    PoSH-R2 is a set of Windows Management Instrumentation interface (WMI) scripts that investigators and forensic analysts can use to retrieve information from a 
    compromised (or potentially compromised) Windows system. The scripts use WMI to pull this information from the operating system. Therefore, this script 
    will need to be executed with a user that has the necessary privileges.

    PoSH-R2 will retrieve the following data from an individual machine or a group of systems:       
            - Autorun entries
            - Disk info
            - Environment variables
            - Event logs (50 latest)
            - Installed Software
            - Logon sessions
            - List of drivers
            - List of mapped network drives
            - List of running processes
            - Logged in user
            - Local groups
            - Local user accounts
            - Network configuration
            - Network connections
            - Patches
            - Scheduled tasks with AT command
            - Shares
            - Services
            - System Information

.EXAMPLE
    .\posh_r2.ps1

.NOTES  
    File Name      : PoSH-R2.ps1
    Version        : v.0.2
    Author         : @WiredPulse
    Prerequisite   : PowerShell
    Created        : 10 Oct 16
#>


# ==============================================================================
# Function Name 'ListComputers' - Takes entered domain and lists all computers
# ==============================================================================
Function ListComputers
{
    $DN = ""
    $Response = ""
    $DNSName = ""
    $DNSArray = ""
    $objSearcher = ""
    $colProplist = ""
    $objComputer = ""
    $objResults = ""
    $colResults = ""
    $Computer = ""
    $comp = ""
    New-Item -type file -force "$Script:Folder_Path\Computer_List_$Script:curDate.txt" | Out-Null
    $Script:Compute = "$Script:Folder_Path\Computer_List_$Script:curDate.txt"
    $strCategory = "(ObjectCategory=Computer)"
    
    Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
    Write-Host "Auto pull uses the current domain you are on, if you need to select a different domain use manual."
    $response = Read-Host = "[1] Auto Pull, [2] Manual Selection"
    
    If($Response -eq "1") {
        $DNSName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        If($DNSName -ne $Null) {
            $DNSArray = $DNSName.Split(".") 
            for ($x = 0; $x -lt $DNSArray.Length ; $x++) {  
                if ($x -eq ($DNSArray.Length - 1)){$Separator = ""}else{$Separator =","} 
                [string]$DN += "DC=" + $DNSArray[$x] + $Separator  } }
        $Script:Domain = $DN
        echo "Pulled computers from: "$Script:Domain 
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$Script:Domain")
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        foreach ($i in $colPropList) {
            $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
	elseif($Response -eq "2")
    {
        Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
        Write-Host "Auto pull uses the current domain you are on, if you need to select a different domain use manual."
        $Script:Domain = Read-Host "Enter your Domain here: OU=West,DC=Company,DC=com"
        If ($Script:Domain -eq $Null) {Write-Host "You did not provide a valid response."; . ListComputers}
        echo "Pulled computers from: "$Script:Domain 
        $objOU = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Script:Domain")
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objOU
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        foreach ($i in $colPropList) { $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
    else {
        Write-Host "You did not supply a correct response, Please select a response." -foregroundColor Red
        . ListComputers }
}

# ==============================================================================
# Function Name 'ListTextFile' - Enumerates Computer Names in a text file
# Create a text file and enter the names of each computer. One computer
# name per line. Supply the path to the text file when prompted.
# ==============================================================================
Function ListTextFile 
{
	$file_Dialog = ""
    $file_Name = ""
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $file_Dialog = New-Object system.windows.forms.openfiledialog
    $file_Dialog.InitialDirectory = "$env:USERPROFILE\Desktop"
    $file_Dialog.MultiSelect = $false
    $file_Dialog.showdialog()
    $file_Name = $file_Dialog.filename
    $Comps = Get-Content $file_Name
    If ($Comps -eq $Null) {
        Write-Host "Your file was empty. You must select a file with at least one computer in it." -Fore Red
        . ListTextFile }
    Else
    {
        $Script:Computers = @()
        ForEach ($Comp in $Comps)
        {
            If ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
            {
                $Temp = $Comp.Split("/")
                $IP = $Temp[0]
                $Mask = $Temp[1]
                . Get-Subnet-Range $IP $Mask
                $Script:Computers += $Script:IPList
            }
            Else
            {
                $Script:Computers += $Comp
            }
        }

        
    }
}

Function Get-Subnet-Range {
    #.Synopsis
    # Lists all IPs in a subnet.
    #.Example
    # Get-Subnet-Range -IP 192.168.1.0 -Netmask /24
    #.Example
    # Get-Subnet-Range -IP 192.168.1.128 -Netmask 255.255.255.128        
    Param(
        [string]
        $IP,
        [string]
        $netmask
    )  
    Begin {
        $IPs = New-Object System.Collections.ArrayList

        Function Get-NetworkAddress {
            #.Synopsis
            # Get the network address of a given lan segment
            #.Example
            # Get-NetworkAddress -IP 192.168.1.36 -mask 255.255.255.0
            Param (
                [string]
                $IP,
               
                [string]
                $Mask,
               
                [switch]
                $Binary
            )
            Begin {
                $NetAdd = $null
            }
            Process {
                $BinaryIP = ConvertTo-BinaryIP $IP
                $BinaryMask = ConvertTo-BinaryIP $Mask
                0..34 | %{
                    $IPBit = $BinaryIP.Substring($_,1)
                    $MaskBit = $BinaryMask.Substring($_,1)
                    IF ($IPBit -eq '1' -and $MaskBit -eq '1') {
                        $NetAdd = $NetAdd + "1"
                    } elseif ($IPBit -eq ".") {
                        $NetAdd = $NetAdd +'.'
                    } else {
                        $NetAdd = $NetAdd + "0"
                    }
                }
                if ($Binary) {
                    return $NetAdd
                } else {
                    return ConvertFrom-BinaryIP $NetAdd
                }
            }
        }
       
        Function ConvertTo-BinaryIP {
            #.Synopsis
            # Convert an IP address to binary
            #.Example
            # ConvertTo-BinaryIP -IP 192.168.1.1
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                Foreach ($octet in $IP.split('.')) {
                    $strout = $null
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            [string]$strout = $strout + "1"
                        } else {
                            [string]$strout = $strout + "0"
                        }  
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }
 
 
        Function ConvertFrom-BinaryIP {
            #.Synopsis
            # Convert from Binary to an IP address
            #.Example
            # Convertfrom-BinaryIP -IP 11000000.10101000.00000001.00000001
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                Foreach ($octet in $IP.split('.')) {
                    $strout = 0
                    0..7|% {
                        $bit = $octet.Substring(($_),1)
                        IF ($bit -eq 1) {
                            $strout = $strout + [math]::pow(2,(7-$_))
                        }
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }

        Function ConvertTo-MaskLength {
            #.Synopsis
            # Convert from a netmask to the masklength
            #.Example
            # ConvertTo-MaskLength -Mask 255.255.255.0
            Param (
                [string]
                $mask
            )
            Process {
                $out = 0
                Foreach ($octet in $Mask.split('.')) {
                    $strout = 0
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            $out++
                        }
                    }
                }
                return $out
            }
        }
 
        Function ConvertFrom-MaskLength {
            #.Synopsis
            # Convert from masklength to a netmask
            #.Example
            # ConvertFrom-MaskLength -Mask /24
            #.Example
            # ConvertFrom-MaskLength -Mask 24
            Param (
                [int]
                $mask
            )
            Process {
                $out = @()
                [int]$wholeOctet = ($mask - ($mask % 8))/8
                if ($wholeOctet -gt 0) {
                    1..$($wholeOctet) |%{
                        $out += "255"
                    }
                }
                $subnet = ($mask - ($wholeOctet * 8))
                if ($subnet -gt 0) {
                    $octet = 0
                    0..($subnet - 1) | %{
                         $octet = $octet + [math]::pow(2,(7-$_))
                    }
                    $out += $octet
                }
                for ($i=$out.count;$i -lt 4; $I++) {
                    $out += 0
                }
                return [string]::join('.',$out)
            }
        }

        Function Get-IPRange {
            #.Synopsis
            # Given an Ip and subnet, return every IP in that lan segment
            #.Example
            # Get-IPRange -IP 192.168.1.36 -Mask 255.255.255.0
            #.Example
            # Get-IPRange -IP 192.168.5.55 -Mask /23
            Param (
                [string]
                $IP,
               
                [string]
                $netmask
            )
            Process {
                iF ($netMask.length -le 3) {
                    $masklength = $netmask.replace('/','')
                    $Subnet = ConvertFrom-MaskLength $masklength
                } else {
                    $Subnet = $netmask
                    $masklength = ConvertTo-MaskLength -Mask $netmask
                }
                $network = Get-NetworkAddress -IP $IP -Mask $Subnet
               
                [int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $network.split('.')
                $TotalIPs = ([math]::pow(2,(32-$masklength)) -2)
                $blocks = ($TotalIPs - ($TotalIPs % 256))/256
                if ($Blocks -gt 0) {
                    1..$blocks | %{
                        0..255 |%{
                            if ($FourthOctet -eq 255) {
                                If ($ThirdOctet -eq 255) {
                                    If ($SecondOctet -eq 255) {
                                        $FirstOctet++
                                        $secondOctet = 0
                                    } else {
                                        $SecondOctet++
                                        $ThirdOctet = 0
                                    }
                                } else {
                                    $FourthOctet = 0
                                    $ThirdOctet++
                                }  
                            } else {
                                $FourthOctet++
                            }
                            Write-Output ("{0}.{1}.{2}.{3}" -f `
                            $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                        }
                    }
                }
                $sBlock = $TotalIPs - ($blocks * 256)
                if ($sBlock -gt 0) {
                    1..$SBlock | %{
                        if ($FourthOctet -eq 255) {
                            If ($ThirdOctet -eq 255) {
                                If ($SecondOctet -eq 255) {
                                    $FirstOctet++
                                    $secondOctet = 0
                                } else {
                                    $SecondOctet++
                                    $ThirdOctet = 0
                                }
                            } else {
                                $FourthOctet = 0
                                $ThirdOctet++
                            }  
                        } else {
                            $FourthOctet++
                        }
                        Write-Output ("{0}.{1}.{2}.{3}" -f `
                        $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                    }
                }
            }
        }
    }
    Process {
        #get every ip in scope
        Get-IPRange $IP $netmask | %{
        [void]$IPs.Add($_)
        }
        $Script:IPList = $IPs
    }
}

# ==============================================================================
# Function Name 'SingleEntry' - Enumerates Computer from user input
# ==============================================================================
Function SingleEntry 
{
    $Comp = Read-Host "Enter Computer Name or IP (1.1.1.1) or IP Subnet (1.1.1.1/24)"
    If ($Comp -eq $Null) { . SingleEntry } 
    ElseIf ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
    {
        $Temp = $Comp.Split("/")
        $IP = $Temp[0]
        $Mask = $Temp[1]
        . Get-Subnet-Range $IP $Mask
        $Script:Computers = $Script:IPList
    }
    Else
    { $Script:Computers = $Comp}
}

Write-Host "  ______                   _______  __    __          ______      ___    " -ForegroundColor Green
Write-Host " |   _  \                 /      | |  |  |  |        |   _  \    |__ \   " -ForegroundColor Green
Write-Host " |  |_)  |   ______      |   (---- |  |__|  |  ______|  |_)  |      ) |  " -ForegroundColor Green
Write-Host " |   ___/   /  __  \      \   \    |   __   | |______|      /      / /   " -ForegroundColor Green
Write-Host " |  |      |  |__|  | |----)   |   |  |  |  |        |  |\  \-----/ /_   " -ForegroundColor Green
Write-Host " | _|       \______/  |_______/    |__|  |__|        | _| \_____|_____|  " -ForegroundColor Green
Write-Host ""

Write-Host "How do you want to list computers?"	-ForegroundColor yellow
$strResponse = Read-Host "`n[1] All Domain Computers (Must provide Domain), `n[2] Computer names from a File, `n[3] List a Single Computer manually `n"
If($strResponse -eq "1"){. ListComputers | Sort-Object}
	elseif($strResponse -eq "2"){. ListTextFile}
	elseif($strResponse -eq "3"){. SingleEntry}
	else{Write-Host "You did not supply a correct response, `
	Please run script again."; pause -foregroundColor Red}				

Write-Host "Got computer list... Next task..." -ForegroundColor yellow

mkdir .\PoSH_R2--Results | Out-Null
mkdir .\PoSH_R2--Results\connects | Out-Null
Set-Location .\PoSH_R2--Results
# ==============================================================================
# Autorun information
# ==============================================================================
Write-Host "Retrieving Autoruns information..." -ForegroundColor yellow
Get-WmiObject -Class win32_startupcommand -ComputerName $computers | select PSComputername, Name, Location, Command, User | Export-CSV ./Autoruns.csv -NoTypeInformation

# ==============================================================================
# Logon information
# ==============================================================================
Write-Host "Retrieving logon information..." -ForegroundColor yellow
Get-WmiObject -Class win32_networkloginprofile -ComputerName $computers | select PSComputername,Name, LastLogon,LastLogoff,NumberOfLogons,PasswordAge | Export-CSV .\NetLogon.csv -NoTypeInformation

# ==============================================================================
# Event log information (Note: If logs are not returning data, ensure the script 
# is not ran from the ISE console)
# ==============================================================================
Write-Host "Retrieving event log information..." -ForegroundColor yellow
Get-WmiObject -Class win32_ntlogevent | where {$_.LogFile -eq 'System'} | select PSComputername, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type | select -first 50 | Export-CSV .\Eventlogs-System.csv -NoTypeInformation
Get-WmiObject -Class win32_ntlogevent | where {$_.LogFile -eq 'Security'} | select PSComputername, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type | select -first 50 | Export-CSV .\Eventlogs-Security.csv -NoTypeInformation
Get-WmiObject -Class win32_ntlogevent | where {$_.LogFile -eq 'Application'} | select PSComputername, LogFile, EventCode, TimeGenerated, Message, InsertionStrings, Type | select -first 50 | Export-CSV .\Eventlogs-Application.csv -NoTypeInformation

# ==============================================================================
# Driver information
# ==============================================================================
Write-Host "Retrieving driver information..." -ForegroundColor yellow
Get-WmiObject -Class win32_systemdriver -ComputerName $computers | select PSComputername, Name, InstallDate, DisplayName, PathName, State, StartMode | Export-CSV .\Drivers.csv -NoTypeInformation

# ==============================================================================
# Mapped drives information
# ==============================================================================
Write-Host "Retrieving mapped drives information..." -ForegroundColor yellow
Get-WmiObject -Class win32_mappedlogicaldisk -ComputerName $computers | select PSComputername, Name, ProviderName | Export-CSV .\Mapped_Drives.csv -NoTypeInformation

# ==============================================================================
# Process information
# ==============================================================================
Write-Host "Retrieving running processes information..." -ForegroundColor yellow
Get-WmiObject -Class win32_process -ComputerName $computers | select PSComputername, Name, Description, ProcessID, ParentProcessID, Handle, HandleCount, ThreadCount, CreationDate | Export-CSV .\Processes.csv -NoTypeInformation

# ==============================================================================
# Scheduled tasks
# ==============================================================================
Write-Host "Retrieving scheduled tasks created by at.exe or Win32_ScheduledJob..." -ForegroundColor yellow
Get-WmiObject -Class win32_scheduledjob -ComputerName $computers | select PSComputername, Name, Owner, JodID, Command, RunRepeatedly, InteractWithDesktop | Export-CSV .\Scheduled_Tasks.csv -NoTypeInformation

# ==============================================================================
# Services
# ==============================================================================
Write-Host "Retrieving service information..." -ForegroundColor yellow
Get-WmiObject -Class win32_service -ComputerName $computers | select PSComputername, ProcessID, Name, Description, PathName, Started, StartMode, StartName, State | Export-CSV .\Services.csv -NoTypeInformation

# ==============================================================================
# Environment variables
# ==============================================================================
Write-Host "Retrieving environment variables information..." -ForegroundColor yellow
Get-WmiObject -Class win32_environment -ComputerName $computers | select PSComputername, UserName, Name, VariableValue | Export-CSV .\Environment_Variables.csv -NoTypeInformation

# ==============================================================================
# User information
# ==============================================================================
Write-Host "Retrieving user information..." -ForegroundColor yellow
Get-WmiObject -Class win32_useraccount -ComputerName $computers | select PSComputername, accounttype, name, fullname, domain, disabled, localaccount, lockout, passwordchangeable, passwordexpires, sid | Export-CSV .\Users.csv -NoTypeInformation

# ==============================================================================
# Group information
# ==============================================================================
Write-Host "Retrieving group information..." -ForegroundColor yellow
Get-WmiObject -Class win32_group -ComputerName $computers |select PSComputername, Caption, Domain, Name, Sid | Export-CSV .\Groups.csv -NoTypeInformation

# ==============================================================================
# Logged in user
# ==============================================================================
Write-Host "Retrieving loggedon user information..." -ForegroundColor yellow
Get-WmiObject -Class win32_computersystem -ComputerName $computers | select PSComputername, Username | Export-CSV .\Logged_on_User.csv -NoTypeInformation

# ==============================================================================
# Network settings
# ==============================================================================
Write-Host "Retrieving network configurations..." -ForegroundColor yellow
Get-WmiObject -Class win32_networkadapterconfiguration -ComputerName $computers | select PSComputername, IPAddress, IPSubnet, DefaultIPGateway, DHCPServer, DNSHostname, DNSserversearchorder, MACAddress, description| Export-CSV .\Network_Configs.csv -NoTypeInformation

# ==============================================================================
# Shares
# ==============================================================================
Write-Host "Retrieving shares information..." -ForegroundColor yellow
Get-WmiObject -Class win32_share -ComputerName $computers |select PSComputername, Name, Path, Description | Export-CSV .\Shares.csv -NoTypeInformation

# ==============================================================================
# Disk information
# ==============================================================================
Write-Host "Retrieving disk information..." -ForegroundColor yellow
Get-WmiObject -Class win32_logicaldisk -ComputerName $computers | select PSComputername, DeviceID, Description, ProviderName | Export-CSV .\Disk.csv -NoTypeInformation

# ==============================================================================
# System information
# ==============================================================================
Write-Host "Retrieving system information..." -ForegroundColor yellow
Get-WmiObject -Class win32_computersystem -ComputerName $computers | select PSComputername, Domain, Model, Manufacturer, EnableDaylightSavingsTime, PartOfDomain, Roles, SystemType, NumberOfProcessors, TotalPhysicalMemory, Username | Export-CSV .\System_Info.csv -NoTypeInformation

# ==============================================================================
# Patch information
# ==============================================================================
Write-Host "Retrieving installed patch information..." -ForegroundColor yellow
Get-WmiObject -Class win32_quickfixengineering -ComputerName $computers | select PSComputername, HotFixID, Description, InstalledBy, InstalledOn | Export-CSV .\Patches.csv -NoTypeInformation

# ==============================================================================
# Installed Software
# ==============================================================================
Write-Host "Retrieving installed software information..." -ForegroundColor yellow
Get-WmiObject -Class win32_product -ComputerName $computers | select PSComputername, Name, PackageCache, Vendor, Version, IdentifyingNumber | Export-CSV .\Software.csv -NoTypeInformation

set-location .\connects

# ==============================================================================
# Network connections
# ==============================================================================
Write-Host "Retrieving network connections..." -ForegroundColor yellow
foreach($computer in $computers){
Invoke-WmiMethod -Class Win32_Process -Name Create -Computername $computer -ArgumentList "cmd /c netstat -ano > c:\$computer.txt" >$null 2>&1
copy-item \\$computer\c$\$computer.txt .\
$conn = get-content .\$computer.txt
$conn2 = $conn | foreach {$computer + $_}
$conn2 | select -skip 4 | out-file .\$computer'_'.txt
remove-item .\$computer.txt
}

# ==============================================================================
# Combining network connection files
# ==============================================================================
cd ..
Get-Content .\connects\*.txt | out-file .\Connections.csv

# ==============================================================================
# Cleaning up
# ==============================================================================
remove-item .\connects -recurse -force
remove-item \\$computer\c$\$computer.txt 




