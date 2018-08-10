<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2016 v5.2.128
	 Created on:   	16/09/2016 13:49
	 Created by:   	e0056585
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>

Import-Module ActiveDirectory

function pcSerialNumber
{
	#PC Serial Number 
	gwmi -computer $compname Win32_BIOS | Select-Object SerialNumber | Format-List
	pressAnyKey
	CheckHost
}

function pcPrinterInformation
{
	#PC Printer Information 
	gwmi -computer $compname Win32_Printer | Select-Object DeviceID, DriverName, PortName | Format-List
	pressAnyKey
	CheckHost
}

function currentUser
{
	#Current User 
	gwmi -computer $compname Win32_ComputerSystem | Format-Table @{ Expression = { $_.Username }; Label = "Current User" }
	[Environment]::NewLine
	
	pressAnyKey
	CheckHost
}

function osInfo
{
	#OS Info 
	gwmi -computer $compname Win32_OperatingSystem | Format-List @{ Expression = { $_.Caption }; Label = "OS Name" }, SerialNumber, OSArchitecture
	pressAnyKey
	CheckHost
}

function systemInfo
{
	#System Info 
	gwmi -computer $compname Win32_ComputerSystem | Format-List Name, Domain, Manufacturer, Model, SystemType
	pressAnyKey
	CheckHost
}

function processList
{
	#Process List
	gwmi -computer $compname Win32_Process | Select-Object Caption, Handle | Sort-Object Caption | Format-Table
	pressAnyKey
	CheckHost
}

function serviceList
{
	#Service List 
	gwmi -computer $compname Win32_Service | Select-Object Name, State, Status, StartMode, ProcessID, ExitCode | Sort-Object Name | Format-Table
	pressAnyKey
	CheckHost
}

function usbDevices
{
	#USB Devices 
	gwmi -computer $compname Win32_USBControllerDevice | %{ [wmi]($_.Dependent) } | Select-Object Caption, Manufacturer, DeviceID | Format-List
	pressAnyKey
	CheckHost
}

function upTime
{
	#Uptime 
	$wmi = gwmi -computer $compname Win32_OperatingSystem
	$localdatetime = $wmi.ConvertToDateTime($wmi.LocalDateTime)
	$lastbootuptime = $wmi.ConvertToDateTime($wmi.LastBootUpTime)
	
	"Current Time:      $localdatetime"
	"Last Boot Up Time: $lastbootuptime"
	
	$uptime = $localdatetime - $lastbootuptime
	[Environment]::NewLine
	"Uptime: $uptime"
	pressAnyKey
	CheckHost
}

function diskInfo
{
	#Disk Info 
	$wmi = gwmi -computer $compname Win32_logicaldisk
	foreach ($device in $wmi)
	{
		Write-Host "Drive: " $device.name
		Write-Host -NoNewLine "Size: "; "{0:N2}" -f ($device.Size/1Gb) + " Gb"
		Write-Host -NoNewLine "FreeSpace: "; "{0:N2}" -f ($device.FreeSpace/1Gb) + " Gb"
		[Environment]::NewLine
	}
	pressAnyKey
	CheckHost
}

function memoryInfo
{
	#Memory Info 
	$wmi = gwmi -computer $compname Win32_PhysicalMemory
	foreach ($device in $wmi)
	{
		Write-Host "Bank Label:     " $device.BankLabel
		Write-Host "Capacity:       " ($device.Capacity/1MB) "Mb"
		Write-Host "Data Width:     " $device.DataWidth
		Write-Host "Device Locator: " $device.DeviceLocator
		[Environment]::NewLine
	}
	pressAnyKey
	CheckHost
}

function processorInfo
{
	#Processor Info 
	gwmi -computer $compname Win32_Processor | Format-List Caption, Name, Manufacturer, ProcessorId, NumberOfCores, AddressWidth
	pressAnyKey
	CheckHost
}

function monitorInfo
{
	#Monitor Info 
	
	#Turn off Error Messages 
	$ErrorActionPreference_Backup = $ErrorActionPreference
	$ErrorActionPreference = "SilentlyContinue"
	
	$keytype = [Microsoft.Win32.RegistryHive]::LocalMachine
	if ($reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($keytype, $compname))
	{
		#Create Table To Hold Info 
		$montable = New-Object system.Data.DataTable "Monitor Info"
		#Create Columns for Table 
		$moncol1 = New-Object system.Data.DataColumn Name, ([string])
		$moncol2 = New-Object system.Data.DataColumn Serial, ([string])
		$moncol3 = New-Object system.Data.DataColumn Ascii, ([string])
		#Add Columns to Table 
		$montable.columns.add($moncol1)
		$montable.columns.add($moncol2)
		$montable.columns.add($moncol3)
		
		$regKey = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\DISPLAY")
		$HID = $regkey.GetSubKeyNames()
		foreach ($HID_KEY_NAME in $HID)
		{
			$regKey = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\$HID_KEY_NAME")
			$DID = $regkey.GetSubKeyNames()
			foreach ($DID_KEY_NAME in $DID)
			{
				$regKey = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\$HID_KEY_NAME\\$DID_KEY_NAME\\Device Parameters")
				$EDID = $regKey.GetValue("EDID")
				foreach ($int in $EDID)
				{
					$EDID_String = $EDID_String + ([char]$int)
				}
				#Create new row in table 
				$monrow = $montable.NewRow()
				
				#MonitorName 
				$checkstring = [char]0x00 + [char]0x00 + [char]0x00 + [char]0xFC + [char]0x00
				$matchfound = $EDID_String -match "$checkstring([\w ]+)"
				if ($matchfound) { $monrow.Name = [string]$matches[1] }
				else { $monrow.Name = '-' }
				
				
				#Serial Number 
				$checkstring = [char]0x00 + [char]0x00 + [char]0x00 + [char]0xFF + [char]0x00
				$matchfound = $EDID_String -match "$checkstring(\S+)"
				if ($matchfound) { $monrow.Serial = [string]$matches[1] }
				else { $monrow.Serial = '-' }
				
				#AsciiString 
				$checkstring = [char]0x00 + [char]0x00 + [char]0x00 + [char]0xFE + [char]0x00
				$matchfound = $EDID_String -match "$checkstring([\w ]+)"
				if ($matchfound) { $monrow.Ascii = [string]$matches[1] }
				else { $monrow.Ascii = '-' }
			    
				$EDID_String = ''
				
				$montable.Rows.Add($monrow)
			}
		}
		$montable | select-object -unique Serial, Name, Ascii | Where-Object { $_.Serial -ne "-" } | Format-Table
	}
	else
	{
		Write-Host "Access Denied - Check Permissions"
	}
	$ErrorActionPreference = $ErrorActionPreference_Backup #Reset Error Messages 
	pressAnyKey
	CheckHost
}

function GetCompName
{
	$compname = Read-Host "Enter Remote IP / Terminal Name"
	CheckHost
}

function CheckHost
{
	$ping = gwmi Win32_PingStatus -filter "Address='$compname'"
	if ($ping.StatusCode -eq 0) { $pcip = $ping.ProtocolAddress; GetMenu }
	else { Pause "Host $compname down...Press any key to continue"; GetCompName }
}

function GetMenu
{
	Clear-Host
	displayVersion
	
	"  /----------------------\"
	"  |     PC INFO TOOL     |"
	"  \----------------------/"
	"  $compname ($pcip)"
	""
	""
	"1) PC Serial Number"
	"2) PC Printer Info"
	"3) Current User"
	"4) OS Info"
	"5) System Info"
	"6) Process List"
	"7) Service List"
	"8) USB Devices"
	"9) Uptime"
	"10) Disk Space"
	"11) Memory Info"
	"12) Processor Info"
	"13) Monitor Serial Numbers"
	"14) Do all and dump to txt file"
	""
	
	"X) Exit the program"
	""
	$MenuSelection = Read-Host "Enter Selection"
	GetInfo
}

function GetInfo
{
	Clear-Host
	switch ($MenuSelection)
	{
		1 {
			#PC Serial Number 
			pcSerialNumber
		}
		
		2 {
			#PC Printer Information 
			pcPrinterInformation
		}
		
		3 {
			#Current User 
			currentUser
		}
		
		4 {
			#OS Info 
			osInfo
		}
		
		5 {
			#System Info 
			systemInfo
		}
		
		6 {
			#Process Listx 
			processList
		}
		
		7 {
			#Service List 
			serviceList
		}
		
		8 {
			#USB Devices 
			usbDevices
		}
		
		9 {
			#Uptime 
			upTime
		}
		
		10 {
			#Disk Info 
			diskInfo
		}
		
		11 {
			#Memory Info 
			memoryInfo
		}
		
		12 {
			#Processor Info 
			processorInfo
		}
		
		13 {
			#Monitor Info 
			monitorInfo
		}
		
		14 {
			# Carry out all 13 functions and output to text file 
			notImplementedYet
		}
		
		x { Clear-Host; return }
		default { CheckHost }
	}
}

function pressAnyKey
{
	# Wait for user to press any key to continue, gives user time to read output
	textSeperateLine -inputString "Press any key to continue..."
	$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
}

function textSeperateLine
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$inputString
	)
	
	[Environment]::NewLine
	Write-Host $inputString
	[Environment]::NewLine
}

function Write-Color([String[]]$Text, [ConsoleColor[]]$Color = "White", [int]$StartTab = 0, [int]$LinesBefore = 0, [int]$LinesAfter = 0)
{
	$DefaultColor = $Color[0]
	if ($LinesBefore -ne 0) { for ($i = 0; $i -lt $LinesBefore; $i++) { Write-Host "`n" -NoNewline } } # Add empty line before
	if ($StartTab -ne 0) { for ($i = 0; $i -lt $StartTab; $i++) { Write-Host "`t" -NoNewLine } } # Add TABS before text
	if ($Color.Count -ge $Text.Count)
	{
		for ($i = 0; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
	}
	else
	{
		for ($i = 0; $i -lt $Color.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $Color[$i] -NoNewLine }
		for ($i = $Color.Length; $i -lt $Text.Length; $i++) { Write-Host $Text[$i] -ForegroundColor $DefaultColor -NoNewLine }
	}
	Write-Host
	if ($LinesAfter -ne 0) { for ($i = 0; $i -lt $LinesAfter; $i++) { Write-Host "`n" } } # Add empty line after
}

function genPass
{
	
	$passFirstString = Read-Host "Enter a memorable word: "
	$passLength = Read-Host "Enter length of password: "
	
	$passDictionary = ("Arnold", "Clark", "Password", "Holiday", "Airport", "Showroom", "October", "August", ""  )
	
	
	
	
}

Function stringToPhonetic
{
	##### ** THIS SCRIPT IS PROVIDED WITHOUT WARRANTY, USE AT YOUR OWN RISK **
	
<#
.SYNOPSIS
    Converts an alphanumeric string into the NATO Phonetic Alphabet equivalent.

.DESCRIPTION
    The advanced function will convert an alphanumeric string into the NATO phonetic alphabet.
	
.PARAMETER String
    This is the default, required parameter. It is the string that the advanced function will convert.

.EXAMPLE
    Convert-TMNatoAlphabet -String '12abc3'
    This example will convert the string, 12abc3, to its NATO phonetic alphabet equivalent. It will return, "One Two Alpha Bravo Charlie Three."

.EXAMPLE
    Convert-TMNatoAlphabet -String '1p2h3-cc'
    This example will attempt to convert the string, 1p2h3-cc, to its NATO phonetic alphabet equivalent. Since it contains an invalid character (-), it will return, "String contained illegal character(s)."

.EXAMPLE
    Convert-TMNatoAlphabet '1ph3cc'
    This example will convert the string, 1ph3cc, to its NATO phonetic alphabet equivalent. It will return, "One Papa Hotel Three Charlie Charlie."

.EXAMPLE
    Convert-TMNatoAlphabet '1ph3cc' -Speak
    This example will convert the string, 1ph3cc, to its NATO phonetic alphabet equivalent. It will return, "One Papa Hotel Three Charlie Charlie." In addition, it will speak the results.

.NOTES
    NAME: Convert-TMNatoAlphabet
    AUTHOR: Tommy Maynard
    LASTEDIT: 08/21/2014
    VERSION 1.1
        -Changed seperate alpha and numeric hashes into one, alphanumeric hash (numbers are being stored as strings).
    VERSION 1.2
        -Edited the logic that handles the conversion (no need for If and nested If - Initial If handles a-z 0-9 check).
        -Added string cleanup inside If statement.
    VERSION 1.3
        -Added switch parameter to speak the results, as well.
#>
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, Position = 0)]
		[string]$String,
		[switch]$Speak
	)
	
	Begin
	{
		Write-Verbose -Message 'Creating alphanumeric hash table'
		$Hash = @{ 'A' = ' Alpha '; 'B' = ' Bravo '; 'C' = ' Charlie '; 'D' = ' Delta '; 'E' = ' Echo '; 'F' = ' Foxtrot '; 'G' = ' Golf '; 'H' = ' Hotel '; 'I' = ' India '; 'J' = ' Juliet '; 'K' = ' Kilo '; 'L' = ' Lima '; 'M' = ' Mike '; 'N' = ' November '; 'O' = ' Oscar '; 'P' = ' Papa '; 'Q' = ' Quebec '; 'R' = ' Romeo '; 'S' = ' Sierra '; 'T' = ' Tango '; 'U' = ' Uniform '; 'V' = ' Victory '; 'W' = ' Whiskey '; 'X' = ' X-ray '; 'Y' = ' Yankee '; 'Z' = ' Zulu '; '0' = ' Zero '; '1' = ' One '; '2' = ' Two '; '3' = ' Three '; '4' = ' Four '; '5' = ' Five '; '6' = ' Six '; '7' = ' Seven '; '8' = ' Eight '; '9' = ' Nine ' }
		
	} # End Begin
	
	Process
	{
		Write-Verbose -Message 'Checking string for illegal charcters'
		If ($String -match '^[a-zA-Z0-9]+$')
		{
			Write-Verbose -Message 'String does not have any illegal characters'
			$String = $String.ToUpper()
			
			Write-Verbose -Message 'Creating converted string'
			For ($i = 0; $i -le $String.Length; $i++)
			{
				[string]$Character = $String[$i]
				$NewString += $Hash.Get_Item($Character)
			}
			
			Write-Verbose -Message 'Cleaning up converted string'
			$NewString = ($NewString.Trim()).Replace('  ', ' ')
			Write-Output $NewString
			
			If ($Speak)
			{
				Add-Type -AssemblyName System.Speech
				$Voice = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
				$Voice.Speak($NewString)
			}
			
		}
		Else
		{
			Write-Output -Verbose 'String contained illegal character(s).'
		}
	} # End Process
} # End Function

function displayVersion
{
	Write-Host ("-------------------------------------------------------------------------") 
	#Write-Host ("|			IT Support Tool					|") -ForegroundColor Cyan
	#Write-Host ("|	IT Support Tool - Version 1.07 - LW - 20/09/2016 - E0056585	|") -ForegroundColor Cyan
	#Write-Host ("|	IT Support Tool - Version 1.07 - LW - 20/09/2016 - E0056585	|") -ForegroundColor Cyan
	Write-Host ("|	IT Support Tool - Version 1.07 - LW - 21/09/2016 - E0056585	|")
	Write-Host ("-------------------------------------------------------------------------")
    [Environment]::NewLine
}

Function Get-LockedOutLocation
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$Identity
	)
	
	Begin
	{
		$DCCounter = 0
		$LockedOutStats = @()
		
	} #end begin 
	Process
	{
		#Get all domain controllers in domain 
		$DomainControllers = Get-ADDomainController -Filter *
		$PDCEmulator = ($DomainControllers | Where-Object { $_.OperationMasterRoles -contains "PDCEmulator" })
		
		Write-Verbose "Finding the domain controllers in the domain"
		Foreach ($DC in $DomainControllers)
		{
			$DCCounter++
			#Write-Progress -Activity "Contacting DCs for lockout info" -Status "Querying $($DC.Hostname)" -PercentComplete (($DCCounter/$DomainControllers.Count) * 100)
			Try
			{
				$UserInfo = Get-ADUser -Identity $Identity -Server $DC.Hostname -Properties AccountLockoutTime, LastBadPasswordAttempt, BadPwdCount, LockedOut -ErrorAction Stop
			}
			Catch
			{
				Write-Warning $_
				Continue
			}
			If ($UserInfo.LastBadPasswordAttempt)
			{
				$LockedOutStats += New-Object -TypeName PSObject -Property @{
					Name = $UserInfo.SamAccountName
					SID = $UserInfo.SID.Value
					LockedOut = $UserInfo.LockedOut
					BadPwdCount = $UserInfo.BadPwdCount
					BadPasswordTime = $UserInfo.BadPasswordTime
					DomainController = $DC.Hostname
					AccountLockoutTime = $UserInfo.AccountLockoutTime
					LastBadPasswordAttempt = ($UserInfo.LastBadPasswordAttempt).ToLocalTime()
				}
			} #end if 
		} #end foreach DCs 
		$LockedOutStats | Format-Table -Property Name, LockedOut, BadPwdCount, AccountLockoutTime, LastBadPasswordAttempt -Wrap
		
		#Get User Info 
		Try
		{
			Write-Verbose "Querying event log on $($PDCEmulator.HostName)"
			$LockedOutEvents = Get-WinEvent -ComputerName $PDCEmulator.HostName -FilterHashtable @{ LogName = 'Security'; Id = 4740 } -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending
		}
		Catch
		{
			Write-Warning $_
			Continue
		} #end catch      
		
		Write-Host ("---------------------------------------------------------------------")
		Write-Host ("                      Locked Terminals")
		Write-Host ("---------------------------------------------------------------------")
		
		$counterTime = 0
		
		Foreach ($Event in $LockedOutEvents)
		{
			If ($Event | Where { $_.Properties[2].value -match $UserInfo.SID.Value })
			{
				$counterTime = $counterTime + 1
				Write-Host ("---------------------------------------------") -ForegroundColor White
				Write-Host ("Locked Terminal $counterTime") -ForegroundColor Cyan
				Write-Host ("---------------------------------------------") -ForegroundColor White
				$Event | Select-Object -Property @(
					@{ Label = 'User'; Expression = { $_.Properties[0].Value } }
					#@{ Label = 'DomainController'; Expression = { $_.MachineName } }
					@{ Label = 'EventId'; Expression = { $_.Id } }
					@{ Label = 'LockedOutTimeStamp'; Expression = { $_.TimeCreated } }
					@{ Label = 'Message'; Expression = { $_.Message -split "`r" | Select -First 1 } }
					@{ Label = 'LockedOutLocation'; Expression = { $_.Properties[1].Value } }
				)
				
			} #end ifevent 
			
		} #end foreach lockedout event 
		# Clear the variables and allow the function to be used again
	 Clear-Variable counterTime
	 Clear-Variable UserInfo
	 Clear-Variable Event
	 Clear-Variable LockedOutEvents
	 Clear-Variable PDCEmulator
	 Clear-Variable DC
	 Clear-Variable Identity
	
	} #end process 
		
} #end function

function clearSecurityLogXP
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$targetComputerName
	)
	
	Write-Host ("Options 1: ")
}

function showMenu
{
	param (
		[string]$Title = 'My Menu'
	)
		
	Clear-Host
	
	# Display Version Info
	displayVersion
	
	$menuCounter = 0
	
	# Option 0
	Write-Host ("Option $menuCounter : Exit the program")
		
	#Write-Color -Text "Option ", $menuCounter, " : Exit the program" -Color White, Green, White
    [Environment]::NewLine
	
	# Option 1
	$menuCounter++
	#Write-Color -Text "Option $menuCounter", " : Remote Shutdown Checker" -Color Green, White
	Write-Host  ("Option $menuCounter : Remote Shutdown Checker")
	[Environment]::NewLine 
	
	# Option 2
	$menuCounter++
	Write-Host ("Option $menuCounter : Ping Target PC")  
	[Environment]::NewLine
	
	# Option 3
	$menuCounter++
	Write-Host ("Option $menuCounter : Scan Active Directory for Locked Out Users")  
	[Environment]::NewLine
	
	# Option 4
	$menuCounter++
	Write-Host ("Option $menuCounter : User Lockout Location Checker")  
	[Environment]::NewLine
	
	# Option 5
	$menuCounter++
	Write-Host ("Option $menuCounter : Active Directory Reset User Password / Unlock Account") -ForegroundColor Yellow
	[Environment]::NewLine
	
	# Option 6
	$menuCounter++
	Write-Host ("Option $menuCounter : Active Directory Query User with Employee ID")  
	[Environment]::NewLine
	
	# Option 7
	$menuCounter++
	Write-Host ("Option $menuCounter : Query Remote PC for System Specs")  
	[Environment]::NewLine
	
	# Option 8
	$menuCounter++
	Write-Host ("Option $menuCounter : Find Users Computer via Employee Number") -ForegroundColor Yellow
	[Environment]::NewLine
	
	<#
	Write-Host ("Black") -Foreground Black
	Write-Host ("Blue") -Foreground Blue
	Write-Host ("Cyan") -Foreground Cyan
	Write-Host ("DarkBlue") -Foreground DarkBlue
	Write-Host ("DarkCyan") -Foreground DarkCyan
	Write-Host ("DarkGray") -Foreground DarkGray
	Write-Host ("DarkGreen") -Foreground DarkGreen
	Write-Host ("DarkMagenta") -Foreground DarkMagenta
	Write-Host ("DarkRed") -Foreground DarkRed
	Write-Host ("DarkYellow") -Foreground DarkYellow
	Write-Host ("Gray") -Foreground Gray
	Write-Host ("Green") -Foreground Green
	Write-Host ("Magenta") -Foreground Magenta
	Write-Host ("Red") -Foreground Red
	Write-Host ("White") -Foreground White
	Write-Host ("Yellow") -Foreground Yellow
	#>
	
}

function pingTargetPC
{
	# Script for displaying scanning the event log of a remote PC and displaying when the PC has been shutdown/restarted.
	# LW - 16/09/2016 
	# Version 1.0
	
	# Begin Script
	
	# Get User input for remote IP 
	$remoteIPtoPing = Read-Host "Input Remote IP"
	[Environment]::NewLine
	
	# Get User input for the amount of times to ping the PC
	$amountOfTimesToPing = Read-Host "How many times do you want to ping $remoteIPtoPing ?"
	[Environment]::NewLine
	
	# Ping the IP address
	ping $remoteIPtoPing -n $amountOfTimesToPing
}

function remoteShutdownChecker
{
	# Script for displaying scanning the event log of a remote PC and displaying when the PC has been shutdown/restarted.
	# LW - 16/09/2016 
	# Version 1.1
	# Added - Displaying a counter for how many times the PC has been shutdown.
	
	# Begin Script
	
	$amountOfDays = 90
	
	# Setting the filter - saves resources by not scanning the entire event log
	$FilterLog = @{
		# Sets which part of the event log to search (Security, System etc...)
		LogName = "System"
		# Sets how far back in the log to check
		StartTime = (Get-Date).AddDays(- $amountOfDays)
		# Set the filter for the event log to the ID '6006' 
		ID = 6006
	}
	
	# Get User input for remote IP 
	$remoteIP = Read-Host 'Input Remote IP / Terminal Name'
	
	# This section actually searches remote PC for shutdowns and puts the output into the variable
	$Events = Get-WinEvent -ComputerName $remoteIP -FilterHashtable $FilterLog
	
	# Count the amount of times the event has happened. In this case it is how many times the PC has been shut down.
	$amountOfRestarts = $Events.Count
	
	# Displaying how many times the PC has been restarted to console 
	textSeperateLine -inputString "The PC with IP $remoteIP has been shut down $amountOfRestarts times in the last $amountOfDays days."	
	
	# Display to console the output log
	Get-WinEvent -ComputerName $remoteIP -FilterHashtable $FilterLog | Format-Table -AutoSize
}

function notImplementedYet
{
	textSeperateLine -inputString "This function is either not implemented yet or is currently not working. This may or may not change in future updates"
}

function resetUserPass
{
	notImplementedYet
}

function findUserComputerViaEmployee
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$employeeID
	)
	
	
	
}

function remoteSystemSpecs
{
	$compname = $args[0]
	if ($compname) { CheckHost }
	else { GetCompName }
}

function queryActiveDirectoryUser
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$employeeID
	)
	
	Get-ADUser $employeeID -Properties * | Format-List Name, Company, Department, Description, Office, EmailAddress, Logoncount, Created, LastLogonDate, LastBadPasswordAttempt, PasswordNeverExpires, LockedOut
}

function scanActiveDirectoryForLockedOutUsers
{
	textSeperateLine -inputString 'List of currently locked out users from Active Directory:'	
	Search-ADAccount -LockedOut | Format-Table Name, LastLogonDate, PasswordExpired, PasswordNeverExpires, SamAccountName -Wrap
}

do
{
	# Run the remote show menu function
	showMenu
	
	# Ask the user to enter the option they want to select
	$input = Read-Host "Select an option"
	[Environment]::NewLine
	
	switch ($input)
	{
		'1' {
			# Option 1 is selected
			Clear-Host
			displayVersion
			
			Write-Host ("Event Viewer Remote Shutdown Checker")
			[Environment]::NewLine
			
			# Run the remote shut down checker function
			remoteShutdownChecker
			
			# Wait for user to press any key to continue, gives user time to read output
			pressAnyKey
			
		} '2' {
			# Option 2 is selected
			Clear-Host
			displayVersion
			
			pingTargetPC
			
			# Wait for user to press any key to continue, gives user time to read output
			pressAnyKey
			
		} '3' {
			# Option 3 is selected
			Clear-Host
			displayVersion
			
			# Run the scan Active Directory For Locked Out Users
			scanActiveDirectoryForLockedOutUsers
			
			# Wait for user to press any key to continue, gives user time to read output
			pressAnyKey
			
		} '4' {
			# Option 4 is selected
			Clear-Host
			displayVersion
			
			Write-Host ("User Lockout Checker")
			[Environment]::NewLine
			Write-Host ("Known Issue - For every user you check for lockouts, you  must restart the application.") -ForegroundColor Yellow
			[Environment]::NewLine
			Write-Host ("May take about 30 seconds to complete. Do not press anything else until it has completed.") -ForegroundColor Yellow
			[Environment]::NewLine
			
			$identity = Read-Host 'Input User ID (e00 etc)'
			[Environment]::NewLine
			Get-LockedOutLocation -Identity $identity
			
			# Wait for user to press any key to continue, gives user time to read output
			pressAnyKey
			
		} '5' {
			#Option 5 is selected
			Clear-Host
			displayVersion
			
			Write-Host ("Active Directory Reset User Password / Unlock Account")
			[Environment]::NewLine
			
			notImplementedYet
			
			# Wait for user to press any key to continue, gives user time to read output
			pressAnyKey
			
		} '6' {
			#Option 6 is selected
			Clear-Host
			displayVersion
			
			Write-Host ("Active Directory Query User with Employee ID")
			[Environment]::NewLine
			
			$employeeID = Read-Host 'Input Employee ID (e00 etc)'
			queryActiveDirectoryUser -employeeID $employeeID
			
			# Wait for user to press any key to continue, gives user time to read output
			pressAnyKey
			
		} '7' {
			#Option 7 is selected
			
			Clear-Host
			displayVersion
			
			Write-Host ("Query Remote PC for System Specs")
			[Environment]::NewLine
			
			remoteSystemSpecs
			
			pressAnyKey
		<#	
		}	'7' {
			#Option 7 is selected
			
			Clear-Host
			displayVersion
			
			Write-Host ("Query Remote PC for System Specs")
			[Environment]::NewLine
			
			remoteSystemSpecs
			
			pressAnyKey		
		#>
		
		}'8' {
			#Option 8 is selected
			
			Clear-Host
			displayVersion
			
			Write-Host ("Find Users Computer via Employee Number")
			[Environment]::NewLine
			
			#$identity = Read-Host 'Input User ID (e00 etc)'
			#Get-LockedOutLocation -Identity $identity
			
			notImplementedYet
			
			#$targetComputerName = Read-Host 'Input Remote IP / Terminal Name'
						
			#clearSecurityLogXP -targetComputerName $targetComputerName 
			
			pressAnyKey
			
		}('0') { # Option 9 is selected
			return
		}
	}
	
}
until ($input -eq '0')






