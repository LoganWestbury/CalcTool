Import-Module ActiveDirectory

Function lockoutLocationFinder
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
			Write-Progress -Activity "Contacting DCs for lockout info" -Status "Querying $($DC.Hostname)" -PercentComplete (($DCCounter/$DomainControllers.Count) * 100)
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
		
		#Write-Host ("/-------------------------------------------------------------------------------------------------------\")
		Write-Host ("Locked Terminals - If nothing appears then it's most likely the emails on the phone locking the user out. ")
		#Write-Host ("\-------------------------------------------------------------------------------------------------------/")
		
		$counterTime = 0
		
		Foreach ($Event in $LockedOutEvents)
		{
			If ($Event | Where { $_.Properties[2].value -match $UserInfo.SID.Value })
			{
				$counterTime = $counterTime + 1
				#Write-Host ("/--------------------------------\") -ForegroundColor White
				#Write-Host ("	Locked Terminal $counterTime") -ForegroundColor Cyan
				#Write-Host ("\--------------------------------/") -ForegroundColor White
				
				
				$lockedEvents += $Event | Select-Object -Property @(
					@{ Label = 'User'; Expression = { $_.Properties[0].Value } }
					@{ Label = 'Domain Controller'; Expression = { $_.MachineName } }
					@{ Label = 'Locked Out Location'; Expression = { $_.Properties[1].Value } }
				) | Out-String 
				
				$outputString = "Locked Terminal $counterTime" + $outputString + $lockedEvents
				
				 
				
				<#
				
				$txtLockoutOutput.Text = $Event | Select-Object -Property @(
					@{ Label = 'User'; Expression = { $_.Properties[0].Value } }
					@{ Label = 'Domain Controller'; Expression = { $_.MachineName } }
					@{ Label = 'Locked Out Location'; Expression = { $_.Properties[1].Value } }
				) | 
		
				#>
				
				#Out-GridView -$Event -Title "Locked Out Locations"  
				
				#$Event | Out-GridView 
					
			} #end ifevent 
			
		} #end foreach lockedout event 
		
		$txtLockoutOutput.Text = $outputString
		
		#$lockedEvents | Out-GridView -PassThru -Title "Location of the Lockout(s)"
		
		# Clear the variables and allow the function to be used again
		Clear-Variable counterTime, UserInfo, Event, LockedOutEvents, PDCEmulator, DC, Identity
	} #end process 
	
} #end function



function scanADForLockedOutUsers
{
<#
	textSeperateLine -inputString 'List of currently locked out users from Active Directory:'
	Search-ADAccount -LockedOut | Format-Table Name, LastLogonDate, PasswordExpired, PasswordNeverExpires, SamAccountName -Wrap
#>
$Write = ("Select a user account and then click Ok to scan the system for the location of the lockout.")
textSeperateLine $Write

 Search-ADAccount -LockedOut |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordExpired, PasswordNeverExpires | Out-GridView -PassThru -Title "List of Locked Out Accounts" | Foreach-Object { lockoutLocationFinder -Identity $_.SamAccountName}

}

function pressAnyKey
{
	# Wait for user to press any key to continue, gives user time to read output
	textSeperateLine -inputString "Press any key to continue..."
	$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
}

function funcFindLockoutClick
{
	$IdentityName = $txtUserName.Text
	lockoutLocationFinder -Identity $IdentityName

}




Add-Type -AssemblyName System.Windows.Forms


$SupportTool = New-Object system.Windows.Forms.Form
$SupportTool.Text = "Support Tool by Logan Westbury"
$SupportTool.Width = 383
$SupportTool.Height = 462
$SupportTool.MaximumSize = $SupportTool.Size
$SupportTool.MinimumSize = $SupportTool.Size


$txtUserName = New-Object system.windows.Forms.TextBox
$txtUserName.Width = 157
$txtUserName.Height = 25
$txtUserName.location = new-object system.drawing.point(3,27)
$txtUserName.Font = "Microsoft Sans Serif,10"
$SupportTool.controls.Add($txtUserName)


$lblUserName = New-Object system.windows.Forms.Label
$lblUserName.Text = "Enter User Name"
$lblUserName.AutoSize = $true
$lblUserName.Width = 25
$lblUserName.Height = 10
$lblUserName.location = new-object system.drawing.point(3,6)
$lblUserName.Font = "Microsoft Sans Serif,10"
$SupportTool.controls.Add($lblUserName)


$cmdFindLockout = New-Object system.windows.Forms.Button
$cmdFindLockout.Text = "GO!"
$cmdFindLockout.Width = 74
$cmdFindLockout.Height = 40
$cmdFindLockout.Add_MouseClick({
#add here code triggered by the event
funcFindLockoutClick
})
$cmdFindLockout.location = new-object system.drawing.point(167,7)
$cmdFindLockout.Font = "Microsoft Sans Serif,10"
$SupportTool.controls.Add($cmdFindLockout)


$cmdClear = New-Object system.windows.Forms.Button
$cmdClear.Text = "Clear"
$cmdClear.Width = 100
$cmdClear.Height = 40
$cmdClear.Add_MouseClick({
#add here code triggered by the event
	$txtLockoutOutput.Text = ""
	$txtUserName.Text = ""
})
$cmdClear.location = new-object system.drawing.point(253,7)
$cmdClear.Font = "Microsoft Sans Serif,10"
$SupportTool.controls.Add($cmdClear)



$txtLockoutOutput = New-Object system.windows.Forms.TextBox
$txtLockoutOutput.Multiline = $true
$txtLockoutOutput.Width = 351
$txtLockoutOutput.Height = 349
$txtLockoutOutput.location = new-object system.drawing.point(4,64)
$txtLockoutOutput.Font = "Microsoft Sans Serif,10"
$SupportTool.controls.Add($txtLockoutOutput)


[void]$SupportTool.ShowDialog()
$SupportTool.Dispose()



