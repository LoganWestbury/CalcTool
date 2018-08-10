Import-Module ActiveDirectory

$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath
Import-Module $totalDir\PSLogging\PSLogging.psm1

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

Function lockoutLocationFinder
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$Identity
	)
	
	
	
	Begin
	{
		Write-LogInfo -LogPath $sLogFile -Message 'Trying to locate the location of the terminal that is locking a user out of Active Directory.'
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
				Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
				
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
			Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
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
		Clear-Variable counterTime, UserInfo, Event, LockedOutEvents, PDCEmulator, DC, Identity
	} #end process 
	End
	{
		If ($?)
		{
			Write-LogInfo -LogPath $sLogFile -Message 'Completed Successfully.'
			Write-LogInfo -LogPath $sLogFile -Message ' '
		}
	}
	
} #end function