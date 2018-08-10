$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath
Import-Module $totalDir\PSLogging\PSLogging.psm1

Import-Module $totalDir\textSeperateLine.psm1
Import-Module ActiveDirectory

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

function scanADForLockedOutUsers
{
	Begin
	{
		Write-LogInfo -LogPath $sLogFile -Message 'Scanning active directory for locked out users'
	}
	
	Process
	{
		Try
		{
			textSeperateLine -inputString 'List of currently locked out users from Active Directory:'
			Search-ADAccount -LockedOut | Format-Table Name, LastLogonDate, PasswordExpired, PasswordNeverExpires, SamAccountName -Wrap
		}
		
		Catch
		{
			Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
			Break
		}
	}
	
	End
	{
		If ($?)
		{
			Write-LogInfo -LogPath $sLogFile -Message 'Completed Successfully.'
			Write-LogInfo -LogPath $sLogFile -Message ' '
		}
	}
}