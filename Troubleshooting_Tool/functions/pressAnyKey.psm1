$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath
Import-Module $totalDir\PSLogging\PSLogging.psm1

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

function pressAnyKey
{
	Begin
	{
		Write-LogInfo -LogPath $sLogFile -Message 'Waits for the user to press any  key to continue, gives the user time to read what is being displayed on the screen.'
	}
	
	Process
	{
		Try
		{
			# Wait for user to press any key to continue, gives user time to read output
			textSeperateLine -inputString "Press any key to continue..."
			$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
			$HOST.UI.RawUI.Flushinputbuffer()
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