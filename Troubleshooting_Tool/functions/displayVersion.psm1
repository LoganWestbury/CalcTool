$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath
Import-Module $totalDir\PSLogging\PSLogging.psm1

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

function displayVersion
{
	Begin
	{
		Write-LogInfo -LogPath $sLogFile -Message 'Displaying the title bar at the top of the screen.'
	}
	
	Process
	{
		Try
		{
			Clear-Host
			Write-Host ("-------------------------------------------------------------------------")
			Write-Host ("|	IT Support Tool - Version 1.0 - LW - 11/10/2016 - E0056585	|")
			Write-Host ("-------------------------------------------------------------------------")
			[Environment]::NewLine
			
			Write-Host ("If you recieve any error messages could you please send a screenshot and the log file to Logan.Westbury@ArnoldClark.com") -ForegroundColor Yellow
			Write-Host ("Log file is located at: " + "$sLogPath") -ForegroundColor Yellow
			Write-Host ("To temporarily fix most issues just relaunch the program.") -ForegroundColor Yellow
			[Environment]::NewLine
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
