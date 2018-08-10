$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath

Import-Module $totalDir\showMenuReusable.psm1



function populateMainMenu
{
	#Begin
	#{
	#	Write-LogInfo -LogPath $sLogFile -Message 'Populating the main menu of the program.'
	#}
	
	#Process
	#{
		#Try
		#{
			$menuItems = @(
				"Exit",
				"Remote Shutdown Checker",
				"Scan Active Directory for Locked Out Users",
				"User Lockout Location Checker",
				"Active Directory Query User with Employee ID"
			)
			
			showMenuReusable -menuItems $menuItems
	#	}
		
	#	Catch
	#	{
	#		Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
	#		Break
	#	}
	#}
	
	#End
	#{
	#	If ($?)
	#	{
	#		Write-LogInfo -LogPath $sLogFile -Message 'Completed Successfully.'
	#		Write-LogInfo -LogPath $sLogFile -Message ' '
	#	}
		
	#}
}