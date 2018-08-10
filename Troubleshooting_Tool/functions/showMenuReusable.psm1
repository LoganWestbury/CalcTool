$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath
Import-Module $totalDir\PSLogging\PSLogging.psm1

Import-Module $totalDir\displayVersion.psm1

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

function showMenuReusable
{
	
	Param (
		[CmdletBinding()]
		[Parameter(Mandatory = $True)]
		[Array]$menuItems
	)
	
	
	Begin
	{
		Write-LogInfo -LogPath $sLogFile -Message 'Actually outputing the menu to the screen, data is gathered from the populateMainMenu function'
	}
	
	Process
	{
		Try
		{
			[Array]$tempMenuArray = $menuItems
			
			displayVersion
			$menuCounter = $tempMenuArray.Length
			$i = 0
			
			do
			{
				Write-Host ("Option $i : " + $tempMenuArray[$i])
				[Environment]::NewLine
				$i++
			}
			until ($i -eq $menuCounter)
		}
		
		Catch
		{
			Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
			Break
		}
	}
	End{ If ($?)
		{
			Write-LogInfo -LogPath $sLogFile -Message 'Completed Successfully.'
			Write-LogInfo -LogPath $sLogFile -Message ' '
		}
	}
}