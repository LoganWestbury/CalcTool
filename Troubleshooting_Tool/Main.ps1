<#
.SYNOPSIS
  IT Helpdesk Support Tool

.DESCRIPTION
  IT Helpdesk Support Tool

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  <Inputs if any, otherwise state None>

.OUTPUTS
  <Outputs if any, otherwise state None>

.NOTES
  Version:        1.0
  Author:         Logan Westbury
  Creation Date:  12/10/2016
  Purpose/Change: Adding logging functions

.EXAMPLE
  <Example explanation goes here>
  
  <Example goes here. Repeat this attribute for more than one example>
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

#Script parameters go here
    $scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath

Import-Module $totalDir\functions\displayVersion.psm1
Import-Module $totalDir\functions\populateMainMenu.psm1
Import-Module $totalDir\functions\showMenuReusable.psm1
Import-Module $totalDir\functions\textSeperateLine.psm1
Import-Module $totalDir\functions\pressAnyKey.psm1
Import-Module $totalDir\functions\remoteShutdownChecker.psm1
Import-Module $totalDir\functions\scanADForLockedOutUsers.psm1
Import-Module $totalDir\functions\lockoutLocationFinder.psm1
Import-Module $totalDir\functions\queryActiveDirectoryUser.psm1
Import-Module $totalDir\functions\PSLogging\PSLogging.psm1

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#Import Modules & Snap-ins


#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\functions\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
#Script Execution goes here

do
{
	populateMainMenu
	$input = Read-Host "Select an option"
	
	switch ($input)
	{
		'1' {
			displayVersion
			Write-Host ("Event Viewer Remote Shutdown Checker")
			[Environment]::NewLine
			remoteShutdownChecker
			pressAnyKey
			
		} '2' {
			displayVersion
			scanADForLockedOutUsers
			pressAnyKey
			
		} '3' {
			displayVersion
			Write-Host ("User Lockout Checker")
			[Environment]::NewLine
			Write-Host ("Known Issue - For every user you check for lockouts, you  must restart the application.") -ForegroundColor Yellow
			[Environment]::NewLine
			Write-Host ("May take about 30 seconds to complete. Do not press anything else until it has completed.") -ForegroundColor Yellow
			[Environment]::NewLine
			$identity = Read-Host 'Input User ID (e00 etc)'
			[Environment]::NewLine
			lockoutLocationFinder -Identity $identity
			pressAnyKey

		} '4' {
			displayVersion
			Write-Host ("Active Directory Query User with Employee ID")
			[Environment]::NewLine
			$employeeID = Read-Host 'Input Employee ID (e00 etc)'
			queryActiveDirectoryUser -employeeID $employeeID
			pressAnyKey

		} ('0')
		{
			return
		}
	}
}
until ($input -eq '0')

Stop-Log -LogPath $sLogFile
