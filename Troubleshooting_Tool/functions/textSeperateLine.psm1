$scriptpath = $MyInvocation.MyCommand.Path
$totalDir = Split-Path $scriptpath
Import-Module $totalDir\PSLogging\PSLogging.psm1

#Script Version
$sScriptVersion = '1.0'

#Log File Info
$sLogPath = "$totalDir\logs\"
$sLogName = 'SupportTool.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

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