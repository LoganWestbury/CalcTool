##########################################################
#   Created by Logan Westbury
#   22/02/2017

##########################################################
#   Clear users terminal screen

Clear-Host

##########################################################
#   Get user input 

$userInput = Read-Host("Enter remote host")

##########################################################
#   Find out who the currently logged on user is via IP
#   This will return the username as "domain\username

$string1 = Get-WmiObject Win32_ComputerSystem -ComputerName $userInput -recurse | Where-Object {!$_.PsIsContainer} | foreach {$_.Username}

##########################################################
#   Remove the domain section of the username 
#   This assumes the domain is three letters 

$string1 = $string1.Substring(4)

##########################################################
#   Set the variable to the users desktop

$createDir = ("\\$userInput\C$\Users\$string1\Desktop\")

##########################################################
#   Create the main directory and subfolders

New-Item "$createDir\Shortcuts\" -type directory
New-Item "$createDir\Shortcuts\Rev8 (Kerridge)\" -type directory
New-Item "$createDir\Shortcuts\Backup Links\" -type directory

##########################################################
#   Set the variable to the new directory

$createDir = ("\\$userInput\C$\Users\$string1\Desktop\Shortcuts\")

##########################################################
#   Copy over the browser specific shortcuts

Copy-Item -Path (".\resources\Shortcuts\Salesmans Office.lnk") -Destination ("$createDir\") 
Copy-Item -Path (".\resources\Shortcuts\AC Web Mail.lnk") -Destination ("$createDir\") 
Copy-Item -Path (".\resources\Shortcuts\ASO 2.lnk") -Destination ("$createDir\") 
Copy-Item -Path (".\resources\Shortcuts\ASO 2_5.lnk") -Destination ("$createDir\") 

##########################################################
#   Copy over the Rev8 shortcuts

Copy-Item -Path (".\resources\Shortcuts\Rev8 (Kerridge)\Rev8 Arnold Clark.kcc") -Destination ("$createDir\Rev8 (Kerridge)\") 
Copy-Item -Path (".\resources\Shortcuts\Rev8 (Kerridge)\Rev8 Harry Fairbairn.kcc") -Destination ("$createDir\Rev8 (Kerridge)\") 
Copy-Item -Path (".\resources\Shortcuts\Rev8 (Kerridge)\Rev8 John R Weir.kcc") -Destination ("$createDir\Rev8 (Kerridge)\") 

##########################################################
#   Copy over frequently used backup URLs
#   These will open up in the default browser

Copy-Item -Path (".\resources\Shortcuts\Backup Links\ASO2.url") -Destination ("$createDir\Backup Links\") 
Copy-Item -Path (".\resources\Shortcuts\Backup Links\ASO2_5.url") -Destination ("$createDir\Backup Links\") 
Copy-Item -Path (".\resources\Shortcuts\Backup Links\WebMail.url") -Destination ("$createDir\Backup Links\") 
Copy-Item -Path (".\resources\Shortcuts\Backup Links\Salesmans_Office.url") -Destination ("$createDir\Backup Links\") 

##########################################################
#   Open explorer at the new directory

Invoke-Expression "explorer $createDir"