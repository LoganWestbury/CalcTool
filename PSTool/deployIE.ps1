#######################################################################################
#                                IE 64-bit Routine
#######################################################################################

IF (($os.OSArchitecture) -eq "64-Bit" -and (Test-Path $fileroot) -eq $true)
{
    Write-Host "Found 64-Bit Architecture...Please wait while we apply pre-requisite updates..."

    #Define Updates x64
    $KB164 = "$fileroot\resources\Installers\IE\Windows6.1-KB2533623-x64.msu"
    $KB264 = "$fileroot\resources\Installers\IE\Windows6.1-KB2888049-x64.msu"
    $KB364 = "$fileroot\resources\Installers\IE\Windows6.1-KB2670838-x64.msu"
    $KB464 = "$fileroot\resources\Installers\IE\Windows6.1-KB2729094-v2-x64.msu"
    $KB564 = "$fileroot\resources\Installers\IE\Windows6.1-KB2731771-x64.msu"
    $KB664 = "$fileroot\resources\Installers\IE\Windows6.1-KB2786081-x64.msu"
    $KB764 = "$fileroot\resources\Installers\IE\Windows6.1-KB2834140-v2-x64.msu"
    $KB864 = "$fileroot\resources\Installers\IE\Windows6.1-KB2882822-x64.msu"
    $KB964 = "$fileroot\resources\Installers\IE\Windows6.1-KB2639308-x64.cab"
    $ie64 = "$fileroot\resources\Installers\IE\IE11-Windows6.1-x64-en-us.exe" #Define App

    Write-Host "Installing Update 1..."
    Start-Process "wusa.exe" -ArgumentList "$kb164 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 2..."
    Start-Process "wusa.exe" -ArgumentList "$kb264 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 3..."
    Start-Process "wusa.exe" -ArgumentList "$kb364 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 4..."
    Start-Process "wusa.exe" -ArgumentList "$kb464 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 5..."
    Start-Process "wusa.exe" -ArgumentList "$kb564 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 6..."
    Start-Process "wusa.exe" -ArgumentList "$kb664 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 7..."
    Start-Process "wusa.exe" -ArgumentList "$kb764 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 8..."
    Start-Process "wusa.exe" -ArgumentList "$kb864 /quiet /norestart" -Wait -Verbose

    Write-Host "Installing Update 9..."
    Start-Process "dism.exe" -ArgumentList "/online /add-package /packagepath:$KB964 /quiet /norestart" -NoNewWindow -Wait -verbose

    Write-Host "Installing Internet Explorer 11, 64-Bit, Please wait..."
    Start-Process "$ie64" -ArgumentList "/passive /norestart /update-no" -Wait -verbose

    Exit 0
}
Elseif ((Test-Path $fileroot) -eq $false)
{
    Write-Host "$date.....Software can not be found, please contact your system administrator!"
    Exit 1603
}