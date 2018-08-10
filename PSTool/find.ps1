
function findUserComputerLogin {
   <# 


                -- If issues look into the substring select --
        #>

        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory=$true, Position=0)]
            [Object]
            $Username = (read-host "Please enter the Primary  user"),
            $FILESERVER = "name of fileserver"
        )
        # Connect Remotely to Server, Run Session, get a list of everybody logged in there 

        $S=NEW-PSSESSION –computername $FILESERVER 
        $Results=(INVOKE-COMMAND –Session $s –scriptblock { (NET SESSION) }) | Select-string $USERNAME 
        REMOVE-PSSESSION $S
        # parse through the data and pull out what we need   
        Foreach ( $Part in $RESULTS ) {
            $ComputerIP=$Part.Line.substring(2,21).trim() 
            $User = $Part.Line.substring(21,44).trim()
            # Use nslookup to identify the computer, grab the line with the “Name:” field in it
            $Computername=([System.Net.dns]::GetHostbyAddress($ComputerIP))
            $computername =  $ComputerName.HostName
            If ($Computername -eq $NULL) { $Computername} 
            #Else { $Computername=$Computername.substring(9).trim()}
            If($User -eq $null){
                write-host ("No computer found for" +  $Username + "Please check the name and try again. A partial samaccountname works best")
            }
            else{
                write-host ($User + "is logged into " + $Computername + "with IP address" + $ComputerIP)
                $global:findusercomputer = $computername
            }
        }
}



findUserComputerLogin 