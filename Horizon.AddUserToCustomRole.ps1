# Requires -Modules VMware.Horizon.VLSI
#######################################
# @Author Narendran Jothiram
# Horizon Engineer, EUC
#######################################

# Example: Powershell module location --> C:\Program Files\WindowsPowerShell\Modules or C:\Users\username\Documents\PowerShell\Modules.
# Place the folder VMWare.Horizon.VLSI in this location for Import to work

# Uncomment this to load the module from current folder location. 
# If not working, print the location of $PSScriptRoot\VMware.Horizon.VLSI\1.0\VMware.Horizon.VLSI.psm1 to know the path and correct it.
Import-Module "$PSScriptRoot\VMware.Horizon.VLSI\1.0\VMware.Horizon.VLSI.psm1" -Force

# Comment the current folder location script loading and uncomment below to load from windows Powershell Modules path
# Import-Module VMware.Horizon.VLSI -Force


#Credentials and Connection Server
$Credential = Get-Credential


# Fully Qualified Host name of Connection Server
$HVServer = "CS002.view.nj"
$domainFQDN="view.nj"
# Only username of AD user.
$ADUsername="administrator"
$customLogCollectorRoleName="LogCollectorAdmins1"

# Login to the CS. Don't Forget to Invoke-LogoutCS after all API executions or use.
# While entering Credentials use format, domain\username and provide password in the prompt.
$SessionInfo = Send-LoginCS $HVServer "true" $Credential


if ($SessionInfo -eq $Null) {
    exit 1
}

# Add Log Collector Custom Role. Default name of the custom role is "LogCollectorAdmins", if role name not specified.
Add-LogCollectorCustomRole $SessionInfo $customLogCollectorRoleName

# Get the information of the AD user.
$userInformation = Find-ADUserByName $SessionInfo $ADUsername $domainFQDN

# Now add the user to custom role with name 
Add-HorizonAdminToRole $SessionInfo $userInformation.id $customLogCollectorRoleName

# Logout of the current session
Invoke-LogoutCS $SessionInfo