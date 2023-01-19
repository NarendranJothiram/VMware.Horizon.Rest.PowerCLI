# Requires -Modules VMware.Horizon.VLSI, VMware.Hv.Helper, VMware.PowerCLI
#######################################
# @Author Narendran Jothiram
# Horizon Engineer, EUC
#
# Modified By: Matt Frey
# Consulting Architect, EUC PSO
#######################################

# Example: Powershell module location --> C:\Program Files\WindowsPowerShell\Modules or C:\Users\username\Documents\PowerShell\Modules.
# Place the folder VMWare.Horizon.VLSI in this location for Import to work

# Uncomment this to load the module from current folder location
Import-Module "$PSScriptRoot\VMware.Horizon.VLSI\1.0\VMware.Horizon.VLSI.psm1" -Force

#Import-Module VMware.Horizon.VLSI -Force

#Global Settings
#Uses the Splatting method
#See https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-hashtable?view=powershell-7.2
#for information about 'Splatting hashtables at cmdlets'
$Parameters = @{
    Vcenter = "myVcenter.FQDN"
    baseImage = "win11Staff"
    datacenter = "SDDC-Datacenter"
    dataStorePath = "/SDDC-Datacenter/host/Cluster-1/WorkloadDatastore"
    icDomainAdminName = "svcIC"
    clusterPath = "/SDDC-Datacenter/host/Cluster-1"
    ResourcesPath = "/SDDC-Datacenter/host/Cluster-1/Resources/Compute-ResourcePool/Horizon Resources"
    icDomainDNS ="vmwarepso.org"
    baseImageSnapshot = "windows 11 June Updates"
    #Generic Horizon Settings
    desktopNamePattern = "IC-AUTO-VLSI{n:fixed=3}" # for example
    UserAssignment = "FLOATING" # or DEDICATED
    #"AutomaticAssignment" = $true # or $false
    allowUsersToResetMachines = $false # or $true
    allowMultipleSessionsPerUser = $false # or $true
    deleteOrRefreshMachineAfterLogoff = "DELETE" # REFRESH, DELETE or NEVER -lof
    refreshOsDiskAfterLogoff = "NEVER"
    supportedDisplayProtocols = @("BLAST") # optional "PCOIP"
    renderer3D = "MANAGE_BY_VSPHERE_CLIENT" # or DISABLED, AUTOMATIC, SOFTWARE, or HARDWARE
    enableGRIDvGPUs = $false
    maxNumberOfMonitors = 2
    maxResolutionOfAnyOneMonitor = "WUXGA"
    #"quality" = "NO_CONTROL" #or HIGH LOW MEDIUM #Controls Flash Redirection Quality - No longer present in Horizon
    #"throttling" = "DISABLED" #or AGGRESIVE CONSERVATIVE DISABLED MODERATE Controls Flash Redirection Throttling - No longer present in Horizon
    # "overrideGlobalSetting" = $false # or $true #only needed for when Mirage is in use (EOL)
    #"UseSeparateDatastoresReplicaAndOSDisks" = $false # or $true #only applies to Composer Linked-clones
    UseViewStorageAccelerator = $false # or $true # not supported with Instant Clones, must be set to $false
    EnableProvisioning = $true # or $false
    NamingMethod = "PATTERN"
    ReclaimVmDiskSpace = $false # or $true
    RedirectWindowsProfile = $false # or $true
    stopProvisioningOnError = $true # or $true
    StorageOvercommit = "UNBOUNDED"
    UseNativeSnapshots = $false # or $true
    #"UseSeparateDatastoresPersistentAndOSDisks" = $false # or $true  #only needed for when $RedirectWindowsProfile is $true
    UseVSAN = $true # or $false
    #"enableHTMLAccess" = $false # or $true # deprecated, defaults to $true - controlled by selecting or desecting feature during installation of Horizon Agent
    defaultDisplayProtocol = "BLAST"
    AutomaticLogoffMinutes = 120
    allowUsersToChooseProtocol = $false
    AutomaticLogoffPolicy = "NEVER" #IMMEDIATELY or NEVER or AFTER
    postSynchronizationScriptName = ""
    postSynchronizationScriptParameters = ""
}

#Select Environment
$Environment = "VMC" # or USERACCEPTANCETESTING or PRODUCTION

If ($environment -eq "PRODUCTION")
    {
        $EnvironmentParams = @{
            desktopPoolName = "PRODUCTION"
            displayName = "PRODUCTION"
            ProvTime = "UP_FRONT"
            vmFolderPath  = "</DATASTORE/FOLDER>"
            MaximumCount = 5
            SpareCount = 1
            #NumUnassignedMachinesKeptPoweredOn = 1 #only applies when using specified naming
            AdContainer = "OU=Production,OU=AMER,OU=Virtual Desktop Clones,OU=Workstations"
        }
    }

If ($environment -eq "USERACCEPTANCETESTING")
    {
        $EnvironmentParams = @{
            desktopPoolName = "USERACCEPTANCETESTING"
            displayName= "USERACCEPTANCETESTING"
            ProvTime = "UP_FRONT"
            vmFolderPath  = "</DATASTORE/FOLDER>"
            MaximumCount = 5
            SpareCount = 1
            #NumUnassignedMachinesKeptPoweredOn = 1 #only applies when using specified naming
            AdContainer = "OU=Pre-Production,OU=AMER,OU=Virtual Desktop Clones,OU=Workstations"
        }
    }

If ($environment -eq "DEVELOPMENT")
    {
        $EnvironmentParams = @{
            desktopPoolName = "DesktopPool1B"
            displayName= "DesktopPool1B"
            ProvTime = "UP_FRONT"
            vmFolderPath   = "/USVA01-HVD-DEV2/vm/ResilientHVD"
            MaximumCount = 5
            SpareCount = 2
            #NumUnassignedMachinesKeptPoweredOn = 1 #only applies when using specified naming
            AdContainer = "OU=Development,OU=AMER,OU=Virtual Desktop Clones,OU=Workstations"
        }
    }

    If ($environment -eq "VMC")
    {
        $EnvironmentParams = @{
            desktopPoolName = "TESTVLSI"
            displayName= "TEST VLSI Testing"
            provisioningTime = "UP_FRONT"
            vmFolderPath   = "/SDDC-Datacenter/vm/Workloads/Users/CreekSideE"
            MaximumCount = 2
            SpareCount = 1
            #NumUnassignedMachinesKeptPoweredOn = 1 #only applies when using specified naming
            AdContainer = "OU=Non-Persistent,OU=Desktops,OU=Horizon,OU=Objects-Computers"
        }
    }


#Credentials and Connection Server
$Credential = Get-Credential
# Fully Qualified Host name of Connection Server
$HVServer = "CS002.view.nj"



# Modify the params as required. Move this to another Ps1 file for execution if required. Don't Forget to Invoke-LogoutCS after all API executions or use.
$SessionInfo = Send-LoginCS $HVServer "true" $Credential

if ($SessionInfo -eq $Null) {
    exit 1
}
### START OF ADD MANUAL MACHINE TO DESKTOP POOL

# Use IP address or FQDN which was used while registering VC with CS
# $Vcenter = "x.x.x.x"
# $vCenterInfo = Get-VCenterInfo $SessionInfo $Vcenter
# $vCenterIdentifier = $vCenterInfo.id
# $desktopPoolName="FIC2"
# $desktopData = Get-DesktopPoolByName $SessionInfo $desktopPoolName $vCenterIdentifier

# $desktopIdentifier = $desktopData.id

# Write-Host ($desktopData | ConvertTo-Json -depth 10)


# $virtualMachinesList = Get-VirtualMachineList $SessionInfo $vCenterIdentifier

# Provide list of Virtual Machine name to added
# $vmNameList = @("Win10Net")

#Sample code to add machine to existing manual desktop pool
# Invoke-AddVMToManualDesktopPool $SessionInfo $virtualMachinesList $vmNameList $desktopIdentifier

### END OF MANUAL DESKTOP POOL SAMPLE CODE

# Uncomment this to test New-DesktopPool API
# New-DesktopPool $SessionInfo @Parameters @EnvironmentParams

Invoke-LogoutCS $SessionInfo