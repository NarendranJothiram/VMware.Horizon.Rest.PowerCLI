#######################################
# @Author Narendran Jothiram
# Horizon Engineer, EUC
#######################################

# Example: Powershell module location --> C:\Program Files\WindowsPowerShell\Modules.
# Place the folder VMWare.Horizon.VLSI in this location for Import to work

Import-Module VMware.Horizon.VLSI -Force

function AddDesktopPool() {

    param(
        $sessionInfoParam
    )

    # Desktop pool Name. Set a unique name each time
    $desktopPoolName="Win11Staff"

    # Name pattern of VMs
    $desktopNamePattern="Win11Staff-{n}"

    # Change to custom access group name when required
    $accessGroupName="Root"

    # dns name of domain to get matched for domain identification
    $icDomainDNS='viewchild.view.nj'

    # Admin user account registered in horizon
    $icDomainAdminName='administrator'

    # Container path where the Instant Clone machines accounts gets created in AD
    $adContainerVDI="OU=Containers,OU=HorizonGroups"

    # Enter the vCenter address or hostname registered with horizon. If horizon uses hostname of Vcenter, do not enter IP address
    $Vcenter = "vCenterIPAddrOrHostName"

    # Set the value suitable for your environment for using it as master image for desktop pool creation
    $baseImagePath="/HorizonWorld/vm/Discovered virtual machine/Win10Ent"

    # Update this value for automation.
    $baseImageSnapshotPath = "/ShapshotPathOfVMImage"

    # VM Folder Path in Datacenter. Update this value for automation.
    $vmFolderPath = "/HorizonWorld/vm/Discovered virtual machine/Floating87"

    # cluster path. Modify it for automation needs
    $clusterPath="/HorizonWorld/host/HorizonResources"

    # Customizable input
    $ResourcesPath="/HorizonWorld/host/HorizonResources/Resources"

    # Use the desired datastore path. For now adding one DS path. Extend it according to the needs.
    $dataStorePath="/HorizonWorld/host/HorizonResources/NJDS1TB"

    # Set the name of NIC card for finding identifier from list
    $nicName="Network adapter 1"

    # Change to the desired network name
    $networkLabelName="DVPortGroupFOUR"

    # Start fetching identifiers for invoking create desktop pool #

    $icDomainInfo = Get-ADDomainInfo $sessionInfoParam $icDomainDNS $icDomainAdminName
    
    $icDomainID = $icDomainInfo.base.domain

    Write-Host $icDomainID

    $adContainerIdentifier = Get-ADContainerIdentifier $sessionInfoParam $icDomainID $adContainerVDI
    Write-Host $adContainerIdentifier

    $vCenterInfo = Get-VCenterInfo $sessionInfoParam $Vcenter
    $vCenterIdentifier = $vCenterInfo.id
    # Write-Host $vCenterIdentifier

    $returnValues = Get-BaseImageAndDataCenterIdentifier $sessionInfoParam $vCenterIdentifier $baseImagePath

    $baseImageIdentifier = $returnValues.baseImageIdentifier;
    $baseImageDataCenterIdentifier = $returnValues.baseImageDataCenterIdentifier;

    # Write-Host $baseImageIdentifier
    # Write-Host $baseImageDataCenterIdentifier

    $baseImageSnapshotIdentifier = Get-BaseSnapshotIdentifier $sessionInfoParam $baseImageIdentifier $baseImageSnapshotPath

    # Write-Host $baseImageSnapshotIdentifier

    $vmfolderIdentifier = Get-VMFolderIdentifier $sessionInfoParam $baseImageDataCenterIdentifier $vmFolderPath

    # Write-Host $vmfolderIdentifier

    $clusterIdentifier = Get-HostOrClusterIdentifier $sessionInfoParam $baseImageDataCenterIdentifier $clusterPath

    # Write-Host $clusterIdentifier

    $resourcePathIdentifier = Get-ResourceIdentifier $sessionInfoParam $clusterIdentifier $ResourcesPath

    # Write-Host $resourcePathIdentifier

    $datastoreIdentifier = Get-DataStoreIdentifier $sessionInfoParam $clusterIdentifier $dataStorePath
    # Write-Host $datastoreIdentifier

    $nicIdentifier = Get-BaseSnapshotNICIdentifier $sessionInfoParam $baseImageSnapshotIdentifier $nicName
    # Write-Host $nicIdentifier

    $networkLabelId = Get-NetworkLabelByClusterID $sessionInfoParam $clusterIdentifier $networkLabelName
    # Write-Host $networkLabelId

    $accessGroupInfo = Get-AccessGroupInfo $sessionInfoParam $accessGroupName
    $accessGroupID = $accessGroupInfo.id

    $icDomainAdminID = $icDomainInfo.id;

    # Replace the hardcoded values with powershell variables where required.
    $desktopCreatePayload = @{ 
	    base = @{
		    name = "$desktopPoolName"
		    accessGroup = "$accessGroupID"
	    }
	    desktopSettings = @{
		    enabled = $true
		    cloudManaged = $false
		    cloudAssigned = $false
		    connectionServerRestrictions = $null
		    supportedSessionType = "DESKTOP"
		    displayAssignedMachineName = $false
		    displayMachineAlias = $false
		    clientRestrictions = $false
		    logoffSettings = @{
			    powerPolicy = "ALWAYS_POWERED_ON"
			    automaticLogoffPolicy = "NEVER"
			    automaticLogoffMinutes = 120
			    allowUsersToResetMachines = $false
			    allowMultipleSessionsPerUser = $false
			    refreshOsDiskAfterLogoff = "NEVER"
			    refreshPeriodDaysForReplicaOsDisk = 1
			    refreshThresholdPercentageForReplicaOsDisk = 1
			    emptySessionTimeoutPolicy = "AFTER"
			    emptySessionTimeoutMinutes = 1
			    preLaunchSessionTimeoutPolicy = "AFTER"
			    preLaunchSessionTimeoutMinutes = 10
			    logoffAfterTimeout = $false
			    deleteOrRefreshMachineAfterLogoff = "DELETE"
		    }
		    displayProtocolSettings  = @{
			    supportedDisplayProtocols =  @('PCOIP', 'RDP', 'BLAST')
			    defaultDisplayProtocol = "BLAST"
			    allowUsersToChooseProtocol = $true
			    pcoipDisplaySettings  = @{
				    renderer3D = "MANAGE_BY_VSPHERE_CLIENT"
				    enableGRIDvGPUs = $false
				    vRamSizeMB = 96
				    maxNumberOfMonitors = "2"
				    maxResolutionOfAnyOneMonitor = "WUXGA"
			    }
			    enableCollaboration = $false
		    }
		    mirageConfigurationOverrides  = @{
			    overrideGlobalSetting = $false
			    enabled = $false
		    }
	    }
	    type = "AUTOMATED"
	    automatedDesktopSpec  = @{
		    provisioningType = "INSTANT_CLONE_ENGINE"
		    virtualCenter = "$vCenterIdentifier"
		    userAssignment  = @{
			    userAssignment = "FLOATING"
			    automaticAssignment = $true
			    allowMultipleAssignments = $false
		    }
		    vmNamingSpec  = @{
			    namingMethod = "PATTERN"
			    patternNamingSettings  = @{
				    namingPattern = "$desktopNamePattern"
				    maxNumberOfMachines = 1
				    numberOfSpareMachines = 1
				    provisioningTime = "UP_FRONT"
			    }
		    }
		    virtualCenterProvisioningSettings  = @{
			    enableProvisioning = $true
			    stopProvisioningOnError = $true
			    minReadyVMsOnVComposerMaintenance = 0
			    addVirtualTPM = $false
			    virtualCenterStorageSettings  = @{
				    datastores = @(
                        @{
						    datastore = "$datastoreIdentifier"
						    sdrsCluster = $false
						    storageOvercommit = "UNBOUNDED"
					    }
                    )
				    useVSan = $false
				    viewStorageAcceleratorSettings  = @{
					    useViewStorageAccelerator = $true
					    viewComposerDiskTypes = "OS_DISKS"
					    regenerateViewStorageAcceleratorDays = 7
					    blackoutTimes = $null
				    }
				    viewComposerStorageSettings  = @{
					    useSeparateDatastoresReplicaAndOSDisks = $false
					    useNativeSnapshots = $false
					    spaceReclamationSettings  = @{
						    reclaimVmDiskSpace = $false
						    reclamationThresholdGB = 1
					    }
					    persistentDiskSettings  = @{
						    redirectWindowsProfile = $false
						    useSeparateDatastoresPersistentAndOSDisks = $false
						    diskSizeMB = 2048
						    persistentDiskDatastores = $null
					    }
					    nonPersistentDiskSettings  = @{
						    redirectDisposableFiles = $false
						    diskSizeMB = 4096
					    }
				    }
			    }
			    virtualCenterNetworkingSettings  = @{}
			    virtualCenterProvisioningData  = @{
				    datacenter = "$baseImageDataCenterIdentifier"
				    vmFolder = "$vmfolderIdentifier"
				    hostOrCluster = "$clusterIdentifier"
				    resourcePool = "$resourcePathIdentifier"
				    parentVm = "$baseImageIdentifier"
				    snapshot = "$baseImageSnapshotIdentifier"
			    }
		    }
		    virtualCenterManagedCommonSettings  = @{
			    transparentPageSharingScope = "VM"
		    }
		    customizationSettings  = @{
			    customizationType = "CLONE_PREP"
			    noCustomizationSettings  = @{
				    doNotPowerOnVMsAfterCreation = $false
			    }
			    adContainer = "$adContainerIdentifier"
			    reusePreExistingAccounts = $false
			    instantCloneEngineDomainAdministrator  = @{
				    id = "$icDomainAdminID"
				    base  = @{
					    id = "$icDomainID"
					    userName = "$icDomainAdminName"
					    password = @(42, 42, 42, 42, 42, 42, 42, 42)
				    }
				    namesData  = @{
					    dnsName = "$icDomainDNS"
				    }
			    }
			    cloneprepCustomizationSettings  = @{}
		    }
	    }
    };

    $desktopIdentifier = Add-DesktopPool $sessionInfoParam $desktopCreatePayload
    if ($desktopIdentifier) {
        Write-Host "Desktop pool `"$desktopPoolName`" created successfully!"
    }

}



# Modify the params as required. Move this to another Ps1 file for execution if required.
$sessionInfo = Send-LoginCS "administrator" "view.nj" "CS002.view.nj"
AddDesktopPool $sessionInfo
Invoke-LogoutCS $sessionInfo
