#######################################
# @Author Narendran Jothiram
# Horizon Engineer, EUC
#######################################

# Leave this as global variable. Only these host get exemption in ignoring certs if opted for it.
$global:ALLOWED_HOST_SKIP_CERTS = ""

# Do not rearrange the function ordering within this file.

function Invoke-LoginCS() {

    param(
       [Parameter(Mandatory = $true)]
       [string]$server,
       [Parameter(Mandatory = $true)]
       $loginParams,
       [Parameter(Mandatory = $false)]
       $skipCertCheck
    )
    $csName=$server
    $urlPrefix = "view-vlsi/rest/v1"
    $bodyContent = $loginParams | ConvertTo-Json
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Windows PowerShell Script"
    $uri="https://$csName/$urlPrefix/login"
    $origin='https://'+$csName
    $referer='https://'+$csName+'/admin'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Accept','Application/Json')
    $headers.Add('Origin', $origin)
    $headers.Add('Referer', $referer)
    $headers.Add('Accept-Encoding','gzip, deflate, br')
    $headers.Add('Accept-Language','en-US,en;q=0.9')
    
    if ($skipCertCheck) {
        $global:ALLOWED_HOST_SKIP_CERTS = $csName;
        class TrustAllCertsPolicy : System.Net.ICertificatePolicy {
            [bool] CheckValidationResult([System.Net.ServicePoint] $service,
                                         [System.Security.Cryptography.X509Certificates.X509Certificate] $cert,
                                         [System.Net.WebRequest] $request,
                                         [int] $value) {
                return ($request.RequestUri.Host -eq $global:ALLOWED_HOST_SKIP_CERTS);
            }
        }
        [System.Net.ServicePointManager]::CertificatePolicy = [TrustAllCertsPolicy]::new()
    }
    Write-Host "Send login request " $uri
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri `
        -Method "POST" `
        -WebSession $session `
        -Headers $headers `
        -ContentType "application/json; charset=UTF-8" `
        -Body $bodyContent;
        if($response -ne $null) {
            $csrfToken = $response.Headers['CSRFToken']
            $headers.Add('CSRFToken', $csrfToken)

            return @{"urlPrefix"= "https://$csName/$urlPrefix"; "session"= $session;
            "headers"= $headers}
        }
        return $null
    } catch {
       Write-Host $_
       throw "Login failed on $server"
    }
}

function Invoke-LogoutCS() {
   param(
        $sessionInfo
    )
    try {
        $uriPrefix = $sessionInfo.urlPrefix
        $logoutUri = "$uriPrefix/logout"
         Write-Host "Send logout request " $logoutUri
        $response = Invoke-WebRequest -UseBasicParsing -Uri $logoutUri `
        -Method "POST" `
        -WebSession $sessionInfo.session `
        -Headers $sessionInfo.headers `
        -ContentType "application/json; charset=UTF-8" -Body "null";
    } catch {
       Write-Host $_
    }
}

function Invoke-ResponseErrorHandler($Error) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Error.Exception.Response) {  
            $Reader = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}

function Invoke-HorizonGetMethod() {
    param(
        $sessionInfo,
        $uriSuffix
    )
    try {
        $uriPrefix = $sessionInfo.urlPrefix
        $uri = "$uriPrefix/$uriSuffix"
        Write-Host "GET -> " $uri 
        $response = Invoke-RestMethod -UseBasicParsing -Uri $uri `
            -Method "GET" `
            -WebSession $sessionInfo.session `
            -Headers $sessionInfo.headers `
            -ContentType "application/json; charset=UTF-8";
            return $response
    } catch {
       $response = Invoke-ResponseErrorHandler($_)
       Write-Host $response
    }
}

function Invoke-HorizonPostMethod() {
    param(
        $sessionInfo,
        $uriSuffix,
        $payload
    )
    try {
        $uriPrefix = $sessionInfo.urlPrefix
        $uri = "$uriPrefix/$uriSuffix"
        $payloadJSON =  (ConvertTo-Json -Depth 10 $payload)
        Write-Host "POST -> " $uri 
        $response = Invoke-RestMethod -UseBasicParsing -Uri $uri `
            -Method "POST" `
            -WebSession $sessionInfo.session `
            -Headers $sessionInfo.headers `
            -ContentType "application/json; charset=UTF-8" -Body $payloadJSON;
            return $response
    } catch {
       $response = Invoke-ResponseErrorHandler($_)
       Write-Host $response
    } 
}

function Get-ADDomainList() {
    param(
        $sessionInfo
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "InstantCloneEngineDomainAdministrator/List"
    } catch {
       Write-Host $_
    }
}

function Get-ADContainerByDomain() {

    param (
        $sessionInfo,
        $adContainerPayload
    )
    try {
        return Invoke-HorizonPostMethod $sessionInfo "ADContainer/getContainerByDomain" $adContainerPayload
    } catch {
       Write-Host $_
    }
}

function Get-ADContainerByRDN() {

    param (
        $sessionInfo,
        $adContainerPayload
    )
    try {
        return Invoke-HorizonPostMethod $sessionInfo "ADContainer/findContainerRDNByDomain" $adContainerPayload
    } catch {
       Write-Host $_
    }
}

function Get-VirtualCenterList() {
    param (
        $sessionInfo
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "VirtualCenter/List"
    } catch {
       Write-Host $_
    }
}

#
# Expensive listing API call as it returns all the virtual machines belonging to specified vcenter
# For automation, fetch it once and use it and reload it only when required!
#
# @Author: Neha Agarwal
#
function Get-VirtualMachineList() {
	param (   
		$sessionInfo ,
		$vCenterIdentifier
    )	

	try {       
		return Invoke-HorizonGetMethod $sessionInfo "VirtualMachine/list?id=$vCenterIdentifier"} 
	catch { 
		Write-Host $_
	}
}

function Get-BaseImageVMList() {

    param (
        $sessionInfo,
        $vCenterPayload
    )
    # List the BaseImage VMs.
    try {
        return Invoke-HorizonPostMethod $sessionInfo "BaseImageVm/list" $vCenterPayload
    } catch {
       Write-Host $_
    }
}

function Get-BaseImageSnapshotList() {
    param (
        $sessionInfo,
        $baseImageIdentifier
    )
    # List of snapshots for base image identifer
    try {
        return Invoke-HorizonGetMethod $sessionInfo "BaseImageSnapshot/list?id=$baseImageIdentifier"
    } catch {
       Write-Host $_
    }
}

function Get-VMFolderTree() {
    param (
        $sessionInfo,
        $dataCenterIdentifier
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "VmFolder/GetVmFolderTree?id=$dataCenterIdentifier"
    } catch {
       Write-Host $_
    }
}

function Get-HostOrClusterTree() {
    param (
        $sessionInfo,
        $dataCenterIdentifier
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "HostOrCluster/GetHostOrClusterTree?id=$dataCenterIdentifier"
    } catch {
       Write-Host $_
    }
}

function Get-ResourcePoolTree() {
    param (
        $sessionInfo,
        $hostOrClusterIdentifier
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "ResourcePool/GetResourcePoolTree?id=$hostOrClusterIdentifier"
    } catch {
       Write-Host $_
    }
}

function Get-DataStoreList() {
    param (
        $sessionInfo,
        $hostOrClusterIdentifier
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "Datastore/ListDatastoresByHostOrCluster?id=$hostOrClusterIdentifier"
    } catch {
       Write-Host $_
    }
}
function Get-BaseImageSnapshotNICs() {
    param (
        $sessionInfo,
        $baseImageSnapshotParam
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "NetworkInterfaceCard/ListBySnapshot?id=$baseImageSnapshotParam"
    } catch {
       Write-Host $_
    }
}

function Get-NetworkLabelListByClusterID() {
    param (
        $sessionInfo,
        $clusterIdentifierParam
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "NetworkLabel/ListByHostOrCluster?id=$clusterIdentifierParam"
    } catch {
       Write-Host $_
    }
}

function Get-AccessGroupList() {
    param(
        $sessionInfo
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "AccessGroup/list"
    } catch {
       Write-Host $_
    }
}

function Get-GlobalAccessGroupList() {
    param(
        $sessionInfo
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "GlobalAccessGroup/list"
    } catch {
       Write-Host $_
    }
}

function Get-AccessGroupInfo() {
    param(
        $sessionInfo,
        $accessGroupName
    )
    $accessGroupList = Get-AccessGroupList $sessionInfo
    $accessGroupInfo = ""
    foreach($data in $accessGroupList) {
        if ($data.base.name -eq $accessGroupName) {
            $accessGroupInfo = $data
            break
        }
    }
    return $accessGroupInfo
}

function Get-GlobalAccessGroupInfo() {
    param(
        $sessionInfo,
        $accessGroupName
    )
    $accessGroupList = Get-GlobalAccessGroupList $sessionInfo
    $accessGroupInfo = ""
    foreach($data in $accessGroupList) {
        if ($data.base.name -eq $accessGroupName) {
            $accessGroupInfo = $data
            break
        }
    }
    return $accessGroupInfo
}

function Get-RootAccessGroupID() {
    param(
        $sessionInfo
    )
    $accessGroupList = Get-AccessGroupList $sessionInfo
    $rootAccessID = ""
    foreach($data in $accessGroupList) {
        if ($data.base.name -eq "Root") {
            $rootAccessID = $data.id
            break
        }
    }
    return $rootAccessID
}

function Get-RootGlobalAccessGroupID() {
    param(
        $sessionInfo
    )
    $accessGroupList = Get-GlobalAccessGroupList $sessionInfo
    $rootAccessID = ""
    foreach($data in $accessGroupList) {
        if ($data.base.name -eq "Root") {
            $rootAccessID = $data.id
            break
        }
    }
    return $rootAccessID
}

function Get-VSANConfigStatus() {
    param (
        $sessionInfo,
        $vCenterIdentifier
    )
    # Check if VSAN is configured in vCenter Server
    try {
        return Invoke-HorizonGetMethod $sessionInfo "VirtualSAN/IsSupportedByVirtualCenter?id=$vCenterIdentifier"
    } catch {
       Write-Host $_
    }
}

function Invoke-ValidateName() {
   param (
        $sessionInfo,
        $validatePayload
    )
    $validatePayloadJson = $validatePayload | ConvertTo-JSON
    try {
        return Invoke-HorizonGetMethod $sessionInfo "Validator/validateName"
    } catch {
       Write-Host $_
    }
}

# Tree data to have identifier as "data.id" or "data.path" or data.info.id
function Convert-TreeAsHashMap() {
    param(
       $treeData,
       $hashMapVariable
    )
    foreach( $data in $treeData) {
        if($data.id) {
            $hashMapVariable.Add($data.id, $data);
        }
        if($data.info.id) {
            $hashMapVariable.Add($data.info.id, $data);
        }
        if($data.path) {
            $hashMapVariable.Add($data.path, $data);
        }
        if ($data.children) {
            Convert-TreeAsHashMap $treeData.children $hashMapVariable
        }
    }
}

##
# For View API, query identifier is returned for query services and it has to be deleted for cleaning up the resources after its use.
##
function Clear-QueryById() {
     param(
        [Parameter(Mandatory = $true)]
        $sessionInfo,
        [Parameter(Mandatory = $true)]
        [string]
        $queryID
    )
    # Cleanup the query resources
    $payload1 = @{ id = $queryID }
    try {
        $response = Invoke-HorizonPostMethod $sessionInfo "queryservice/delete" $payload1
    } catch {
       Write-Host $_
       throw "Failed to delete query by identifier $queryID"
    }
}

#
# Get the desktop pool filtered by name and virtual center identifier
#
function Get-DesktopPoolByName() {

    param(
        $sessionInfo,
        $desktopPoolName,
        $vCenterIdentifier
    )

	$payload = @{
        entityType = "DesktopSummaryView"
        queryEntityType = "DesktopSummaryView"
        filter = @{ 
            type = "Equals"
            memberName = "desktopSummaryData.name"
            value = $desktopPoolName
        }
    }
    $responseData = $null
    try {
         $responseData = Invoke-HorizonPostMethod $sessionInfo "queryservice/create" $payload
         if ( $responseData -ne $null) {
             $payload = @{ id = $responseData.id }
             Clear-QueryById $sessionInfo $responseData.id             
             if ($responseData.results[0].desktopSummaryData.virtualCenter -eq $vCenterIdentifier) {
                return $responseData.results[0]
             }
             throw "No desktop pool found!";
         }
         
    } catch {
       Write-Host $_
    }
    return $null
}

function Add-DesktopPool() {

    param (
        $sessionInfo,
        $desktopPayload
    )
    try {
        return Invoke-HorizonPostMethod $sessionInfo "desktop/create" $desktopPayload
    } catch {
       Write-Host $_
    }
}


####################################################################
# @Author: Neha Agarwal
# Description: Add virtual machines to existing manual desktop pool
####################################################################
function Add-MachinesToManualDesktop()
{
	param (       
		$sessionInfo,
		$desktopId,
		$vmIdList
    )
  
	$payload = @{
        id = $desktopId
        machines = $vmIdList
    }

	try {
       $response = Invoke-HorizonPostMethod $sessionInfo "Desktop/AddMachinesToManualDesktop" $payload
       if ($response -ne $null) {
            if($response.message -ne $null) {
                throw "Failed to add machine $response"
            } else{
                Write-Host "Machines added to desktop pool!"
                return $response
            }
       }
    } catch {
       Write-Host $_
    }
	return $null
}

function Add-CustomRole() {

    param(
        [Parameter(Mandatory = $true)]
        $sessionInfoParam,

        # CustomRoleName with only Alphanumeric characters and no space or special chars
        [Parameter(Mandatory = $true)]
        [string]
        $customRoleName,

        # Description about the custom role
        [Parameter(Mandatory = $true)]
        [string]
        $description,

        # Privileges array in the format Example: @("LOG_COLLECTION", "GLOBAL_VIEW")
        [Parameter(Mandatory = $true)]
        $privilegesList

    )
    $payload = @{
        description=$description
        privileges=$privilegesList
        name=$customRoleName
    }
    try {
       $response = Invoke-HorizonPostMethod $sessionInfoParam "Role/Create" $payload
       if ($response -ne $null) {
            Write-Host "New custom role $customRoleName with identifier $response created successfully!"
       }
    } catch {
       Write-Host $_
       throw "Add custom role failed!"
    }

}


##
# Provided full AD user name as input, it finds the AD user.
# Sample payload: {"queryEntityType":"ADUserOrGroupSummaryView","startingOffset":0,"limit":1000,"filter":{"type":"And",
# "filters":[{"type":"Equals","memberName":"base.group","value":false},{"type":"StartsWith","memberName":"base.name","value":"log"},
# {"type":"Equals","memberName":"base.domain","value":"view.nj"}]}}
##
function Find-ADUserByName() {
     param(
        [Parameter(Mandatory = $true)]
        $sessionInfo,
        [Parameter(Mandatory = $true)]
        [string]
        $fullADUserName,
        [Parameter(Mandatory = $true)]
        [string]
        $domainFQDN
    )

	$payload = @{
        entityType = "ADUserOrGroupSummaryView"
        queryEntityType = "ADUserOrGroupSummaryView"
        limt = 1
        filter = @{ 
            type = "And"
            filters = @(
                @{
                    type = "StartsWith"
                    memberName = "base.name"
                    value = $fullADUserName
                },
                @{
                    type = "Equals"
                    memberName = "base.group"
                    value = $false
                },
                @{
                    type = "Equals"
                    memberName = "base.domain"
                    value = $domainFQDN
                }
            )
        }
    }
    try {
         $responseData = Invoke-HorizonPostMethod $sessionInfo "queryservice/create" $payload
         if ($responseData -ne $null -And $responseData.results -ne $null) {
             $userInfo = $responseData.results[0]
             Clear-QueryById $sessionInfo $responseData.id
             return $userInfo
         } else {
             throw "No AD user found!"
         }
         
    } catch {
       Write-Host $_
       throw "No AD user found!"
    }
}

##
# List of available roles in horizon enterprise
##
function Get-HorizonRoleList() {
    param(
        [Parameter(Mandatory = $true)]
        $sessionInfo
    )
    try {
        return Invoke-HorizonGetMethod $sessionInfo "Role/List"
    } catch {
       Write-Host $_
       throw "List Role API failed to get executed!"
    }
}



###############
# START HELPERS
###############


# Credits to Matt Frey for adding PSCredential
function Send-LoginCS () {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $servername,
        [Parameter(Mandatory = $true)]
        [string]
        $ignoreCert,
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $loginParams = @{}
    if ($PSBoundParameters.ContainsKey('credential')) {
        $loginParams = @{
            name = $Credential.GetNetworkCredential().UserName
            passwd = $Credential.GetNetworkCredential().Password
            domain = $Credential.GetNetworkCredential().Domain
        }
        $server=$servername
    }

    # Session Info required for other API requests on same logged in session.
    # The third parameter to be set as $false for production environments
    $sessionInfo = Invoke-LoginCS $server $loginParams $ignoreCert

    # Reset login payload.
    $loginParams = "";

    return $sessionInfo;
}

function Get-HorizonRoleByName() {
     param(
        [Parameter(Mandatory = $true)]
        $sessionInfo,
        [Parameter(Mandatory = $true)]
        [string]
        $customRoleName
    )
    try {
        $roles = Get-HorizonRoleList $sessionInfo
        foreach ($role in $roles) {
            if ($role.base.name -eq $customRoleName) {
                return $role
            }
        }
    } catch {
       Write-Host $_
       throw "List Role API failed to get executed!"
    }
    return $null
}

##
# Add an user to existing role.
# Use custom AccessGroupId and GlobalAccessGroupId if granular RBAC required for that user
##
function Add-HorizonAdminToRole() {
    param(
        [Parameter(Mandatory = $true)]
        $sessionInfo,
        [Parameter(Mandatory = $true)]
        [string]
        $userId,
        [Parameter(Mandatory = $true)]
        [string]
        $customRoleName,
        [Parameter(Mandatory = $false)]
        [string]
        $accessGroupId,
        [Parameter(Mandatory = $false)]
        [string]
        $globalAccessGroupId
    )
    $role = Get-HorizonRoleByName $sessionInfo $customRoleName
    if ($role) {
        if (-Not ($psBoundParameters.containsKey('accessGroupId'))) {
            $accessGroupId = Get-RootAccessGroupID $sessionInfo
        }
        if ($role.data.appliesToGlobalAccessGroup) {
            if (-Not ($psBoundParameters.containsKey('globalAccessGroupId'))) {
                $globalAccessGroupId = Get-RootGlobalAccessGroupID $sessionInfo
            }
        }

        $payload = @(
            @{
                userOrGroup = $userId
                role = $role.id
                accessGroup = $accessGroupId
            }
        )
        if ($role.data.appliesToGlobalAccessGroup) {
            $payload = @(
                @{
                    userOrGroup = $userId
                    role = $role.id
                    accessGroup = $accessGroupId
                },
                @{
                    userOrGroup = $userId
                    role = $role.id
                    globalAccessGroup = $globalAccessGroupId
                }
            )
        }
        try {
            # uncomment for debugging purpose
            # Write-Host (ConvertTo-JSON -depth 10 $payload)
            $responseData = Invoke-HorizonPostMethod $sessionInfo "Permission/CreatePermissions" $payload
        } catch {
           Write-Host $_
           throw "Failed to add user to role $customRoleName"
        }
    }
}

function Get-ADDomainInfo() {
    param(
       $sessionInfo,
       $icdomainDNS,
       $icDomainAdminName
    )
    $adDomains = Get-ADDomainList $sessionInfo

    # Select domain identifier from dnsName and IC domain admin user name
    $icDomain = $null
    foreach($data in $adDomains) {
       if ($icDomainDNS -eq $data.namesData.dnsName -And $data.base.userName -eq $icDomainAdminName) {
         $icDomain=$data
         break;
       }
    }
    if ($icDomain -eq $null) {
        throw "AD Domain information not found. Check the domain dnsname input and ensure no space append at the end."
    }
    return $icDomain
}


function Get-ADContainerIdentifier() {
    
    param(
       $sessionInfo,
       $icDomainID,
       $adContainerVDI
    )
    
    $parts = $icDomainID.split("/");
    $domainSIDEncoded = $parts[$parts.length - 1];
    $domainIDEncoded = $parts[$parts.length - 2];
    $adContainerIdentifier = "ADContainer/$domainIDEncoded/$domainSIDEncoded/" + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($adContainerVDI))
    # Payload to find AD Container by Identifier
    $adContainerByIdPayload = @{
        domain = "$icDomainID"
        containerId = "$adContainerIdentifier"
    }
    $adIdentifierInfo = Get-ADContainerByDomain $sessionInfo $adContainerByIdPayload
    if ($adIdentifierInfo -eq $null) {
        throw "AD Container Identifier not found";
    }
    return $adIdentifierInfo.id;
}


function Get-VCenterInfo() {
    param(
        $sessionInfo,
        $Vcenter
    )
    $vcenterList = Get-VirtualCenterList $sessionInfo
    $vcInfo = "";
    foreach($data in $vcenterList) {
        if ($Vcenter -eq $data.serverSpec.serverName) {
            $vcInfo=$data
            break;
        }
    }
    return $vcInfo
}


# Example allowed values are DESKTOP, FARM, MACHINE
function Get-ValidateNameStatus() {
    param(
        $sessionInfo,
        $name,
        $type
    )
    # Validate name uniqueness before sending to Create API
    $validateMachineNamePatternPayload = @{
        "name" = $name
        "type" = $type
    }
    $nameStatus = Invoke-ValidateName $sessionInfo $validateDesktopNamePatternPayload
    return $nameStatus.isUnique

}

function Get-BaseImageAndDataCenterIdentifier() {

    param (
        $sessionInfo,
        $vCenterIdentifier,
        $baseImagePath
    )
    # Post payload to BaseImage VM List
    $vCenterIdentifierInfo = @{
        "virtualCenter" = $vCenterIdentifier
        "filterIncompatibleVms" = $true
    }

    $baseImageList = Get-BaseImageVMList $sessionInfo $vCenterIdentifierInfo

    # Uncomment this line for debugging purpose
    # Write-Host ($baseImageList | Format-List | Out-String)

    $returnValues = @{}
    foreach($data in $baseImageList) {
        if ($baseImagePath -eq $data.path) {
            $returnValues.Add("baseImageIdentifier", $data.id);
            $returnValues.Add("baseImageDataCenterIdentifier", $data.datacenter);
        }
    }
    return $returnValues;
}


function Get-BaseSnapshotIdentifier() {

    param(
        $sessionInfo,
        $baseImageIdentifier,
        $baseImageSnapshotPath

    )
    $snapshotsList = Get-BaseImageSnapshotList $sessionInfo $baseImageIdentifier

    # Uncomment this line for debugging purpose
    # Write-Host ($snapshotsList | Format-List | Out-String)
    $baseImageSnapshotIdentifierLocal = ""
    foreach($data in $snapshotsList) {
        if ($baseImageSnapshotPath -eq $data.path) {
            $baseImageSnapshotIdentifierLocal =$data.id
        }
    }
    return $baseImageSnapshotIdentifierLocal;
}


function Get-VMFolderIdentifier() {
    param(
       $sessionInfo,
       $baseImageDataCenterIdentifier,
       $vmFolderPathParam
    )
    # Fetch list of Folders in datacenter to choose an folder from it.
    $vmfolderTreeList = Get-VMFolderTree $sessionInfo $baseImageDataCenterIdentifier

    # Write-Host ($vmfolderTreeList | Format-List | Out-String)

    # $vmfolderIdentifier = find-VmFolderPath $vmfolderTreeList


    $vmFolderInfo = @{}

    Convert-TreeAsHashMap $vmfolderTreeList $vmFolderInfo

    foreach ($enumObj in $vmFolderInfo.getEnumerator()) {
        if ( $enumObj.value.folderData.path -eq $vmFolderPathParam ) {
            $vmfolderIdentifier = $enumObj.key
        }
    }

    Clear-Variable -Name "vmFolderInfo"

    return $vmfolderIdentifier
}


function Get-HostOrClusterIdentifier() {
    param(
       $sessionInfo,
       $baseImageDataCenterIdentifier,
       $clusterPathParam
    )
    # Fetch list of Folders in datacenter to choose an folder from it.
    $clusterTreeList = Get-HostOrClusterTree $sessionInfo $baseImageDataCenterIdentifier

    # Write-Host ($clusterTreeList | Format-List | Out-String)

    $clusterIdentifier = "";
    foreach ($enumObj in $clusterTreeList.treeContainer.children) {
        if ( $enumObj.info.path -eq $clusterPathParam ) {
            $clusterIdentifier = $enumObj.info.id
        }
    }
    return $clusterIdentifier
}

function Get-ResourceIdentifier() {
    param(
       $sessionInfo,
       $clusterIdentifier,
       $ResourcePathParam
    )
    $ResourcePoolTree = Get-ResourcePoolTree $sessionInfo $clusterIdentifier

    $ResourcePoolList = @{}

    Convert-TreeAsHashMap $ResourcePoolTree $ResourcePoolList

    # Write-Host ($ResourcePoolList | Format-List | Out-String)

    $resourcePathIdentifier = ""
    foreach ($enumObj in $ResourcePoolList.getEnumerator()) {
        if ( $enumObj.value.resourcePoolData.path -eq $ResourcePathParam ) {
            $resourcePathIdentifier = $enumObj.key
        }
    }
    return $resourcePathIdentifier;
}

function Get-DataStoreIdentifier() {
    param(
       $sessionInfo,
       $clusterIdentifier,
       $DataStorePathParam
    )
    $dataStoreList = Get-DataStoreList $sessionInfo $clusterIdentifier
    $identifier = ""
    foreach($data in $dataStoreList) {
        if ($DataStorePathParam -eq $data.datastoreData.path) {
            $identifier=$data.id
        }
    }
    return $identifier
}

function Get-BaseSnapshotNICIdentifier() {
    param(
       $sessionInfo,
       $BaseImageSnapshotIdParam,
       $nicNameParam
    )
    $dataStoreList = Get-BaseImageSnapshotNICs $sessionInfo $BaseImageSnapshotIdParam
    $identifier = ""
    foreach($data in $dataStoreList) {
        if ($nicNameParam -eq $data.data.name) {
            $identifier=$data.id
        }
    }
    return $identifier
}

function Get-NetworkLabelByClusterID() {
    param(
       $sessionInfo,
       $clusterIdentifierParam,
       $networkLabelName
    )
    $dataStoreList = Get-NetworkLabelListByClusterID $sessionInfo $clusterIdentifierParam
    $identifier = ""
    foreach($data in $dataStoreList) {
        if ($networkLabelName -eq $data.data.name) {
            $identifier=$data.id
        }
    }
    return $identifier
}

#
# Credits to Matt Frey for adding it as helper method
#
function New-DesktopPool() {

    param(
        [Parameter(Mandatory = $true)]
        $sessionInfoParam,

        # Desktop pool Name. Set a unique name each time
        [Parameter(Mandatory = $true)]
        [string]
        $desktopPoolName,

        # Desktop pool Display Name. Set a unique name each time
        [Parameter(Mandatory = $true)]
        [string]
        $displayName,

        # Name pattern of VMs
        [Parameter(Mandatory = $true)]
        [string]
        $desktopNamePattern,

        # Change to custom access group name when required
        [Parameter(Mandatory = $false)]
        [string]
        $accessGroupName = "Root",

        # dns name of domain to get matched for domain identification
        [Parameter(Mandatory = $true)]
        [string]
        $icDomainDNS,

        # Admin user account registered in horizon
        [Parameter(Mandatory = $true)]
        [string]
        $icDomainAdminName,

        # Container path where the Instant Clone machines accounts gets created in AD
        [Parameter(Mandatory = $true)]
        [string]
        $adContainerVDI,

        # Enter the vCenter address or hostname registered with horizon. If horizon uses hostname of Vcenter, do not enter IP address
        [Parameter(Mandatory = $true)]
        [string]
        $Vcenter,

        # Set the value suitable for your environment for using it as master image for desktop pool creation
        [Parameter(Mandatory = $true)]
        [string]
        $baseImage,

        # Update this value for automation.
        [Parameter(Mandatory = $true)]
        [string]
        $baseImageSnapshot,

        # Datacenter Name
        [Parameter(Mandatory = $true)]
        [string]
        $datacenter,

        # VM Folder Path in Datacenter. Update this value for automation.
        [Parameter(Mandatory = $true)]
        [string]
        $vmFolderPath,

        # cluster path. Modify it for automation needs
        [Parameter(Mandatory = $true)]
        [string]
        $clusterPath,

        # Customizable input
        [Parameter(Mandatory = $true)]
        [string]
        $ResourcesPath,

        # Use the desired datastore path. For now adding one DS path. Extend it according to the needs.
        [Parameter(Mandatory = $true)]
        [string]
        $dataStorePath,

        # Set the name of NIC card for finding identifier from list
        [Parameter(Mandatory = $false)]
        [string]
        $nicName,

        # Change to the desired network name
        [Parameter(Mandatory = $false)]
        [string]
        $networkLabelName,

        [Parameter(Mandatory = $false)]
        [int]
        $MinimumCount = 1,
        
        [Parameter(Mandatory = $true)]
        [int]
        $MaximumCount,

        [Parameter(Mandatory = $true)]
        [int]
        $SpareCount,

        [Parameter(Mandatory = $false)]
        [string]
        $provisioningTime = "UP_FRONT",

        [Parameter(Mandatory = $false)]
        [string]
        $userAssignment = "FLOATING",

        [Parameter(Mandatory = $false)]
        [bool]
        $allowUsersToResetMachines = $false,

        [Parameter(Mandatory = $false)]
        [bool]
        $allowMultipleSessionsPerUser = $false,

        [Parameter(Mandatory = $false)]
        [string]
        $deleteOrRefreshMachineAfterLogoff = "DELETE",

        [Parameter(Mandatory = $false)]
        [string]
        $refreshOsDiskAfterLogoff = "NEVER",

        [Parameter(Mandatory = $false)]
        [string[]]
        $supportedDisplayProtocols =  @('PCOIP', 'RDP', 'BLAST'),

        [Parameter(Mandatory = $false)]
        [string]
        $renderer3D = "MANAGE_BY_VSPHERE_CLIENT",

        [Parameter(Mandatory = $false)]
        [bool]
        $enableGRIDvGPUs = $false,

        [Parameter(Mandatory = $false)]
        [int]
        $maxNumberOfMonitors = 2,

        [Parameter(Mandatory = $false)]
        [string]
        $maxResolutionOfAnyOneMonitor = "WUXGA",

        [Parameter(Mandatory = $false)]
        [bool]
        $useViewStorageAccelerator = $false,

        [Parameter(Mandatory = $false)]
        [bool]
        $enableProvisioning = $true,

        [Parameter(Mandatory = $false)]
        [bool]
        $stopProvisioningOnError = $false,

        [Parameter(Mandatory = $false)]
        [string]
        $namingMethod = "PATTERN",

        [Parameter(Mandatory = $false)]
        [bool]
        $reclaimVmDiskSpace = $false,

        [Parameter(Mandatory = $false)]
        [bool]
        $redirectWindowsProfile = $false,

        [Parameter(Mandatory = $false)]
        [string]
        $storageOvercommit = "UNBOUNDED",

        [Parameter(Mandatory = $false)]
        [bool]
        $useNativeSnapshots = $false,

        [Parameter(Mandatory = $false)]
        [bool]
        $useVsan = $false,

        [Parameter(Mandatory = $false)]
        [string]
        $defaultDisplayProtocol = "BLAST",

        [Parameter(Mandatory = $false)]
        [bool]
        $allowUsersToChooseProtocol = $true,

        [Parameter(Mandatory = $false)]
        [Int]
        $automaticLogoffMinutes = 120,

        [Parameter(Mandatory = $false)]
        [string]
        $automaticLogoffPolicy = "AFTER",

        [Parameter(Mandatory = $false)]
        [string]
        $powerOffScriptName = "",

        [Parameter(Mandatory = $false)]
        [string]
        $powerOffScriptParameters = "",

        [Parameter(Mandatory = $false)]
        [string]
        $postSynchronizationScriptName = "",

        [Parameter(Mandatory = $false)]
        [string]
        $postSynchronizationScriptParameters = "",

        [Parameter(Mandatory = $false)]
        [string]
        $primingComputerAccount = ""

    )


    # Start fetching identifiers for invoking create desktop pool #

    $icDomainInfo = Get-ADDomainInfo $sessionInfoParam $icDomainDNS $icDomainAdminName

    $icDomainID = $icDomainInfo.base.domain

    Write-Host $icDomainID

    $adContainerIdentifier = Get-ADContainerIdentifier $sessionInfoParam $icDomainID $adContainerVDI
    Write-Host $adContainerIdentifier

    $vCenterInfo = Get-VCenterInfo $sessionInfoParam $Vcenter
    $vCenterIdentifier = $vCenterInfo.id
    # Write-Host $vCenterIdentifier

    $returnValues = Get-BaseImageAndDataCenterIdentifier $sessionInfoParam $vCenterIdentifier $baseImage

    $baseImageIdentifier = $returnValues.baseImageIdentifier;
    $baseImageDataCenterIdentifier = $returnValues.baseImageDataCenterIdentifier;

    # Write-Host $baseImageIdentifier
    # Write-Host $baseImageDataCenterIdentifier

    $baseImageSnapshotIdentifier = Get-BaseSnapshotIdentifier $sessionInfoParam $baseImageIdentifier $baseImageSnapshot

    # Write-Host $baseImageSnapshotIdentifier

    $vmfolderIdentifier = Get-VMFolderIdentifier $sessionInfoParam $baseImageDataCenterIdentifier $vmFolderPath

    # Write-Host $vmfolderIdentifier

    $clusterIdentifier = Get-HostOrClusterIdentifier $sessionInfoParam $baseImageDataCenterIdentifier $clusterPath

    # Write-Host $clusterIdentifier

    $resourcePathIdentifier = Get-ResourceIdentifier $sessionInfoParam $clusterIdentifier $ResourcesPath

    # Write-Host $resourcePathIdentifier

    $datastoreIdentifier = Get-DataStoreIdentifier $sessionInfoParam $clusterIdentifier $dataStorePath
    # Write-Host $datastoreIdentifier

    #$nicIdentifier = Get-BaseSnapshotNICIdentifier $sessionInfoParam $baseImageSnapshotIdentifier $nicName
    # Write-Host $nicIdentifier

    #$networkLabelId = Get-NetworkLabelByClusterID $sessionInfoParam $clusterIdentifier $networkLabelName
    # Write-Host $networkLabelId

    $accessGroupInfo = Get-AccessGroupInfo $sessionInfoParam $accessGroupName
    $accessGroupID = $accessGroupInfo.id

    $icDomainAdminID = $icDomainInfo.id;

    $minNumOfMachines = $MinimumCount;
    if ($provisioningTime -eq "UP_FRONT") {
        $minNumOfMachines = $MaximumCount;
    }   
    # Replace the hardcoded values with powershell variables where required.
    $desktopCreatePayload = @{
        base = @{
            name = "$desktopPoolName"
            accessGroup = "$accessGroupID"
            displayName = "$displayName"
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
                automaticLogoffPolicy = "$automaticLogoffPolicy"
                automaticLogoffMinutes = $automaticLogoffMinutes
                allowUsersToResetMachines = $allowUsersToResetMachines
                allowMultipleSessionsPerUser = $allowMultipleSessionsPerUser
                refreshOsDiskAfterLogoff = "$refreshOsDiskAfterLogoff"
                refreshPeriodDaysForReplicaOsDisk = 1
                refreshThresholdPercentageForReplicaOsDisk = 1
                emptySessionTimeoutPolicy = "AFTER"
                emptySessionTimeoutMinutes = 1
                preLaunchSessionTimeoutPolicy = "AFTER"
                preLaunchSessionTimeoutMinutes = 10
                logoffAfterTimeout = $false
                deleteOrRefreshMachineAfterLogoff = "$deleteOrRefreshMachineAfterLogoff"
            }
            displayProtocolSettings  = @{
                supportedDisplayProtocols =  $supportedDisplayProtocols
                defaultDisplayProtocol = "$defaultDisplayProtocol"
                allowUsersToChooseProtocol = $allowUsersToChooseProtocol
                pcoipDisplaySettings  = @{
                    renderer3D = $renderer3D
                    enableGRIDvGPUs = $enableGRIDvGPUs
                    vRamSizeMB = 96
                    maxNumberOfMonitors = $maxNumberOfMonitors
                    maxResolutionOfAnyOneMonitor = "$maxResolutionOfAnyOneMonitor"
                }
                enableCollaboration = $false
            }
            mirageConfigurationOverrides  = @{
                overrideGlobalSetting = $false
                enabled = $false
            }
            shortcutLocations = $null
        }
        type = "AUTOMATED"
        automatedDesktopSpec  = @{
            provisioningType = "INSTANT_CLONE_ENGINE"
            virtualCenter = "$vCenterIdentifier"
            userAssignment  = @{
                userAssignment = "$userAssignment"
                automaticAssignment = $true
                allowMultipleAssignments = $false
            }
            vmNamingSpec  = @{
                namingMethod = "$namingMethod"
                patternNamingSettings  = @{
                    namingPattern = "$desktopNamePattern"
                    maxNumberOfMachines = "$MaximumCount"
                    minNumberOfMachines = "$minNumOfMachines"
                    numberOfSpareMachines = $SpareCount
                    provisioningTime = "$provisioningTime"
                }
            }
            virtualCenterProvisioningSettings  = @{
                enableProvisioning = $enableProvisioning
                stopProvisioningOnError = $stopProvisioningOnError
                minReadyVMsOnVComposerMaintenance = 0
                addVirtualTPM = $false
                virtualCenterStorageSettings  = @{
                    datastores = @(
                        @{
                            datastore = "$datastoreIdentifier"
                            sdrsCluster = $false
                            storageOvercommit = "$storageOvercommit"
                        }
                    )
                    useVSan = $useVSan
                    viewStorageAcceleratorSettings  = @{
                        useViewStorageAccelerator = $useViewStorageAccelerator
                        viewComposerDiskTypes = "OS_DISKS"
                        regenerateViewStorageAcceleratorDays = 7
                        blackoutTimes = $null
                    }
                    viewComposerStorageSettings  = @{
                        useSeparateDatastoresReplicaAndOSDisks = $false
                        useNativeSnapshots = $useNativeSnapshots
                        spaceReclamationSettings  = @{
                            reclaimVmDiskSpace = $reclaimVmDiskSpace
                            reclamationThresholdGB = 1
                        }
                        persistentDiskSettings  = @{
                            redirectWindowsProfile = $redirectWindowsProfile
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
                        domain = "$icDomainID"
                        userName = "$icDomainAdminName"
                        password = @(42, 42, 42, 42, 42, 42, 42, 42)
                    }
                    namesData  = @{
                        dnsName = "$icDomainDNS"
                    }
                }
                cloneprepCustomizationSettings  = @{
                    #powerOffScriptName = $powerOffScriptName
                    #powerOffScriptParameters = $powerOffScriptParameters
                    #postSynchronizationScriptName = $postSynchronizationScriptName
                    #postSynchronizationScriptParameters = $postSynchronizationScriptParameters
                    #primingComputerAccount = $primingComputerAccount
                }
            }
        }
    };

    $desktopIdentifier = Add-DesktopPool $sessionInfoParam $desktopCreatePayload
    if ($desktopIdentifier) {
        Write-Host "Desktop pool `"$desktopPoolName`" created successfully!"
    }

}


###############################################################################
# @Author: Neha Agarwal
# Description: Helper to add virtual machines to existing manual desktop pool
##############################################################################
function Invoke-AddVMToManualDesktopPool() {
	param(
        [Parameter(Mandatory = $true)]
		$sessionInfo , 
        [Parameter(Mandatory = $true)]
		$virtualMachinesList,
        [Parameter(Mandatory = $true)]
		$vmNameList,
        [Parameter(Mandatory = $true)]
        $desktopIdentifier
	)
	$vmIdList = [System.Collections.ArrayList]@()
    foreach($vmdata in $virtualMachinesList) {
		foreach($vmName in $vmNameList) {
			
			if ( $vmName -eq $vmdata.name ) {
			    # Make sure that it is the correct vm to add 
				if( !$vmdata.incompatibleReasons.inUseByLocalDesktop -And !$vmdata.incompatibleReasons.unsupportedOS -And !$vmdata.incompatibleReasons.viewComposerReplica -And !$vmdata.incompatibleReasons.instantInternal ) {
					$null = $vmIdList.Add($vmdata.id)
				}
			}
		}
    }
    if ($vmIdList) {
       Add-MachinesToManualDesktop $sessionInfo $desktopIdentifier $vmIdList
    }
}

###
# Adds new LogCollectorAdmins custom role with "LOG_COLLECTION" permission.
###
function Add-LogCollectorCustomRole() {
    param(
        [Parameter(Mandatory = $true)]
		$sessionInfo,
        [Parameter(Mandatory = $false)]
        [string]
        $customRoleName
    )
    $roleName = $customRoleName
    if (-Not ($psBoundParameters.containsKey('customRoleName'))) {
        $roleName = "LogCollectorAdmins"
    }
    $privileges = @("LOG_COLLECTION")
    $description = "Allow log collection operations."
    Add-CustomRole $sessionInfo $roleName $description $privileges
}


Export-ModuleMember -Function Invoke-LoginCS, Invoke-LogoutCS

Export-ModuleMember -Function Get-ADDomainList, Get-ADContainerByRDN, Get-ADContainerByDomain, Add-DesktopPool, Get-DesktopPoolByName, Add-MachinesToManualDesktop

Export-ModuleMember -Function Get-VirtualCenterList, Get-VSANConfigStatus, Invoke-ValidateName, Get-VirtualMachineList

Export-ModuleMember -Function Get-BaseImageVMList, Get-BaseImageSnapshotList, Get-BaseImageSnapshotNICs, Get-VMFolderTree, Get-HostOrClusterTree, Get-ResourcePoolTree, Get-DataStoreList, Convert-TreeAsHashMap

Export-ModuleMember -Function Get-NetworkLabelListByClusterID, Get-RootAccessGroupID, Get-RootGlobalAccessGroupID, Get-AccessGroupList, Get-GlobalAccessGroupList, Get-AccessGroupInfo, Get-GlobalAccessGroupInfo, Get-AccessGroupList

Export-ModuleMember -Function Add-CustomRole, Find-ADUserByName, Clear-QueryById, Get-HorizonRoleList

## 
# Export helper methods
##

Export-ModuleMember -Function Send-LoginCS, Invoke-HorizonPostMethod, Invoke-HorizonGetMethod, Invoke-ResponseErrorHandler

Export-ModuleMember -Function Get-NetworkLabelByClusterID, Get-BaseSnapshotNICIdentifier, Get-DataStoreIdentifier, Get-ResourceIdentifier

Export-ModuleMember -Function Get-HostOrClusterIdentifier, Get-VMFolderIdentifier, Get-BaseSnapshotIdentifier, Get-BaseImageAndDataCenterIdentifier

Export-ModuleMember -Function Get-ValidateNameStatus, Get-VCenterInfo, Get-ADContainerIdentifier, Get-ADDomainInfo, Send-LoginCS

Export-ModuleMember -Function New-DesktopPool, Invoke-AddVMToManualDesktopPool

Export-ModuleMember -Function Add-LogCollectorCustomRole, Get-HorizonRoleByName, Add-HorizonAdminToRole