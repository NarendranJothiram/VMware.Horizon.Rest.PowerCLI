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
    $response = Invoke-WebRequest -UseBasicParsing -Uri $uri `
    -Method "POST" `
    -WebSession $session `
    -Headers $headers `
    -ContentType "application/json; charset=UTF-8" `
    -Body $bodyContent;
    $csrfToken = $response.Headers['CSRFToken']
    $headers.Add('CSRFToken', $csrfToken)

    return @{"urlPrefix"= "https://$csName/$urlPrefix"; "session"= $session;
    "headers"= $headers}
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
        $payloadJSON = $payload | ConvertTo-Json -Depth 10
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
    return $accessGroupInfo;
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
    return $rootAccessID;
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



###############
# START HELPERS
###############


function Send-LoginCS () {
    param(
        $username,
        $domain,
        $servername
    )
    $pwd_secure_string = Read-Host "Enter a Password" -AsSecureString
    $plainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd_secure_string))
    $loginParams = @{
        name = $username
        passwd = $plainTextPassword
        domain = $domain
    }
    $server=$servername

    # Session Info required for other API requests on same logged in session.
    # The third parameter to be set as $false for production environments
    $sessionInfo = Invoke-LoginCS $server $loginParams $true

    # Reset login payload.
    $loginParams = "";
    # Reset plain password immediately after login.
    $plainTextPassword="";

    return $sessionInfo;
}

function Get-ADDomainInfo() {
    param(
       $sessionInfo,
       $icdomainDNS,
       $icDomainAdminName
    )
    $adDomains = Get-ADDomainList $sessionInfo

    # Select domain identifier from dnsName and IC domain admin user name
    $icDomain=""
    foreach($data in $adDomains) {
       if ($icDomainDNS -eq $data.namesData.dnsName -And $data.base.userName -eq $icDomainAdminName) {
         $icDomain=$data
       }
    }
    return $icDomain
}


function Get-ADContainerIdentifier() {
    
    param(
       $sessionInfo,
       $icDomainID,
       $adContainerVDI
    )
    # Payload to find AD Container by RDN
    $adContainerByIdPayload = @{
        domain = "$icDomainID"
        containerRDN = "$adContainerVDI"
    }

    $adContainerInfo = Get-ADContainerByRDN $sessionInfo $adContainerByIdPayload
    $adContainerIdentifier = ""
    # Now, lets find the ADContainerIdentifier
    foreach($data in $adContainerInfo) {
        if ($adContainerVDI -eq $data.rdn) {
            $adContainerIdentifier=$data.id
        }
    }
    return $adContainerIdentifier
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

Export-ModuleMember -Function Invoke-LoginCS, Invoke-LogoutCS

Export-ModuleMember -Function Get-ADDomainList, Get-ADContainerByRDN, Add-DesktopPool

Export-ModuleMember -Function Get-VirtualCenterList, Get-VSANConfigStatus, Invoke-ValidateName

Export-ModuleMember -Function Get-BaseImageVMList, Get-BaseImageSnapshotList, Get-BaseImageSnapshotNICs, Get-VMFolderTree, Get-HostOrClusterTree, Get-ResourcePoolTree, Get-DataStoreList, Convert-TreeAsHashMap

Export-ModuleMember -Function Get-NetworkLabelListByClusterID, Get-RootAccessGroupID, Get-AccessGroupList, Get-AccessGroupInfo, Get-AccessGroupList

## 
# Export helper methods
##

Export-ModuleMember -Function Send-LoginCS, Invoke-HorizonPostMethod, Invoke-HorizonGetMethod, Invoke-ResponseErrorHandler

Export-ModuleMember -Function Get-NetworkLabelByClusterID, Get-BaseSnapshotNICIdentifier, Get-DataStoreIdentifier, Get-ResourceIdentifier

Export-ModuleMember -Function Get-HostOrClusterIdentifier, Get-VMFolderIdentifier, Get-BaseSnapshotIdentifier, Get-BaseImageAndDataCenterIdentifier

Export-ModuleMember -Function Get-ValidateNameStatus, Get-VCenterInfo, Get-ADContainerIdentifier, Get-ADDomainInfo, Send-LoginCS