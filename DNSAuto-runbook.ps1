[OutputType("PSAzureOperationResponse")]
param
(
    [Parameter (Mandatory=$false)]
    [object] $WebhookData
)
#$ErrorActionPreference = "stop"

if ($WebhookData)
{
    Write-Verbose "$WebhookData.RequestBody" -Verbose   
     
    # Get the data object from WebhookData
    $WebhookBody = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

    Write-Verbose "RequestBody: $WebhookData.RequestBody" -Verbose

    # Get the info needed to identify the VM (depends on the payload schema)
    $schemaId = $WebhookBody.schemaId
    Write-Verbose "schemaId: $schemaId" -Verbose
    if ($schemaId -eq "Microsoft.Insights/activityLogs") {
        # This is the Activity Log Alert schema
        $AlertContext = [object] (($WebhookBody.data).context).activityLog
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = (($AlertContext.resourceId).Split("/"))[-1]
        $status = ($WebhookBody.data).status
    }    
    else {
        # Schema not supported
        Write-Error "The alert data schema - $schemaId - is not supported."
    }

    Write-Verbose "status: $status" -Verbose
    if (($status -eq "Activated") -or ($status -eq "Fired"))
    {
                # Determine code path depending on the resourceType - Private endpoints
        if ($ResourceType -eq "microsoft.network/privateendpoints")
        {
            Write-Verbose "resourceType: $ResourceType" -Verbose
            Write-Verbose "resourceName: $ResourceName" -Verbose
            Write-Verbose "resourceGroupName: $ResourceGroupName" -Verbose
            Write-Verbose "subscriptionId: $SubId" -Verbose

            # Ensures you do not inherit an AzContext in your runbook
	        Disable-AzContextAutosave -Scope Process

	        # Connect to Azure with system-assigned managed identity
	        $AzureContext = (Connect-AzAccount -Identity).context

            Write-Verbose "ContextID: $AzureContext.Account.ID" -Verbose
            
            Write-Verbose "subscriptionId: $SubId" -Verbose
	      
            #set and store context
	        $AzureContext = Set-AzContext -Subscription $SubId -DefaultProfile $AzureContext

            Write-Verbose "Az Context set properly" -Verbose

             #retrive the private endpoint for getting the required DNS record name and IP
            $privateendpointofalert = Get-AzPrivateEndpoint -Name $ResourceName -ResourceGroupName $ResourceGroupName

            Write-Verbose "Retrieved private endpoint : $privateendpointofalert.Name" -Verbose

            #retrive the private endpoint for getting the required DNS record name and IP
            $nic = Get-AzNetworkInterface -ResourceId $privateendpointofalert.NetworkInterfaces[0].Id

            $privateendpointIP = $nic.IpConfigurations[0].PrivateIpAddress

            Write-Verbose "IP: $privateendpointIP" -Verbose

            $privateendpointFQDN = $nic.IpConfigurations[0].PrivateLinkConnectionProperties[0].Fqdns

            $DNSRecordAname = $privateendpointFQDN -replace ".blob.core.windows.net" -replace ""

            Write-Verbose "A record: $DNSRecordAname" -Verbose

            Write-Verbose "Got all the information to add A record in the private DNS zone" -Verbose

            # Ensures you do not inherit an AzContext in your runbook
	        Disable-AzContextAutosave -Scope Process

            # Connect to Azure with service principal in the global tenant
            $ApplicationId = <<SPN Client ID>> # SPN ID
            $SecuredPassword = <<SPN Client secret>> # SPN 
            $SecureStringPwd =  $SecuredPassword | ConvertTo-SecureString -AsPlainText -Force

	        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecureStringPwd
            $TenantId = <<Tenant ID>> # Global tenant ID

             # Set new credentails and tenant details for login
            Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential

             #set and store context
	        $AzureContext = Set-AzContext -Subscription <<Global tenant Sub Name>> -Tenant $TenantId
            
            $dnsrecordnamestring = $DNSRecordAname | Out-String
            Write-Verbose "Original DNS recordname : $DNSRecordAname" -Verbose
            Write-Verbose "dnsrecordnamestring post conversion: $dnsrecordnamestring" -Verbose

            $ipstring = $privateendpointIP | Out-String
            Write-Verbose "privateendpointIP: $ipstring" -Verbose

            #$Records = @()
            #$Records += New-AzPrivateDnsRecordConfig -IPv4Address  $ipstring
            #Write-Verbose "Context Name: $AzureContext.Name" -Verbose

            $recordset = New-AzPrivateDnsRecordSet -Name $dnsrecordnamestring -RecordType A -ZoneName "privatelink.blob.core.windows.net" -ResourceGroupName <<Resource group name>> -Ttl 60 -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -IPv4Address $ipstring )
            #$recordset = New-AzPrivateDnsRecordSet -Name "samplename" -RecordType A -ZoneName "privatelink.blob.core.windows.net" -ResourceGroupName "rsg-ccoe-prod-hub-privatednszones" -Ttl 60 -PrivateDnsRecords (New-AzPrivateDnsRecordConfig -IPv4Address "192.168.0.15" )

            Write-Verbose "A record created successfully in the private DNS zone in another tenant" -Verbose
        }
        else {
            # ResourceType not supported
            Write-Error "$ResourceType is not a supported resource type for this runbook."
        }
    }
    else {
        # The alert status was not 'Activated' or 'Fired' so no action taken
        Write-Verbose ("No action taken. Alert status: " + $status) -Verbose
    }
}
else {
    # Error
    Write-Error "This runbook is meant to be started from an Azure alert webhook only."
}
