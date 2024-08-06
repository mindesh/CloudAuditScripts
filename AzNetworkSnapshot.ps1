# PowerShell script that will iterate through all subscriptions, capture the configuration of all VNETs and NSGs, UDRs and their contents and associations and export the results to CSV files.
# The script may take some time to run if you have a large number of subscriptions and resources, so be patient.
# In order to yeld accurate results, be sure to have Global Reader permissions.

# Login to Azure with your credentials
Connect-AzAccount

### VNET config list

# Get all subscriptions within the tenant
$Subscriptions = Get-AzSubscription

# Initialize empty array to hold VNET configurations
$VNETConfig = @()

# Iterate through all subscriptions within the tenant
foreach ($Subscription in $Subscriptions) {
    Set-AzContext -Subscription $Subscription.Id
    $VNETs = Get-AzVirtualNetwork

    foreach ($VNET in $VNETs) {
        $VNETConfig += [PSCustomObject]@{
            SubscriptionName = $Subscription.Name
            SubscriptionID   = $Subscription.Id
            VNETName         = $VNET.Name
            VNETAddressSpace = $VNET.AddressSpace.AddressPrefixes -join '; '
            ResourceGroup    = $VNET.ResourceGroupName
            Location         = $VNET.Location
            Subnets          = $VNET.Subnets.Name -join '; '
        }
    }
}

$VNETConfig | Export-Csv -Path "VNETconfig.csv" -NoTypeInformation

### UDR config list

# Initialize an empty array to hold the UDR configuration
$udrConfig = @()

# Get a list of all subscriptions within the tenant
$subList = Get-AzSubscription -TenantId $tenantId

# Iterate through each subscription and capture UDR configuration
foreach ($sub in $subList) {
    # Select the current subscription
    Set-AzContext -Subscription $sub.Id

    # Get a list of all VNETs within the current subscription
    $vnetList = Get-AzVirtualNetwork

    # Iterate through each VNET and capture UDR configuration
    foreach ($vnet in $vnetList) {
        # Get a list of all UDRs associated with the current VNET
        $udrList = Get-AzRouteTable -VirtualNetwork $vnet

        # Iterate through each UDR and capture its configuration
        foreach ($udr in $udrList) {
            $udrConfig += [PSCustomObject]@{
                SubscriptionId = $sub.Id
                SubscriptionName = $sub.Name
                ResourceGroupName = $udr.ResourceGroupName
                RouteTableName = $udr.Name
                VirtualNetworkName = $vnet.Name
            }
        }
    }
}

# Export the UDR configuration to a CSV file
$udrConfig | Export-Csv -Path "UDRconfig.csv" -NoTypeInformation

### Public IP list

 Get all subscriptions within the tenant
$subscriptions = Get-AzSubscription | Select-Object SubscriptionId

# Create an empty array to store public IPs
$publicIps = @()

# Iterate through each subscription
foreach ($sub in $subscriptions) {

    # Set the current subscription context
    Set-AzContext -SubscriptionId $sub.SubscriptionId
    
    # Get all resources with public IP addresses
    $resources = Get-AzResource -ExpandProperties | Where-Object {$_.Properties.PublicIPAddress -ne $null}
    
    # Iterate through each resource and extract its public IP address
    foreach ($resource in $resources) {
        $publicIp = $resource.Properties.PublicIPAddress.Id.Split("/")[-1]
        $publicIps += [PSCustomObject]@{
            ResourceName = $resource.Name
            ResourceType = $resource.ResourceType
            PublicIPAddress = $publicIp
        }
    }
}

# Export the results to a CSV file
$publicIps | Export-Csv -Path "public_ips.csv" -NoTypeInformation
