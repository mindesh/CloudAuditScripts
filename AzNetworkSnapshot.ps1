# PowerShell script that will iterate through all subscriptions, capture the configuration of all VNETs and NSGs, UDRs and their contents and associations and export the results to CSV files.
# The script may take some time to run if you have a large number of subscriptions and resources, so be patient.
# In order to yeld accurate results, be sure to have Global Reader permissions.

# Login to Azure with your credentials
Connect-AzAccount

$Subscriptions = Get-AzSubscription

$VNETConfig = @()

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

###

# Initialize empty array to hold NSG configurations
$nsgConfigs = @()

# Iterate through all subscriptions within the tenant
$subIds = Get-AzSubscription | Select-Object -ExpandProperty SubscriptionId
foreach ($subId in $subIds) {
    Set-AzContext -SubscriptionId $subId

    # Get all VNETs and VMs in the subscription
    $vnetVMs = Get-AzResource -ResourceType "Microsoft.Network/virtualNetworks" `
        -ExpandProperties | Where-Object {$_.properties.subnets -ne $null} `
        | Select-Object -ExpandProperty properties.subnets | Select-Object -ExpandProperty properties

    # Iterate through all NSGs in the subscription
    $nsgs = Get-AzNetworkSecurityGroup
    foreach ($nsg in $nsgs) {
        # Get NSG configuration
        $nsgConfig = [ordered]@{
            SubscriptionId = $subId
            ResourceGroupName = $nsg.ResourceGroupName
            NSGName = $nsg.Name
            NSGId = $nsg.Id
            Location = $nsg.Location
        }

        # Get the VNET or VM the NSG is assigned to, if any
        $associatedVnet = $nsg | Get-AzNetworkSecurityGroupAssociation | Where-Object {$_.AssociationType -eq "AssociatedToSubnet"} | Select-Object -ExpandProperty VirtualNetwork
        $associatedVM = $nsg | Get-AzNetworkInterface | Get-AzVM | Select-Object -ExpandProperty Name

        # Add VNET or VM information to NSG configuration
        if ($associatedVnet) {
            $nsgConfig.VNetName = $associatedVnet.Name
            $nsgConfig.VNetId = $associatedVnet.Id
        }
        if ($associatedVM) {
            $nsgConfig.VMName = $associatedVM
        }

        # Add NSG configuration to array
        $nsgConfigs += New-Object PSObject -Property $nsgConfig
    }
}

# Export NSG configurations to CSV file
$nsgConfigs | Export-Csv -Path "NSGconfig.csv" -NoTypeInformation

###

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
