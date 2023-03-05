# PowerShell script that will iterate through all subscriptions within a tenant, list all public IPs that are assigned to a resource, and then export the results to a CSV file
# This script will prompt you to log in to Azure using your Azure AD credentials and then retrieve all subscriptions within the tenant. 
# It will then iterate through each subscription, retrieve all resources that have a public IP address assigned to them, and then extract the public IP address from each resource. 
# Finally, it will store the results in an array of PSCustomObject objects and export it to a CSV file named "public_ips.csv"

# Login to Azure using the Azure AD credentials
Connect-AzAccount

# Get all subscriptions within the tenant
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
