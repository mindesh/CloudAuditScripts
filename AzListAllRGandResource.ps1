# Login to Azure
Connect-AzAccount

# Set output file name and location
$outputFile = "AzureResourceGroupsAndResources.csv"

# Create an empty array to store results
$results = @()

# Loop through all Azure subscriptions
foreach ($subscription in Get-AzSubscription) {
    Set-AzContext $subscription.Id

    # Get all resource groups in the current subscription
    $resourceGroups = Get-AzResourceGroup

    # Loop through each resource group
    foreach ($resourceGroup in $resourceGroups) {
        # Get all resources in the current resource group
        $resources = Get-AzResource -ResourceGroupName $resourceGroup.ResourceGroupName

        # Loop through each resource
        foreach ($resource in $resources) {
            # Create a custom object to store the resource information
            $resourceInfo = [PSCustomObject]@{
                Subscription = $subscription.Name
                ResourceGroup = $resourceGroup.ResourceGroupName
                ResourceType = $resource.ResourceType
                ResourceName = $resource.Name
            }

            # Add the resource information to the results array
            $results += $resourceInfo
        }
    }
}

# Export the results to a CSV file
$results | Export-Csv -Path $outputFile -NoTypeInformation

# Display a confirmation message
Write-Host "Results exported to $outputFile"
