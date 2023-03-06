# Login to Azure
Connect-AzAccount

# Get all Azure subscriptions
$subscriptions = Get-AzSubscription

# Initialize an array to hold the results
$results = @()

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext $subscription.Context

    # Get all storage accounts in the current subscription
    $storageAccounts = Get-AzStorageAccount

    # Iterate through each storage account
    foreach ($storageAccount in $storageAccounts) {
        # Check if the storage account is public
        $isPublic = $storageAccount | Get-AzStorageAccount | Select-Object -ExpandProperty Properties | Select-Object -ExpandProperty SupportsHttpsTrafficOnly
        if ($isPublic -eq $false) {
            # Add the storage account to the results array
            $results += @{
                SubscriptionName = $subscription.Name
                StorageAccountName = $storageAccount.Name
                IsPublic = $isPublic
            }
        }
    }
}

# Export the results to a CSV file
$results | Export-Csv -Path AzPublicStorage.csv -NoTypeInformation
