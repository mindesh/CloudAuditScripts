# Authenticate with Azure
Connect-AzAccount

# Get all Azure subscriptions
$subscriptions = Get-AzSubscription

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    # Select the current subscription
    Set-AzContext -SubscriptionId $subscription.Id

    # Get all VMs with public IP addresses and no NSG
    $vms = Get-AzVM | Where-Object { $_.PublicIps -ne $null -and $_.NetworkSecurityGroup -eq $null }

    # Export the results to a CSV file
    $outputPath = "C:\VMs-without-NSG.csv"
    $vms | Export-Csv $outputPath -NoTypeInformation -Append
}
