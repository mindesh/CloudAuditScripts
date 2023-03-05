# PowerShell script that will iterate through all subscriptions, capture the configuration of all VNETs and NSGs, and export the results to a CSV file.
# Make sure to update the $outputFilePath variable to specify the path and filename for the CSV file that the results will be exported to. 
# The script will prompt you to log in to Azure if you're not already logged in. 
# The script may take some time to run if you have a large number of subscriptions and resources, so be patient.
# In order to yeld accurate results, be sure to have Global Reader permissions.

# Connect to Azure
Connect-AzAccount

# Set output file path
$outputFilePath = "C:\temp\azure-network-config.csv"

# Initialize an array to hold the results
$results = @()

# Loop through all subscriptions
foreach ($subscription in Get-AzSubscription) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Get all VNETs
    $vnets = Get-AzVirtualNetwork

    # Loop through each VNET
    foreach ($vnet in $vnets) {
        # Get the NSGs associated with the VNET
        $nsgs = Get-AzNetworkSecurityGroup -ResourceGroupName $vnet.ResourceGroupName | Where-Object { $_.Subnets.ID -contains $vnet.Subnets[0].Id }

        # Loop through each NSG
        foreach ($nsg in $nsgs) {
            # Get the VMs associated with the NSG
            $vms = Get-AzVM | Where-Object { $_.NetworkProfile.NetworkInterfaces.NetworkSecurityGroup.ID -eq $nsg.Id }

            # Create a custom object to hold the results
            $result = New-Object -TypeName PSObject
            $result | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value $subscription.Name
            $result | Add-Member -MemberType NoteProperty -Name ResourceGroupName -Value $vnet.ResourceGroupName
            $result | Add-Member -MemberType NoteProperty -Name VNetName -Value $vnet.Name
            $result | Add-Member -MemberType NoteProperty -Name NSGName -Value $nsg.Name
            $result | Add-Member -MemberType NoteProperty -Name NSGResourceGroupName -Value $nsg.ResourceGroupName
            $result | Add-Member -MemberType NoteProperty -Name AssociatedVMs -Value ($vms.Name -join ',')
            
            # Add the custom object to the results array
            $results += $result
        }
    }
}

# Export the results to a CSV file
$results | Export-Csv -Path $outputFilePath -NoTypeInformation
