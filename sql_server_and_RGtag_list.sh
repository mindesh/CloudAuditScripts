# This script lists all Azure Subscriptions, then iterates over them to retrieve all SQL servers and obtain tags from each parent Resource Group.
# Can be useful when server oweners need to be identified and the information is available within tags of the Resource Group.
# Script can be executed in Azure CloudShell

#!/bin/bash

# Get all subscriptions
subscriptions=$(az account list --query "[].{id:id, name:name}" -o tsv)

# Iterate over each subscription
while IFS=$'\t' read -r subId subName; do
    echo "Checking subscription: $subName ($subId)"
    
    # Set the current subscription
    az account set --subscription "$subId"

    # Get all SQL servers in the subscription
    sqlServers=$(az sql server list --query "[].{name:name, resourceGroup:resourceGroup}" -o tsv)
    
    # Check if there are SQL servers in the subscription
    if [ -z "$sqlServers" ]; then
        echo "No SQL servers found in subscription: $subName ($subId)"
        continue
    fi

    # Iterate over each SQL server
    while IFS=$'\t' read -r serverName resourceGroup; do
        # Get all the tags for the resource group
        tags=$(az group show --name "$resourceGroup" --query "tags" -o json)
        
        # Output the details
        echo -e "Subscription ID: $subId\nSubscription Name: $subName\nSQL Server: $serverName\nResource Group: $resourceGroup\nTags: $tags\n"
    done <<< "$sqlServers"
done <<< "$subscriptions"
