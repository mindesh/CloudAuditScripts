# List all Public IPs and export to a CSV file.

#!/bin/bash

# Get a list of all regions available in your account
regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

# Loop through each region and get a list of public IP addresses
for region in $regions; do
    echo "Checking region $region..."
    ips=$(aws ec2 describe-addresses --query 'Addresses[].PublicIp' --output text --region $region)
    if [ -z "$ips" ]; then
        echo "No public IPs found in region $region."
    else
        echo "Public IPs found in region $region:"
        echo "$ips"
        echo "$ips" >> AWS_PublicIP_list.csv
    fi
done
