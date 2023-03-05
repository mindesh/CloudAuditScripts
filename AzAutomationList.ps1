# List all automation accounts accross all subscriptions in Azure and then attempt to export all runbooks.

# Login to Azure
Connect-AzAccount

# Get a list of all subscriptions
$subscriptions = Get-AzSubscription

# Loop through each subscription
foreach ($subscription in $subscriptions) {

    # Select the current subscription
    Set-AzContext -Subscription $subscription.Id

    # Get a list of all Automation Accounts in the current subscription
    $automationAccounts = Get-AzAutomationAccount

    # Loop through each Automation Account
    foreach ($automationAccount in $automationAccounts) {

        # Print the Automation Account name and resource group name
        Write-Output "Automation Account: $($automationAccount.Name), Resource Group: $($automationAccount.ResourceGroupName)"

        # Set the context to the Automation Account
        $context = $automationAccount.Context

        # Get a list of all Runbooks in the Automation Account
        $runbooks = Get-AzAutomationRunbook -AutomationAccountName $context.AutomationAccountName -ResourceGroupName $context.ResourceGroupName

        # Export each Runbook to a file
        foreach ($runbook in $runbooks) {
            $runbookContent = Get-AzAutomationRunbookContent -AutomationAccountName $context.AutomationAccountName -ResourceGroupName $context.ResourceGroupName -Name $runbook.Name
            $fileName = "$($automationAccount.Name)-$($runbook.Name).ps1"
            $filePath = Join-Path -Path $PSScriptRoot -ChildPath $fileName
            Set-Content -Path $filePath -Value $runbookContent.Content
            Write-Output "Exported Runbook '$($runbook.Name)' to '$($filePath)'"
        }
    }
}
