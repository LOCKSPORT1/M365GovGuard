function Test-GovGuardServicePlan {
    <#
    .SYNOPSIS
        Is a given service plan present and provisioned in this tenant?

    .DESCRIPTION
        Licensing decides whether a control is even available. A rule that
        recommends Privileged Identity Management to a tenant with no Entra ID
        P2 is telling the client to use something they cannot use, which is
        worse than saying nothing.

        Checks every subscribed SKU for the named service plan in a successful
        provisioning state.

    .PARAMETER ServicePlanName
        The service plan to look for. Common ones:
          AAD_PREMIUM      Entra ID P1  - Conditional Access, sign-in activity
          AAD_PREMIUM_P2   Entra ID P2  - PIM, access reviews, Identity Protection

    .EXAMPLE
        if (-not (Test-GovGuardServicePlan -ServicePlanName 'AAD_PREMIUM_P2')) { ... }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ServicePlanName
    )

    try {
        $skus = @(Invoke-GovGuardGraph -Uri 'v1.0/subscribedSkus')
    }
    catch {
        Write-Verbose -Message ("Could not read subscribed SKUs: {0}" -f $_.Exception.Message)
        return $false
    }

    foreach ($sku in $skus) {
        $plans = @(Get-GovGuardProperty -InputObject $sku -Path 'servicePlans')
        foreach ($plan in $plans) {
            $name = [string](Get-GovGuardProperty -InputObject $plan -Path 'servicePlanName')
            if ($name -ne $ServicePlanName) { continue }

            $status = [string](Get-GovGuardProperty -InputObject $plan -Path 'provisioningStatus')
            if ($status -in @('Success', 'PendingInput', 'PendingActivation')) { return $true }
        }
    }

    return $false
}
