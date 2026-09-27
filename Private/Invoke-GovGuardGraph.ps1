function Invoke-GovGuardGraph {
    <#
    .SYNOPSIS
        Thin wrapper over Invoke-MgGraphRequest with paging and error shaping.

    .DESCRIPTION
        Every rule calls Graph through this and nothing else. Two reasons:

        1. Invoke-MgGraphRequest resolves relative URIs against the base endpoint
           of the connected environment, so the same rule code runs unchanged
           against graph.microsoft.com, graph.microsoft.us and dod-graph.microsoft.us.
           No per-cloud URL branching inside rules.
        2. One dependency (Microsoft.Graph.Authentication) instead of a dozen
           Microsoft.Graph.* submodules whose cmdlet names drift between versions.

    .PARAMETER Uri
        Relative Graph URI, e.g. 'v1.0/policies/authenticationMethodsPolicy'.

    .PARAMETER All
        Follow @odata.nextLink and return every page.

    .PARAMETER Raw
        Return the response object untouched instead of unwrapping .value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method = 'GET',

        [object]$Body,

        [switch]$All,

        [switch]$Raw
    )

    if (-not (Get-MgContext)) {
        throw 'Not connected to Microsoft Graph. Run Connect-GovGuard first.'
    }

    $requestParams = @{
        Uri         = $Uri
        Method      = $Method
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $requestParams['Body'] = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
        $requestParams['ContentType'] = 'application/json'
    }

    $response = Invoke-MgGraphRequest @requestParams

    if ($Raw -or $null -eq $response) { return $response }

    $propertyNames = @($response.PSObject.Properties.Name)
    if ($propertyNames -notcontains 'value') { return $response }

    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($response.value)) { $items.Add($item) }

    if ($All) {
        $nextLink = $null
        if ($propertyNames -contains '@odata.nextLink') { $nextLink = $response.'@odata.nextLink' }

        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Uri $nextLink -Method GET -OutputType PSObject -ErrorAction Stop
            foreach ($item in @($page.value)) { $items.Add($item) }

            $nextLink = $null
            if (@($page.PSObject.Properties.Name) -contains '@odata.nextLink') { $nextLink = $page.'@odata.nextLink' }
        }
    }

    return $items.ToArray()
}

function Test-GovGuardProperty {
    <#
    .SYNOPSIS
        Strict-mode-safe property probe for Graph payloads.

    .DESCRIPTION
        Graph omits null properties rather than returning them, and the module
        runs under Set-StrictMode. Rules use this instead of $obj.foo.bar.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    return (@($InputObject.PSObject.Properties.Name) -contains $Name)
}

function Get-GovGuardProperty {
    <#
    .SYNOPSIS
        Returns a nested property value or $null, without throwing under StrictMode.

    .EXAMPLE
        Get-GovGuardProperty -InputObject $policy -Path 'conditions','locations','includeLocations'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Path
    )

    $current = $InputObject
    foreach ($segment in $Path) {
        if (-not (Test-GovGuardProperty -InputObject $current -Name $segment)) { return $null }
        $current = $current.$segment
    }
    return $current
}
