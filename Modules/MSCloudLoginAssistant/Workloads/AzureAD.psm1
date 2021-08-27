function Connect-MSCloudLoginAzureAD
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )
    # Explicitly import the required module(s) in case there is cmdlet ambiguity with other modules e.g. SharePointPnPPowerShell2013
    Import-Module -Name AzureADPreview -DisableNameChecking -Force

    if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
        -not [String]::IsNullOrEmpty($TenantId) -and `
        -not [String]::IsNullOrEmpty($CertificateThumbprint))
    {
        Write-Verbose -Message "Connecting to AzureAD using Application {$ApplicationId}"
        try
        {
            Connect-AzureAD -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint | Out-Null
        }
        catch
        {
            throw $_
        }
    }
    else
    {
        try
        {
            Connect-AzureAD -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
            $Global:IsMFAAuth = $false
            $Global:MSCloudLoginAzureADConnected = $true
        }
        catch
        {
            if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
            {
                try
                {
                    Connect-AzureAD -Credential $Global:o365Credential -AzureEnvironmentName AzureUSGovernment -ErrorAction Stop | Out-Null
                    $Global:IsMFAAuth = $false
                    $Global:MSCloudLoginAzureADConnected = $true
                    $Global:CloudEnvironment = 'GCCHigh'
                }
                catch
                {
                    if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
                    {
                        try
                        {
                            Connect-AzureAD -Credential $Global:o365Credential -AzureEnvironmentName AzureGermanyCloud -ErrorAction Stop | Out-Null
                            $Global:IsMFAAuth = $false
                            $Global:MSCloudLoginAzureADConnected = $true
                            $Global:CloudEnvironment = 'Germany'
                        }
                        catch
                        {                            
                            if ($_.Exception -like '*AADSTS50076*')
                            {
                                Connect-MSCloudLoginAzureADMFA
                            }
                            elseif ($_.Exception -like '*unknown_user_type*')
                            {
                                $Global:CloudEnvironment = 'GCCHigh'
                                Connect-MSCloudLoginAzureADMFA
                            }
                            else
                            {
                                $Global:MSCloudLoginAzureADConnected = $false
                                throw $_
                            }
                        }
                    }                                      
                    elseif ($_.Exception -like '*AADSTS50079*' -or $_.Exception -like '*AADSTS50076*' -or $_.Exception -like '*unknown_user_type*')
                    {
                        $Global:CloudEnvironment = 'GCCHigh'
                        Connect-MSCloudLoginAzureADMFA
                    }
                    else
                    {
                        throw $_
                    }
                }
            }
            elseif ($_.Exception -like '*AADSTS50076*')
            {
                Connect-MSCloudLoginAzureADMFA
            }
            else
            {
                $Global:MSCloudLoginAzureADConnected = $false
                throw $_
            }
        }
    }
    return
}

function Connect-MSCloudLoginAzureADMFA
{
    [CmdletBinding()]
    param()

    # We are using an MFA enabled account. Need to call Azure AD
    try
    {
        if ($null -ne $Global:o365Credential)
        {
            if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
            {
                $EnvironmentName = 'AzureGermanyCloud'
                $Global:CloudEnvironment = 'Germany'
            }
            elseif ($null -eq $Global:CloudEnvironment)
            {
                $EnvironmentName = 'AzureCloud'
            }
            Connect-AzureAD -AccountId $Global:o365Credential.UserName -AzureEnvironmentName $EnvironmentName -ErrorAction Stop | Out-Null
            $Global:IsMFAAuth = $true
            $Global:MSCloudLoginAzureADConnected = $true
        }
        else
        {
            Connect-AzureAD -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginAzureADConnected = $true
        }
    }
    catch
    {
        try
        {
            Connect-AzureAD -AccountId $Global:o365Credential.UserName -AzureEnvironmentName AzureUSGovernment -ErrorAction Stop | Out-Null
            $Global:IsMFAAuth = $true
            $Global:MSCloudLoginAzureADConnected = $true

            if ($Global:CloudEnvironment -ne 'GCCHigh')
            {
                $Global:CloudEnvironment = 'USGovernment'
            }
        }
        catch
        {
            $Global:MSCloudLoginAzureADConnected = $false
            throw $_
        }
    }
    return
}
