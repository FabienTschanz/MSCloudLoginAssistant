function Connect-MSCloudLoginAutopatch
{
    [CmdletBinding()]
    param()

    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $source = 'Connect-MSCloudLoginAutopatch'

    if ($Script:MSCloudLoginConnectionProfile.Autopatch.Connected)
    {
        if (($Script:MSCloudLoginConnectionProfile.Autopatch.AuthenticationType -eq 'ServicePrincipalWithSecret' `
                    -or $Script:MSCloudLoginConnectionProfile.Autopatch.AuthenticationType -eq 'Identity') `
                -and (Get-Date -Date $Script:MSCloudLoginConnectionProfile.Autopatch.ConnectedDateTime) -lt [System.DateTime]::Now.AddMinutes(-50))
        {
            Add-MSCloudLoginAssistantEvent -Message 'Token is about to expire, renewing' -Source $source
            $Script:MSCloudLoginConnectionProfile.Autopatch.Connected = $false
        }
    }

    try
    {
        if ($Script:MSCloudLoginConnectionProfile.Autopatch.AuthenticationType -eq 'CredentialsWithApplicationId' -or
            $Script:MSCloudLoginConnectionProfile.Autopatch.AuthenticationType -eq 'Credentials' -or
            $Script:MSCloudLoginConnectionProfile.Autopatch.AuthenticationType -eq 'CredentialsWithTenantId')
        {
            Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with user credentials' -Source $source
            Connect-MSCloudLoginAutopatchWithUser
        }
        elseif ($Script:MSCloudLoginConnectionProfile.Autopatch.AuthenticationType -eq 'AccessTokens')
        {
            Add-MSCloudLoginAssistantEvent -Message 'Using provided access token to connect to Windows Autopatch' -Source $source
            $accessToken = if ($Script:MSCloudLoginConnectionProfile.Autopatch.AccessTokens[0] -like 'Bearer *')
            {
                $Script:MSCloudLoginConnectionProfile.Autopatch.AccessTokens[0]
            }
            else
            {
                'Bearer ' + $Script:MSCloudLoginConnectionProfile.Autopatch.AccessTokens[0]
            }
            $Script:MSCloudLoginConnectionProfile.Autopatch.AccessToken = $accessToken
        }
        else
        {
            throw 'Specified authentication method is not supported.'
        }

        $Script:MSCloudLoginConnectionProfile.Autopatch.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Script:MSCloudLoginConnectionProfile.Autopatch.Connected = $true
        $Script:MSCloudLoginConnectionProfile.Autopatch.MultiFactorAuthentication = $false
        Add-MSCloudLoginAssistantEvent -Message "Successfully connected to Windows Autopatch API using AAD App {$ApplicationID}" -Source $source
    }
    catch
    {
        throw $_
    }
}

function Connect-MSCloudLoginAutopatchWithUser
{
    [CmdletBinding()]
    param()

    $source = 'Connect-MSCloudLoginAutopatchWithUser'

    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.Autopatch.TenantId))
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.Autopatch.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.Autopatch.TenantId
    }

    try
    {
        $managementToken = Get-AuthToken -AuthorizationUrl $Script:MSCloudLoginConnectionProfile.Autopatch.AuthorizationUrl `
            -Credentials $Script:MSCloudLoginConnectionProfile.Autopatch.Credentials `
            -TenantId $tenantId `
            -ClientId $Script:MSCloudLoginConnectionProfile.Autopatch.ApplicationId `
            -Scope $Script:MSCloudLoginConnectionProfile.Autopatch.Scope

        $Script:MSCloudLoginConnectionProfile.Autopatch.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
        $Script:MSCloudLoginConnectionProfile.Autopatch.Connected = $true
        $Script:MSCloudLoginConnectionProfile.Autopatch.ConnectedDateTime = [System.DateTime]::Now.ToString()
    }
    catch
    {
        if ($_.ErrorDetails.Message -like '*AADSTS50076*')
        {
            Add-MSCloudLoginAssistantEvent -Message 'Account used required MFA' -Source $source
            Connect-MSCloudLoginAutopatchWithUserMFA
        }
    }
}
function Connect-MSCloudLoginAutopatchWithUserMFA
{
    [CmdletBinding()]
    param()

    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.Autopatch.TenantId))
    {
        $tenantid = $Script:MSCloudLoginConnectionProfile.Autopatch.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.Autopatch.TenantId
    }

    $managementToken = Get-AuthToken -AuthorizationUrl $Script:MSCloudLoginConnectionProfile.Autopatch.AuthorizationUrl `
        -Credentials $Script:MSCloudLoginConnectionProfile.Autopatch.Credentials `
        -TenantId $tenantId `
        -ClientId $Script:MSCloudLoginConnectionProfile.Autopatch.ApplicationId `
        -Scope $Script:MSCloudLoginConnectionProfile.Autopatch.Scope `
        -DeviceCode

    $Script:MSCloudLoginConnectionProfile.Autopatch.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
    $Script:MSCloudLoginConnectionProfile.Autopatch.Connected = $true
    $Script:MSCloudLoginConnectionProfile.Autopatch.MultiFactorAuthentication = $true
    $Script:MSCloudLoginConnectionProfile.Autopatch.ConnectedDateTime = [System.DateTime]::Now.ToString()
}
