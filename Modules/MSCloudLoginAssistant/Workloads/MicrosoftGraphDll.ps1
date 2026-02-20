$Script:IsTypeLoaded = $false

function Connect-MSCloudLoginMicrosoftGraphDll
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $source = 'Connect-MSCloudLoginMicrosoftGraphDll'

    # If the current profile is not the same we expect, make the switch.
    if ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected)
    {
        if (($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'ServicePrincipalWithSecret' `
                    -or $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'Identity') `
                -and (Get-Date -Date $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime) -lt [System.DateTime]::Now.AddMinutes(-50))
        {
            Add-MSCloudLoginAssistantEvent -Message 'Token is about to expire, renewing' -Source $source
            $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $false
        }
        else
        {
            return
        }
    }

    if ($Global:CustomEnvironment)
    {
        $customEnv = Get-MgEnvironment | Where-Object { $_.Name -eq 'Custom' }
        if ($null -eq $customEnv)
        {
            Add-MgEnvironment -Name 'Custom' -GraphEndpoint $Global:CustomGraphResourceUrl -AzureADEndPoint $Global:CustomGraphTokenUrl
        }
    }

    if ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'CredentialsWithTenantId' -or `
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'Credentials')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Use device login for user credential sign-in' -Source $source
        Connect-MSCloudLoginMSGraphWithUserMFA
    }
    elseif ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'Identity')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Connecting with managed identity' -Source $source

        $options = [Azure.Identity.ManagedIdentityCredentialOptions]::new()
        $options.AuthorityHost = [System.Uri]::new($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthorizationUrl)

        $managedIdentityCredential = [Azure.Identity.ManagedIdentityCredential]::new($options)
        $authProvider = [Microsoft.Graph.Authentication.AzureIdentityAuthenticationProvider]::new($managedIdentityCredential, $null, $null,$true, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Scope)

        $graphServiceClient = [Microsoft.Graph.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/v1.0")
        $graphServiceClientBeta = [Microsoft.Graph.Beta.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/beta")

        $null = $graphServiceClient.Me.GetAsync().Result
        $null = $graphServiceClientBeta.Me.GetAsync().Result

        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $graphServiceClient
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $graphServiceClientBeta

        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.MultiFactorAuthentication = $false
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $true
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.TenantId = $graphServiceClient.Organization.GetAsync().GetAwaiter().GetResult().Value.Id
    }
    else
    {
        try
        {
            if ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
            {
                try
                {
                    $options = [Azure.Identity.ClientCertificateCredentialOptions]::new()
                    $options.AuthorityHost = [System.Uri]::new($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthorizationUrl)

                    $x509StoreUser = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
                    $x509StoreUser.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                    $certificate = $x509StoreUser.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.CertificateThumbprint, $false)

                    if ($certificate.Count -eq 0)
                    {
                        $x509StoreMachine = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                        $x509StoreMachine.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                        $certificate = $x509StoreMachine.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.CertificateThumbprint, $false)

                        if ($certificate.Count -eq 0)
                        {
                            throw "Certificate with thumbprint $($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.CertificateThumbprint) not found in CurrentUser or LocalMachine store"
                        }
                    }

                    $clientCertCredential = [Azure.Identity.ClientCertificateCredential]::new(
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.TenantId,
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ApplicationId,
                        $certificate[0],
                        $options)
                    $authProvider = [Microsoft.Graph.Authentication.AzureIdentityAuthenticationProvider]::new($clientCertCredential, $null, $null,$true, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Scope)

                    $graphServiceClient = [Microsoft.Graph.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/v1.0")
                    $graphServiceClientBeta = [Microsoft.Graph.Beta.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/beta")

                    $null = $graphServiceClient.Me.GetAsync().Result
                    $null = $graphServiceClientBeta.Me.GetAsync().Result

                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $graphServiceClient
                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $graphServiceClientBeta
                }
                catch
                {
                    Write-Error "Error when connecting to Microsoft Graph with Certificate from Local Certificate Store: $_"
                    throw
                }

                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.MultiFactorAuthentication = $false
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $true
            }
            elseif ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'ServicePrincipalWithSecret')
            {
                Add-MSCloudLoginAssistantEvent -Message 'Connecting to Microsoft Graph with ApplicationSecret' -Source $source
                try
                {
                    $options = [Azure.Identity.ClientSecretCredentialOptions]::new()
                    $options.AuthorityHost = [System.Uri]::new($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthorizationUrl)

                    $clientSecretCredential = [Azure.Identity.ClientSecretCredential]::new(
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.TenantId,
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ApplicationId,
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ApplicationSecret,
                        $options)
                    $authProvider = [Microsoft.Graph.Authentication.AzureIdentityAuthenticationProvider]::new($clientSecretCredential, $null, $null,$true, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Scope)

                    $graphServiceClient = [Microsoft.Graph.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/v1.0")
                    $graphServiceClientBeta = [Microsoft.Graph.Beta.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/beta")

                    $null = $graphServiceClient.Me.GetAsync().Result
                    $null = $graphServiceClientBeta.Me.GetAsync().Result

                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $graphServiceClient
                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $graphServiceClientBeta
                }
                catch
                {
                    Write-Error "Error when connecting to Microsoft Graph with ApplicationSecret: $_"
                    throw
                }

                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.MultiFactorAuthentication = $false
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $true
            }
            elseif ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'ServicePrincipalWithPath')
            {
                Add-MSCloudLoginAssistantEvent -Message 'Connecting to Microsoft Graph with Certificate Path' -Source $source
                try
                {
                    $options = [Azure.Identity.ClientCertificateCredentialOptions]::new()
                    $options.AuthorityHost = [System.Uri]::new($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthorizationUrl)

                    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $CertificatePath), $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
                    $clientCertCredential = [Azure.Identity.ClientCertificateCredential]::new(
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.TenantId,
                        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ApplicationId,
                        $certificate,
                        $options)
                    $authProvider = [Microsoft.Graph.Authentication.AzureIdentityAuthenticationProvider]::new($clientCertCredential, $null, $null,$true, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Scope)

                    $graphServiceClient = [Microsoft.Graph.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/v1.0")
                    $graphServiceClientBeta = [Microsoft.Graph.Beta.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/beta")

                    $null = $graphServiceClient.Me.GetAsync().Result
                    $null = $graphServiceClientBeta.Me.GetAsync().Result

                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $graphServiceClient
                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $graphServiceClientBeta
                }
                catch
                {
                    Write-Error "Error when connecting to Microsoft Graph with Certificate Path: $_"
                    throw
                }

                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.MultiFactorAuthentication = $false
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $true
            }
            elseif ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthenticationType -eq 'AccessTokens')
            {
                Add-MSCloudLoginAssistantEvent -Message 'Connecting to Microsoft Graph with AccessToken' -Source $source

                try
                {
                    $tokenCredential = [Azure.Core.AccessToken]::new($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AccessTokens[0], [DateTimeOffset]::UtcNow.AddHours(1))
                    $authProvider = [Microsoft.Graph.Authentication.AzureIdentityAuthenticationProvider]::new([Azure.Identity.ChainedTokenCredential]::new($tokenCredential), $null, $null, $true, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Scope)

                    $graphServiceClient = [Microsoft.Graph.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/v1.0")
                    $graphServiceClientBeta = [Microsoft.Graph.Beta.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/beta")

                    $null = $graphServiceClient.Me.GetAsync().Result
                    $null = $graphServiceClientBeta.Me.GetAsync().Result

                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $graphServiceClient
                    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $graphServiceClientBeta
                }
                catch
                {
                    throw "Error when connecting to Microsoft Graph with AccessToken: $_"
                }

                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.MultiFactorAuthentication = $false
                $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $true
            }
            Add-MSCloudLoginAssistantEvent -Message 'Connected' -Source $source
        }
        catch
        {
            Add-MSCloudLoginAssistantEvent -Message $_ -Source $source -EntryType 'Error'
            throw $_
        }
    }
}

function Connect-MSCloudLoginMSGraphWithUserMFA
{
    [CmdletBinding()]
    param()

    $source = 'Connect-MSCloudLoginMSGraphWithUserMFA'
    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.TenantId))
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.TenantId
    }

    Add-MSCloudLoginAssistantEvent -Message 'Getting access token from Microsoft Graph using device code' -Source $source

    # Add type with a compiled static method as the callback
    if (-not $Script:IsTypeLoaded)
    {
        Add-Type -TypeDefinition @"
using System;
using System.Threading;
using System.Threading.Tasks;
public static class DeviceCodeCallbackHandler
{
    public static Task HandleDeviceCodeInfo(Azure.Identity.DeviceCodeInfo code, CancellationToken cancellation)
    {
        Console.WriteLine(code.Message);
        return Task.CompletedTask;
    }
}
"@ -ReferencedAssemblies "Azure.Identity", "netstandard", "System.Console"
        $Script:IsTypeLoaded = $true
    }

    try
    {
        $options = [Azure.Identity.DeviceCodeCredentialOptions]::new()
        $options.TenantId = $tenantId
        $options.ClientId = $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ApplicationId
        $options.AuthorityHost = [System.Uri]::new($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AuthorizationUrl)
        $options.DeviceCodeCallback = [DeviceCodeCallbackHandler]::HandleDeviceCodeInfo

        $deviceCodeCredential = [Azure.Identity.DeviceCodeCredential]::new($options)
        $authProvider = [Microsoft.Graph.Authentication.AzureIdentityAuthenticationProvider]::new($deviceCodeCredential, $null, $null, $true, $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Scope)

        $graphServiceClient = [Microsoft.Graph.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/v1.0")
        $graphServiceClientBeta = [Microsoft.Graph.Beta.GraphServiceClient]::new($authProvider, "$($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ResourceUrl)/beta")

        $null = $graphServiceClient.Me.GetAsync().Result
        $null = $graphServiceClientBeta.Me.GetAsync().Result

        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $graphServiceClient
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $graphServiceClientBeta
    }
    catch {
        Write-Error "Error in Connect-MSCloudLoginMSGraphWithUserMFA: $_"
        throw
    }

    Add-MSCloudLoginAssistantEvent -Message 'Successfully connected to Microsoft Graph with MFA' -Source $source

    #$Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.AccessToken = $AccessToken
    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $true
    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.MultiFactorAuthentication = $true
    $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.ConnectedDateTime = [System.DateTime]::Now.ToString()
}

function Disconnect-MSCloudLoginMicrosoftGraphDll
{
    [CmdletBinding()]
    param()

    $source = 'Disconnect-MSCloudLoginMicrosoftGraphDll'

    if ($Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected)
    {
        Add-MSCloudLoginAssistantEvent -Message 'Attempting to disconnect from Microsoft Graph' -Source $source
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClient = $null
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.GraphServiceClientBeta = $null
        $Script:MSCloudLoginConnectionProfile.MicrosoftGraphDll.Connected = $false
        Add-MSCloudLoginAssistantEvent -Message 'Successfully disconnected from Microsoft Graph' -Source $source
    }
    else
    {
        Add-MSCloudLoginAssistantEvent -Message 'No connections to Microsoft Graph were found' -Source $source
    }
}
