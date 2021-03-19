<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2020 v5.7.173
	 Created on:   	7/23/2020 12:32 PM
	 Created by:   	Dakota Zinn
	 Organization: 	
	 Filename:     	WSO2-Auth.psm1
	-------------------------------------------------------------------------
	 Module Name: WSO2-Auth
	===========================================================================
#>

function Connect-WSO2
{
	[CmdletBinding(DefaultParameterSetName = 'Using Kerberos')]
	param
	(
		[Parameter(ParameterSetName = 'JWT',
				   Mandatory = $true)]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string]$HostName,
		[Parameter(ParameterSetName = 'JWT')]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[int]$TokenPort = 8243,
		[Parameter(ParameterSetName = 'JWT')]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[int]$APIPort = 9443,
		[Parameter(ParameterSetName = 'JWT',
				   Mandatory = $false)]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string]$ClientId,
		[Parameter(ParameterSetName = 'JWT',
				   Mandatory = $false)]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string]$ClientSecret,
		[Parameter(ParameterSetName = 'JWT')]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string]$Base64Key,
		[Parameter(ParameterSetName = 'JWT')]
		[string]$JWT,
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string]$KerberosToken,
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string]$KerberosRealm,
		[Parameter(ParameterSetName = 'Username/Password')]
		[string]$Username,
		[Parameter(ParameterSetName = 'Username/Password')]
		[string]$Password,
		[Parameter(ParameterSetName = 'RefreshToken')]
		[string]$RefreshToken,
		[Parameter(ParameterSetName = 'JWT')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[string[]]$Scopes,
		[Parameter(ParameterSetName = 'JWT')]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[switch]$PassThru,
		[Parameter(ParameterSetName = 'JWT')]
		[Parameter(ParameterSetName = 'RefreshToken')]
		[Parameter(ParameterSetName = 'Username/Password')]
		[Parameter(ParameterSetName = 'Using Kerberos')]
		[Alias('ValidFor')]
		[int]$TokenValidityPeriod,
		[switch]$NoAuthorization
	)
	
	process
	{
		if (!$NoAuthorization.IsPresent)
		{
			if ($base64Key -eq "" -and ("" -in @($ClientId, $ClientSecret)))
			{
				$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("An application identifier is required!`r`n(i.e. ConsumerKey/Secret, Base64Key)", "", [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
			elseif ($ClientId -and $ClientSecret)
			{ $base64Key = "$ClientID`:$ClientSecret" | ConvertTo-Base64 }
			if ($base64Key)
			{ <#Do NOT perform any transformations on the data#> }
			
			$OneAuthError = New-Object System.Management.Automation.ErrorRecord("Only one authentication method is allowed!`r`n(Kerberos, Refresh Token, or JWT.)", "", [System.Management.Automation.ErrorCategory]::InvalidArgument, $PSBoundParameters)
			switch ($PSBoundParameters.RefreshToken)
			{
				{ $_ -eq $null }{ break }
				{ $KerberosToken -ne "" } {
					Write-Debug "Token Refresh: Kerberos Token"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $JWT -ne "" } {
					Write-Debug "Token Refresh: JWT"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $Username -ne "" } {
					Write-Debug "Token Refresh: Username"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				default { $Body = "grant_type=refresh_token&refresh_token=$RefreshToken" }
			}
			switch ($PSBoundParameters.KerberosToken)
			{
				{ $_ -eq $null }{ break }
				{ $JWT -ne "" } {
					Write-Debug "Kerberos Autnentication"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $RefreshToken -ne "" } {
					Write-Debug "Kerberos Autnentication"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $Username -ne "" } {
					Write-Debug "Kerberos Autnentication"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $KerberosRealm -eq "" } {
					$KerbError = New-Object System.Management.Automation.ErrorRecord("Cannot use Kerberos Authentication; KerberosRealm not provided", "", [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
					$PSCmdlet.ThrowTerminatingError($KerbError)
				}
				default{
					$body = "grant_type=kerberos&kerberos_realm=$KerberosRealm&kerberos_token=$KerberosToken"
				}
			}
			
			switch ($PSBoundParameters.JWT)
			{
				{ $_ -eq $null }{ break }
				{ $KerberosToken -ne "" }{
					Write-Debug "JWT Autnentication"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $RefreshToken -ne "" }{
					Write-Debug "JWT Autnentication"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $Username -ne "" } {
					Write-Debug "JWT Autnentication"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				default { $body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$JWT" }
			}
			
			switch ($PSBoundParameters.Username)
			{
				{ $_ -eq $null }{ break }
				{ $KerberosToken -ne "" } {
					Write-Debug "Username : Has KerberosToken"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $JWT -ne "" } {
					Write-Debug "Username : Has JWT"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $RefreshToken -ne "" } {
					Write-Debug "Username : Has RefreshToken"
					$PSCmdlet.ThrowTerminatingError($OneAuthError)
				}
				{ $Password -ne "" } {
					Write-Debug "Username/Password Authentication"
					$Body = "grant_type=password&username=$Username&password=$Password"
				}
				default {
					$UserError = New-Object System.Management.Automation.ErrorRecord("Cannot use Username Authentication; Password not provided", "", [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
					$PSCmdlet.ThrowTerminatingError($UserError)
				}
			}
			if (!$body)
			{
				Write-Debug "Client Credentials"
				$Body = "grant_type=client_credentials"
			}
			
			if ($Scopes)
			{
				Write-Verbose "Using Scopes: $($Scopes -join ", ")"
				$Body += "&scope=$($Scopes -join " ")"
			}
			
			$invocation = @{
				Uri = "https://$HostName`:$TokenPort/token"
				Headers = @{ Authorization = "Basic $base64Key" }
				ContentType = "application/x-www-form-urlencoded"
				Body = $Body
				Method = "POST"
			}
			
		}
		
		if ($isLinux -or $isMacOS)
		{ $TokenPath = "$env:HOME" }
		elseif ($isWindows)
		{ $TokenPath = "$env:LOCALAPPDATA" }
		else
		{ $TokenPath = "$env:LOCALAPPDATA" }
		
		$TokenFolder = "$TokenPath/WSO2"
		if (!(Test-Path $TokenFolder -ErrorAction SilentlyContinue))
		{ New-Item -Path $TokenFolder -ItemType directory | Out-Null }
		
		$TokenFile = "$TokenFolder/Token"
		
		try
		{
			if ($NoAuthorization.IsPresent)
			{
				$token = [pscustomobject]@{
					HostName = "$HostName"
					APIPort  = $APIPort
				}
			}
			else
			{
				$token = Invoke-RestMethod @invocation
				if ($token.expires_in -lt 31557600)
				{ $token | Add-Member -MemberType NoteProperty -Name expire_time -Value ((Get-Date).AddSeconds($token.expires_in)) }
				else { $token | Add-Member -MemberType NoteProperty -Name expire_time -Value ((Get-Date).AddYears(15)) }
				#$token | Add-Member -MemberType NoteProperty -Name expires_in -Value $token
				$token | Add-Member -MemberType NoteProperty -Name "HostName" -Value $HostName
				$token | Add-Member -MemberType NoteProperty -Name "APIPort" -Value $APIPort
				$token | Add-Member -MemberType NoteProperty -Name "TokenPort" -Value $TokenPort
				$token | Add-Member -MemberType NoteProperty -Name key -Value $base64Key
				$token | Add-Member -MemberType NoteProperty -Name "ApplicationToken" -Value ($Body -like "grant_type=client_credentials*")
			}
			$token | Convert-ObjectToBase64 | Out-File $TokenFile -Force
			
			
			if ($PassThru)
			{
				if (!$NoAuthorization)
				{
					$token = $token | Select-Object * -ExcludeProperty key, token_type
				}
				return $token
			}
			
		}
		catch
		{
			if ($PSVersionTable.PSCompatibleVersions.major -contains 7)
			{
				$StatusCode = $_.Exception.Response.StatusCode.value__
				$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
				$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($_.Exception.Message, "$statuscode", $ErrCategory, $invocation)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
			else
			{
				$ErrorRecord = $_.Exception.Response.GetResponseStream() | Get-ErrorResult -Invocation $Invocation -StatusCode $_.Exception.Response.StatusCode.value__
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		}
		
	}
}

function Disconnect-WSO2
{
	[CmdletBinding(DefaultParameterSetName = 'Using ClientID/Secret')]
	param
	(
		[Parameter(Mandatory = $false,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 1)]
		[Alias('Refresh_Token')]
		[string]$RefreshToken,
		[Parameter(ParameterSetName = 'Using Base64',
				   Mandatory = $false,
				   ValueFromPipelineByPropertyName = $true)]
		[Alias('Key')]
		[string]$Base64Key,
		[Parameter(ValueFromPipelineByPropertyName = $true,
				   Position = 1)]
		[Alias('access_token')]
		[string]$AccessToken,
		[Parameter(ParameterSetName = 'Using ClientID/Secret')]
		[string]$ClientID,
		[Parameter(ParameterSetName = 'Using ClientID/Secret')]
		[string]$ClientSecret
	)
	begin
	{
		
		if ($isLinux -or $isMacOS)
		{ $TokenPath = "$env:HOME" }
		if ($isWindows)
		{ $TokenPath = "$env:LOCALAPPDATA" }
		if (!$tokenPath)
		{ $TokenPath = "$env:LOCALAPPDATA" }
		$TokenFolder = "$TokenPath/WSO2"
		$TokenFile = "$TokenFolder/Token"
	}
	process
	{
		$TokenInfo = Get-Content $TokenFile | ConvertFrom-Base64 | ConvertFrom-Json
		$TokenPort = $TokenInfo.TokenPort
		$HostName = $TokenInfo.HostName
		$tokenAPI = "https://$HostName`:$TokenPort/revoke"
		
		if (!$PSBoundParameters.Base64Key -and !$PSBoundParameters.ClientID -and !$PSBoundParameters.ClientSecret)
		{
			$Token = (Get-Content $TokenFile | ConvertFrom-Base64 | ConvertFrom-Json)
			$Base64Key = $Token.key
			$AccessToken = $Token.access_token
		}
		if ($PSBoundParameters.ClientID -and $PSBoundParameters.ClientSecret)
		{ $Base64Key = "$($PSBoundParameters.ClientID)`:$($PSBoundParameters.ClientSecret)" | ConvertTo-Base64 }
		if ($Base64Key)
		{
			if ($PSBoundParameters.AccessToken)
			{ $Body = "token=$($PSBoundParameters.AccessToken)&token_type_hint=access_token" }
			elseif ($PSBoundParameters.RefreshToken)
			{ $Body = "token=$($PSBoundParameters.RefreshToken)&token_type_hint=refresh_token" }
			$header = @{ Authorization = "Basic $Base64Key" }
			$invocation = @{
				Uri		    = $tokenAPI
				Headers	    = $header
				ContentType = "application/x-www-form-urlencoded"
				Body	    = $Body
				Method	    = "POST"
			}
			
			try
			{
				
				$response = Invoke-RestMethod @invocation
				if ($PSBoundParameters.AccessToken)
				{
					if ($TokenInfo.access_token -eq $PSBoundParameters.AccessToken)
					{
						$TokenInfo.access_token = ""
						$TokenInfo.refresh_token = ""
						$TokenInfo | ConvertTo-Json | ConvertTo-Base64 | Out-File $TokenFile -Force
					}
				}
				elseif ($PSBoundParameters.RefreshToken)
				{
					if ($TokenInfo.refresh_token -eq $PSBoundParameters.RefreshToken)
					{
						$TokenInfo.access_token = ""
						$TokenInfo.refresh_token = ""
						$TokenInfo | ConvertTo-Json | ConvertTo-Base64 | Out-File $TokenFile -Force
					}
				}
				#Remove-Item -Path $TokenFile -Force -ErrorAction Ignore
				Write-Output "Token Revoked"
			}
			catch
			{
				$result = $_.Exception.Response.GetResponseStream()
				$reader = New-Object System.IO.StreamReader($result)
				$reader.BaseStream.Position = 0
				$reader.DiscardBufferedData()
				$response = $reader.ReadToEnd();
				$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("$response", "", [system.management.automation.errorcategory]::InvalidResult, $invocation)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		}
	}
}

function Get-WSO2Token
{
	[CmdletBinding()]
	param ()
	
	if ($isLinux -or $isMacOS)
	{ $TokenPath = "$env:HOME" }
	elseif ($isWindows)
	{ $TokenPath = "$env:LOCALAPPDATA" }
	else
	{ $TokenPath = "$env:LOCALAPPDATA" }
	
	$TokenFolder = "$TokenPath/WSO2"
	if (!(Test-Path $TokenFolder -ErrorAction SilentlyContinue))
	{ New-Item -Path $TokenFolder -ItemType directory | Out-Null }
	
	$TokenFile = "$TokenFolder/Token"
	
	if (!(Test-Path $TokenFile -ErrorAction SilentlyContinue))
	{ throw "Could not get local token, use Connect-WSO2 to get a new token" }
	
	#if (!(Test-Path "$TokenFile" -ErrorAction SilentlyContinue))
	#{ $PSCmdlet.ThrowTerminatingError($_) }
	
	$Token = gc $TokenFile | ConvertFrom-Base64 | ConvertFrom-JSON
	if ($Token.access_token)
	{
		$AccessToken = $Token | select access_token, refresh_token, hostname, expire_time, apiport, tokenport, scope, expires_in
		$AccessToken.expire_time = ([datetime]$AccessToken.expire_time).toLocalTime()
		$AccessToken.expires_in = $([math]::Round((New-TimeSpan -Start (Get-Date) -End $AccessToken.expire_time).TotalSeconds))
		if ($Token.id_token)
		{ $AccessToken | Add-Member -MemberType NoteProperty -Name "id_token" -Value $Token.id_token }
		if ($AccessToken.expires_in -le 0)
		{
			Write-Verbose "Token has expired"
			#Token has expired
			if ($Token.applicationtoken -eq $true)
			{
				write-verbose "Attempting to retreive new Application Token"
				try { Connect-WSO2 -HostName $Token.hostname -TokenPort $Token.tokenport -Base64Key $Token.key }
				catch { $PSCmdlet.ThrowTerminatingError($_) }
			}
			elseif ($Token.key -and $Token.refresh_token -notin @("",$null))
			{
				Write-Verbose "Attempting to automatically refresh the token"
				try
				{
					$Token = Connect-WSO2 -HostName $Token.hostname -TokenPort $Token.tokenport -Base64Key $Token.key -RefreshToken $Token.refresh_token -PassThru
					return $Token
				}
				catch { $PSCmdlet.ThrowTerminatingError($_) }
			}
			
			else
			{
				$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Access Token has expired.", "", [System.Management.Automation.ErrorCategory]::SecurityError, $null)
				$PSCmdlet.ThrowTerminatingError($ErrorRecord)
			}
		}
		else { return $AccessToken }
	}
	else { return $Token }
}

function Register-DynamicClient
{
<#
	.SYNOPSIS
		Register a client to use admin/publisher/devportal APIs
	
	.DESCRIPTION
		Register a client to use admin/publisher/devportal APIs
	
	.PARAMETER Credentials
		Credentials to register a dynamic client. This is typically the Admin user credentials
	
	.PARAMETER DCREndpoint
		The full dynamic client registration url
		e.g. https://localhost:9443/client-registration/v0.16/register
	
	.PARAMETER callbackUrl
		The URL callback for the application, this will be where the user is redirected after signing in.
	
	.PARAMETER ClientName
		Name of the Application/Client
	
	.PARAMETER Owner
		Owner of the Client, should match the user in the credentials
	
	.PARAMETER AllowedGrantTypes
		List of grant types allowed to be used with the client
	
	.PARAMETER SaaSApp
		Switch that indicates whether the client is a SaaS App
	
	.EXAMPLE
		PS C:\> Register-DynamicClient -DCREndpoint 'https://localhost:9443/client-registration/v0.16/register' -ClientName 'admin_app' `
		-Owner 'admin' -AllowedGrantTypes "client_credentials refresh_token"
	
#>
	
	[CmdletBinding()]
	param
	(
		[pscredential]$Credentials = (Get-Credential),
		[Parameter(Mandatory = $false)]
		[string]$DCREndpoint,
		[string]$callbackUrl,
		[Parameter(Mandatory = $true)]
		[Alias('AppName', 'ServiceProviderName')]
		[string]$ClientName,
		[Parameter(Mandatory = $true)]
		[string]$Owner,
		[Parameter(Mandatory = $true)]
		[string[]]$AllowedGrantTypes,
		[switch]$SaaSApp
	)
	
	$JSON = [pscustomobject]@{
		callbackUrl = $PSBoundParameters.callbackurl
		clientName  = $PSBoundParameters.clientName
		owner	    = $PSBoundParameters.owner
		grantType   = ($PSBoundParameters.AllowedGrantTypes -join " ")
		saasApp	    = $SaaSApp.IsPresent
	}
	
	$body = $JSON | ConvertTo-Json
	
	try
	{
		Invoke-RestMethod -Headers @{ Authorization = "Basic $("$($credentials.UserName):$($Credentials.GetNetworkCredential().Password)" | ConvertTo-Base64)" } `
						  -Method POST -Uri $DCREndpoint -Body $body -ContentType "Application/JSON"
	}
	catch
	{
		if ($PSVersionTable.PSCompatibleVersions.major -contains 7)
		{
			$StatusCode = $_.Exception.Response.StatusCode.value__
			$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($_.Exception.Message, "$statuscode", $ErrCategory, $invocation)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
		else
		{
			$ErrorRecord = $_.Exception.Response.GetResponseStream() | Get-ErrorResult -Invocation $Invocation -StatusCode $_.Exception.Response.StatusCode.value__
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
}

function Unregister-DynamicClient
{
<#
	.SYNOPSIS
		Delete an Oauth application
	
	.DESCRIPTION
		Delete an Oauth application
	
	.PARAMETER Credentials
		A description of the Credentials parameter.
	
	.PARAMETER DCRendpoint
		A description of the DCRendpoint parameter.
	
	.PARAMETER ClientId
		A description of the ClientId parameter.
	
	.EXAMPLE
		PS C:\> Unregister-DynamicClient -Credentials $Credentials -DCREndpoint 'https://localhost:9443/api/identity/oauth2/dcr/v1.1/register/' -ClientId 's6BhdRkqt3'
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[pscredential]$Credentials,
		[Parameter(Mandatory = $true)]
		[string]$DCREndpoint,
		[Parameter(Mandatory = $true)]
		[string]$ClientId
	)
	
	try
	{
		Invoke-RestMethod -Headers @{ Authorization = "Basic $("$($credentials.UserName):$($Credentials.GetNetworkCredential().Password)" | ConvertTo-Base64)" } `
						  -Method DELETE -Uri "$DCREndpoint/$ClientId" -ContentType "Application/JSON"
	}
	catch
	{
		if ($PSVersionTable.PSCompatibleVersions.major -contains 7)
		{
			$StatusCode = $_.Exception.Response.StatusCode.value__
			$ErrCategory = [system.management.automation.errorcategory]::InvalidOperation
			$ErrorRecord = New-Object System.Management.Automation.ErrorRecord($_.Exception.Message, "$statuscode", $ErrCategory, $invocation)
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
		else
		{
			$ErrorRecord = $_.Exception.Response.GetResponseStream() | Get-ErrorResult -Invocation $Invocation -StatusCode $_.Exception.Response.StatusCode.value__
			$PSCmdlet.ThrowTerminatingError($ErrorRecord)
		}
	}
}

#region Conversions
function Convert-FileToBase64
{
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		$Filepath
	)
	process
	{
		$bufferSize = 9000 # should be a multiplier of 3
		$buffer = New-Object byte[] $bufferSize
		
		$reader = [System.IO.File]::OpenRead($Filepath)
		$writer = ""
		$bytesRead = 0
		do
		{
			$bytesRead = $reader.Read($buffer, 0, $bufferSize);
			$writer += ([Convert]::ToBase64String($buffer, 0, $bytesRead))
		}
		while ($bytesRead -eq $bufferSize);
		
		$reader.Dispose()
		return $writer
	}
	
}


function Convert-Base64ToFile
{
	param
	(
		$B64String,
		$OutFilePath
	)
	$bytes = [Convert]::FromBase64String($B64String)
	[IO.File]::WriteAllBytes($OutFilePath, $bytes)
}


function Convert-ObjectToBase64
{
	[CmdletBinding()]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		$psobject
	)
	
	process
	{
		$ObjString = [string]($psobject | ConvertTo-Json -Depth 10 -Compress)
		$String = [System.Text.Encoding]::UTF8.GetBytes($ObjString)
		[System.convert]::ToBase64String($string)
	}
}


function ConvertTo-Base64
{
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[string]$String
	)
	
	Process
	{
		$BytesString = [System.Text.Encoding]::UTF8.GetBytes($String)
		[System.convert]::ToBase64String($BytesString)
	}
}


function ConvertFrom-Base64
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[string]$base64String
	)
	
	process
	{
		$bytes = [System.Convert]::FromBase64String($base64String)
		[System.Text.Encoding]::UTF8.GetString($bytes)
	}
}


function ConvertFrom-EPOCHDate
{
	[OutputType([datetime])]
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		$date
	)
	begin { $UTCOffset = [System.TimeZoneInfo]::Local.GetUtcOffset((get-date)).totalseconds }
	process
	{
		if ($date)
		{
			$newdate = (get-date -Date "1/1/1970").AddSeconds($date).AddSeconds($UTCOffset)
			return $newdate
		}
		else { return $null }
	}
}


function ConvertTo-EPOCHDate
{
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		[datetime]$Date
	)
	begin { $UTCOffset = (([System.TimeZoneInfo]::Local.GetUtcOffset((get-date)).totalseconds) * -1) }
	process
	{ [System.Math]::Round((New-TimeSpan (get-date -Date "1/1/1970") ($Date).AddSeconds($UTCOffset)).TotalSeconds) }
}


function ConvertFrom-Hashtable
{
	param (
		[Parameter(
				   Position = 0,
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true
				   )]
		[object[]]$hashtable
	);
	
	begin { $i = 0; }
	
	process
	{
		foreach ($myHashtable in $hashtable)
		{
			if ($myHashtable.GetType().Name -eq 'hashtable')
			{
				$output = New-Object -TypeName PsObject;
				Add-Member -InputObject $output -MemberType ScriptMethod -Name AddNote -Value {
					Add-Member -InputObject $this -MemberType NoteProperty -Name $args[0] -Value $args[1];
				};
				$myHashtable.Keys | Sort-Object | ForEach-Object {
					$output.AddNote($_, $myHashtable.$_);
				}
				$output;
			}
			else
			{
				Write-Warning "Index $i is not of type [hashtable]";
			}
			$i += 1;
		}
	}
}


function ConvertTo-HashTable
{
	param (
		[Parameter(
				   Position = 0,
				   Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true
				   )]
		[object[]]$psCustomObject
	);
	
	process
	{
		foreach ($myPsObject in $psObject)
		{
			$output = @{ };
			$myPsObject | Get-Member -MemberType *Property | ForEach-Object {
				$output.($_.name) = $myPsObject.($_.name);
			}
			$output;
		}
	}
}


function ConvertFrom-Jwt
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[string]$Token,
		[switch]$IncludeHeader
	)
	process
	{
		# Validate as per https://tools.ietf.org/html/rfc7519
		# Access and ID tokens are fine, Refresh tokens will not work
		if (!$Token.Contains(".") -or !$Token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
		
		# Extract header and payload
		$tokenheader, $tokenPayload = $Token.Split(".").Replace('-', '+').Replace('_', '/')[0 .. 1]
		
		# Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
		while ($tokenheader.Length % 4) { Write-Debug "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
		while ($tokenPayload.Length % 4) { Write-Debug "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
		
		Write-Debug "Base64 encoded (padded) header:`n$tokenheader"
		Write-Debug "Base64 encoded (padded) payoad:`n$tokenPayload"
		
		# Convert header from Base64 encoded string to PSObject all at once
		$header = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json
		Write-Debug "Decoded header:`n$header"
		
		# Convert payload to string array
		$tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))
		Write-Debug "Decoded array in JSON format:`n$tokenArray"
		
		# Convert from JSON to PSObject
		$tokobj = $tokenArray | ConvertFrom-Json
		Write-Debug "Decoded Payload:"
		
		if ($IncludeHeader) { $header }
		return $tokobj
	}
	
}
#endregion Conversions


function Set-UseUnsafeHeaderParsing
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "This is required for Kerberos Auth, not to be used by end-user")]
	param (
		[Parameter(Mandatory, ParameterSetName = 'Enable')]
		[switch]$Enable,
		[Parameter(Mandatory, ParameterSetName = 'Disable')]
		[switch]$Disable
	)
	
	$ShouldEnable = $PSCmdlet.ParameterSetName -eq 'Enable'
	
	$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])
	
	if ($netAssembly)
	{
		$bindingFlags = [Reflection.BindingFlags] 'Static,GetProperty,NonPublic'
		$settingsType = $netAssembly.GetType('System.Net.Configuration.SettingsSectionInternal')
		
		$instance = $settingsType.InvokeMember('Section', $bindingFlags, $null, $null, @())
		
		if ($instance)
		{
			$bindingFlags = 'NonPublic', 'Instance'
			$useUnsafeHeaderParsingField = $settingsType.GetField('useUnsafeHeaderParsing', $bindingFlags)
			
			if ($useUnsafeHeaderParsingField)
			{ $useUnsafeHeaderParsingField.SetValue($instance, $ShouldEnable) }
		}
	}
}

function Get-ErrorResult
{
	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true)]
		$Result,
		$Invocation,
		[int]$statuscode
	)
	process
	{
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$response = $reader.ReadToEnd();
		
		switch -Wildcard ($response)
		{
			"*Missing parameters*"{ $ErrCategory = [system.management.automation.errorcategory]::InvalidArgument }
			"*Forbidden*"{ $ErrCategory = [system.management.automation.errorcategory]::PermissionDenied }
			default { $ErrCategory = [system.management.automation.errorcategory]::InvalidOperation }
		}
		$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("$response", "$statuscode", $ErrCategory, $invocation)
		return $ErrorRecord
	}
}


function Get-AzureJWT
{
	[CmdletBinding()]
	param
	(
		[string]$ClientId,
		[string]$TenantId,
		[switch]$ForcePrompt
	)
	
		Import-Module MSAL.PS
		$Splat = @{
			ClientId = $PSBoundParameters.ClientID
			TenantId = $TenantId
			RedirectURI = "http://localhost"
		}
		try
		{
			if ($PSBoundParameters.ForcePrompt)
			{
				Write-Verbose "Acquiring ID token in forground through MSAL"
				$AzureToken = Get-MsalToken @splat -Interactive
			}
			else
			{
				Write-Verbose "Acquiring ID token silently through MSAL"
				$AzureToken = Get-MsalToken @splat -IntegratedWindowsAuth
			}
		}
		catch [Microsoft.Identity.Client.MsalClientException]{
			$AzureError = $_.exception.message
		}
		
		if ($AzureError)
		{
			switch -Wildcard ($AzureError)
			{
				"Failed to get user*"{
					Try
					{
						Write-Verbose "Acquiring ID Token Interactively through MSAL"
						$AzureToken = Get-MsalToken @splat -Interactive
					}
					catch
					{
						$ErrCategory = [system.management.automation.errorcategory]::AuthenticationError
						$ErrorRecord = New-Object System.Management.Automation.ErrorRecord("Could not acquire a token interactively or silently.'", "", $ErrCategory, $null)
						$PSCmdlet.ThrowTerminatingError($ErrorRecord)
					}
				}
			}
		}
		
		if ($AzureToken)
		{ return $AzureToken.IdToken }
}