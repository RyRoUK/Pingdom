#Requires -Version 3.0
$DEFAULT_API_VERSION = '2.1'
$CURRENT_API_VERSION = $DEFAULT_API_VERSION
$AVAILABLE_PARAMS = @("CheckId", "Limit", "CheckName", "Hostname", "Paused", "Resolution", "ContactIds", "SendToEmail", "SendToSms",
                                    "SendToTwitter", "SendToIphone", "SendToAndroid", "SendNotificationWhenDown", "Offset", "AnalysisId",
                                    "NotifyAgainEvery", "NotifyWhenBackup", "Url", "Encryption", "Port", "Auth", "To", "From", "Status", 
                                    "ShouldContain", "ShouldNotContain", "PostData", "RequestHeader", "StringToSend", "StringToExpect", 
									"Via", "EpectedIp", "NameServer", "ContactName", "Email", "CellPhone", "CountryCode", "CountryIso",
									"DefaultSmsProvider", "DirectTwitter", "TwitterUser")
<################################################
.Synopsis
   Pause or change resolution for multiple checks in one bulk call.
################################################>
Function Set-PingdomCheckBulk{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        # Pingdom Account Username and Password
        [Parameter(Mandatory=$true, Position=0)]
		[PSCredential]$Credential,
        # Pingdom API Key
		[Parameter(Mandatory=$true, Position=1)]
        [string]$APIKey,
		# Check name
		[Parameter(Position=2)]
		[int[]]$CheckIds,
		# Paused
		[Parameter()]
		[switch]$Paused,
		# Check resolution
		[ValidateSet(1, 5, 15, 30, 60)]
		[Parameter(Position=3)]
		[int]$Resolution
    )
    [string[]]$queryParams = @()
    foreach ($key in $PSBoundParameters.Keys.GetEnumerator()){
        if ($AVAILABLE_PARAMS -contains $key){
            $keyString = [string]::Empty
            # Some Pingdom parameters are reserved in Posh
            switch ($key.ToString()){
                'Hostname' {$keyString = "host"}
                'CheckName' {$keyString = "name"}
                Default {$keyString = $_.ToLower()}
            }
            if ($PSBoundParameters[$key].GetType().Name -eq 'DateTime'){
                $queryParams += , "$keyString={0}" -f (ConvertTo-UnixTimestamp $PSBoundParameters[$key])
            }
			elseif ($PSBoundParameters[$key].GetType().BaseType.Name -eq "Array"){
				$queryParams += , "$keyString={0}" -f ($PSBoundParameters[$key] -join ',')
			}
            else{
                $queryParams += , "$keyString={0}" -f $PSBoundParameters[$key]
            }
        }
    }
    $urlstring = 'https://api.pingdom.com/api/{0}/checks' -f $CURRENT_API_VERSION
    $params = @{Credential=$Credential
		APIKey=$APIKey
		API=$urlstring
		Method="Post"}
    if ($queryParams.Count -gt 0){
		$queryParams = $queryParams | ForEach-Object {[Web.HttpUtility]::HtmlEncode($_)}
		$querystring = $queryParams -join '&'
		$params.Add('Query', $querystring)
	}
	Send-Request @params
}

<################################################
.Synopsis
	Additional functions to be used.
################################################>
Function Send-Request{
    Param(
		[PSCredential]$Credential,
        [string]$APIKey,
		[string]$API,
		[string]$Method,
		[string]$Query
    )
	Write-Debug "$Method $API $Query"
	$uriString = $API
	if ($Query){
		$uriString += "?$Query"
	}
	Invoke-RestMethod  -Uri $uriString -Credential $Credential -Method $Method -Headers @{"App-Key"=$APIKey; "Accept-Encoding"="gzip"}
}

Function ConvertFrom-UnixTimestamp{
	Param(
		$TimeStamp
	)
	$Origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
	return $Origin.AddSeconds($TimeStamp).ToLocalTime()
}

Function ConvertTo-UnixTimestamp{
	Param(
		[DateTime]$TimeStamp
	)
	$Origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
	$span = $TimeStamp.ToUniversalTime() - $Origin
	return $span.TotalSeconds
}

Function Get-QueryString{
	Param(
		[Hashtable]$inputObject
	)
	$properties = @()
	foreach($k in $inputObject.Keys.GetEnumerator()){
		$properties += , "{0}={1}" -f $k, $inputObject[$k]
	}
	return $properties -join "&"
}

<################################################
.Synopsis
	Run your commands here...
################################################>
Set-PingdomCheckBulk 