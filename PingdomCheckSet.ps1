#Requires -Version 3.0
$DEFAULT_API_VERSION = '2.1'
$current_api_version = $DEFAULT_API_VERSION
$AVAILABLE_PARAMS = @("CheckId", "Limit", "CheckName", "Hostname", "Paused", "Resolution", "ContactIds", "SendToEmail", "SendToSms",
                                    "SendToTwitter", "SendToIphone", "SendToAndroid", "SendNotificationWhenDown", "Offset", "AnalysisId",
                                    "NotifyAgainEvery", "NotifyWhenBackup", "Url", "Encryption", "Port", "Auth", "To", "From", "Status", 
                                    "ShouldContain", "ShouldNotContain", "PostData", "RequestHeader", "StringToSend", "StringToExpect", 
									"Via", "EpectedIp", "NameServer", "ContactName", "Email", "CellPhone", "CountryCode", "CountryIso",
									"DefaultSmsProvider", "DirectTwitter", "TwitterUser")
<################################################
.Synopsis
   Modify settings for a check. 
.Description
   Modify settings for a check. The provided settings will overwrite previous values. 
   Settings not provided will stay the same as before the update. To clear an existing 
   value, provide an empty value. Please note that you cannot change the type of a 
   check once it has been created.

Implemented Checks:
	-HttpCheck
	-PingCheck
	-TcpCheck
	-DnsCheck
	-SmtpCheck

Not yet implemented:
	HTTP Custom
	POP3
	IMAP 
################################################>
Function Set-PingdomCheck{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
		[Parameter(ParameterSetName="http", Mandatory=$true)]
		[switch]$HttpCheck,
		[Parameter(ParameterSetName="ping", Mandatory=$true)]
		[switch]$PingCheck,
		[Parameter(ParameterSetName="tcp", Mandatory=$true)]
		[switch]$TcpCheck,
		[Parameter(ParameterSetName="dns", Mandatory=$true)]
		[switch]$DnsCheck,
		[Parameter(ParameterSetName="smtp", Mandatory=$true)]
		[switch]$SmtpCheck,
        # Pingdom Account Username and Password
        [Parameter(Mandatory=$true, Position=0)]
		[PSCredential]$Credential,
        # Pingdom API Key
		[Parameter(Mandatory=$true, Position=1)]
        [string]$APIKey,
        # Pingdom API Key
		[Parameter(Mandatory=$true, Position=2)]
        [string]$CheckId,
		# Check name
		[Parameter(Position=3)]
		[string]$CheckName,
		# Target host
		[Parameter(Position=4)]
		[string]$Hostname,
		# Paused
		[Parameter(Position=5)]
		[switch]$Paused,
		# Check resolution
		[ValidateSet(1, 5, 15, 30, 60)]
		[Parameter(Position=6)]
		[int]$Resolution,
		# Contact identifiers. For example contactids=154325,465231,765871
		[Parameter(Position=7)]
		[int[]]$ContactIds,
		# Send alerts as email
		[Parameter()]
		[switch]$SendToEmail,
		# Send alerts as SMS
		[Parameter()]
		[switch]$SendToSms,
		# Send alerts through Twitter
		[Parameter()]
		[switch]$SendToTwitter,
		# Send alerts to iPhone
		[Parameter()]
		[switch]$SendToIphone,
		# Send alerts to Android
		[Parameter()]
		[switch]$SendToAndroid,
		# Send notification when down n times
		[Parameter(Position=8)]
		[int]$SendNotificationWhenDown,
		# Notify again every n result. 0 means that no extra notifications will be sent.
		[Parameter(Position=9)]
		[int]$NotifyAgainEvery,
		# Notify when back up again
		[Parameter()]
		[switch]$NotifyWhenBackup,	
		# Target path on server
		[Parameter(ParameterSetName="http", Position=10)]
		[string]$Url,
		# Connection encryption
		[Parameter(ParameterSetName="http", Position=11)]
		[Parameter(ParameterSetName="smtp", Position=12)]
		[switch]$Encryption,
		# Target port
		[ValidateRange(0,65536)]
		[Parameter(ParameterSetName="http", Position=12)]
		[Parameter(ParameterSetName="tcp", Mandatory=$true, Position=9)]
		[Parameter(ParameterSetName="smtp", Position=10)]
		[int]$Port,
		# Username and password for target HTTP authentication. Example: user:password
		[Parameter(ParameterSetName="http", Position=13)]
		[Parameter(ParameterSetName="smtp", Position=11)]
		[string]$Auth,
		# Target site should contain this string
		[Parameter(ParameterSetName="http", Position=14)]
		[string]$ShouldContain,
		# Target site should NOT contain this string. If shouldcontain is also set, this parameter is not allowed.
		[Parameter(ParameterSetName="http", Position=15)]
		[string]$ShouldNotContain,
		# Data that should be posted to the web page, for example submission data for a sign-up or login form. The data needs to be formatted in the same way as a web browser would send it to the web server
		[Parameter(ParameterSetName="http", Position=16)]
		[string]$PostData,
		# Data that should be posted to the web page, for example submission data for a sign-up or login form. The data needs to be formatted in the same way as a web browser would send it to the web server
		[Parameter(ParameterSetName="http", Position=17)]
		[string[]]$RequestHeader,
		# String to send
		[Parameter(ParameterSetName="tcp", Position=11)]
		[string]$StringToSend,
		# String to expect in response
		[Parameter(ParameterSetName="tcp", Position=12)]
		[Parameter(ParameterSetName="smtp", Position=12)]
		[string]$StringToExpect,
		# Expected ip
		[Parameter(ParameterSetName="dns", Mandatory=$true, Position=10)]
		[string]$EpectedIp,
		# Nameserver
		[Parameter(ParameterSetName="dns", Mandatory=$true, Position=11)]
		[string]$NameServer
    )
    [string[]]$queryParams = @()
	if ($HttpCheck){
		$queryParams += "type=http"
	}
	if ($PingCheck){
		$queryParams += "type=ping"
	}
	if ($TcpCheck){
		$queryParams += "type=tcp"
	}
	if ($DnsCheck){
		$queryParams += "type=tcp"
	}
	if ($SmtpCheck){
		$queryParams += "type=dns"
	}
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
    $urlstring = 'https://api.pingdom.com/api/{0}/checks' -f $current_api_version
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
Set-PingdomCheck 