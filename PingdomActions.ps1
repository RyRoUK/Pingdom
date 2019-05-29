#Requires -Version 3.0
$DEFAULT_API_VERSION = '2.1'
$CURRENT_API_VERSION = $DEFAULT_API_VERSION
<################################################
.Synopsis
   Returns a list of actions (alerts) that have been generated for your account.
################################################>
Function Get-PingdomActions{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        # Pingdom Account Username and Password
        [Parameter(Mandatory=$true, Position=0)]
		[PSCredential]$Credential,
        # Pingdom API Key
		[Parameter(Mandatory=$true, Position=1)]
        [string]$APIKey,
		# Only include actions generated later than this timestamp.
		[Parameter(Position=2)]
		[DateTime]$From,
		# Only include actions generated prior to this timestamp.
		[Parameter(Position=3)]
		[DateTime]$To,
		# Limits the number of returned results to the specified quantity.
		[Parameter(Position=4)]
		[int]$Limit,
		# Offset for listing
		[Parameter(Position=5)]
		[int]$Offset,
		# Comma-separated list of check identifiers. Limit results to actions generated from these checks.
		[Parameter(Position=6)]
		[string[]]$CheckIds,
		# Comma-separated list of contact identifiers. Limit results to actions sent to these contacts.
		[Parameter(Position=7)]
		[string[]]$ContactIds,
		# Comma-separated list of statuses. Limit results to actions with these statuses. 
		[ValidateSet("sent", "delivered", "error", "not_delivered", "no_credits")]
		[Parameter(Position=8)]
		[string[]]$Status,
		# Comma-separated list of via mediums. Limit results to actions with these mediums.
		[ValidateSet("email", "sms", "twitter", "iphone", "android")]
		[Parameter(Position=9)]
		[string[]]$Via
    )
	$urlstring = 'https://api.pingdom.com/api/{0}/actions'-f $CURRENT_API_VERSION
	[string[]]$queryParams = @()
	if ($PSBoundParameters["From"]){
		$queryParams += , "from={0}" -f (ConvertTo-UnixTimestamp $From)
	}
	if ($PSBoundParameters["To"]){
		$queryParams += , "to={0}" -f (ConvertTo-UnixTimestamp $To)
	}
	if ($PSBoundParameters["Limit"]){
		$queryParams += , "limit={0}" -f $Limit
	}
	if ($PSBoundParameters["Offset"]){
		$queryParams += , "offset={0}" -f $Offset
	}
	if ($PSBoundParameters["CheckIds"]){
		$queryParams += , "checkids={0}" -f ($CheckIds -join ',')
	}
	if ($PSBoundParameters["ContactIds"]){
		$queryParams += , "contactids={0}" -f ($ContactIds -join ',')
	}
	$params = @{Credential=$Credential
		APIKey=$APIKey
		API=$urlstring
		Method="Get"}
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
Get-PingdomActions 