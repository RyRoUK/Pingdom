#Requires -Version 3.0
$DEFAULT_API_VERSION = '2.1'
$CURRENT_API_VERSION = $DEFAULT_API_VERSION
<################################################
.Synopsis
   Returns the raw result for a specified error analysis. This data is primarily 
   intended for internal use, but you might be interested in it as well. However, 
   there is no real documentation for this data at the moment. In the future, we 
   may add a new API method that provides a more user-friendly format.
################################################>
Function Get-PingdomAnalysisRaw{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        # Pingdom Account Username and Password
        [Parameter(Mandatory=$true, Position=0)]
		[PSCredential]$Credential,
        # Pingdom API Key
		[Parameter(Mandatory=$true, Position=1)]
        [string]$APIKey,
		# Check ID
		[Parameter(Mandatory=$true, Position=2)]
        [int]$CheckId,
		# Analysis ID
		[Parameter(Mandatory=$true, Position=3)]
        [int]$AnalysisId,
		# Limits the number of returned results to the specified quantity.
		[Parameter(Position=4)]
		[int]$Limit,
		# Offset for listing
		[Parameter(Position=5)]
		[int]$Offset,
		# Only include actions generated later than this timestamp.
		[Parameter(Position=6)]
		[DateTime]$From,
		# Only include actions generated prior to this timestamp.
		[Parameter(Position=7)]
		[DateTime]$To
    )
	$urlstring = 'https://api.pingdom.com/api/{0}/analysis/{1}/{2}' -f $CURRENT_API_VERSION, $CheckId
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
Get-PingdomAnalysisRaw 