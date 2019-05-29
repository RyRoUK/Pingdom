#Requires -Version 3.0
$DEFAULT_API_VERSION = '2.1'
$current_api_version = $DEFAULT_API_VERSION
<################################################
.Synopsis
   Returns a list of all contacts.
################################################>
Function Get-PingdomContact{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        # Pingdom Account Username and Password
        [Parameter(Mandatory=$true, Position=0)]
		[PSCredential]$Credential,
        # Pingdom API Key
		[Parameter(Mandatory=$true, Position=1)]
        [string]$ApiKey,
		# Limits the number of returned results to the specified quantity.
		[Parameter(Position=2)]
		[int]$Limit,
		# Offset for listing
		[Parameter(Position=3)]
		[int]$Offset
    )
	$urlstring = 'https://api.pingdom.com/api/{0}/contacts' -f $current_api_version
	[string[]]$queryParams = @()
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
Get-PingdomContact 