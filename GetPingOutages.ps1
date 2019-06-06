###################################################################
# FUNCTIONS
###################################################################
function Get-PingOutages {
    $outages = Invoke-RestMethod `
        -Uri 'https://api.pingdom.com/api/2.1/summary.outage/{CheckID}'`
        -Credential 'user@domain.com'`
        -Method 'GET'`
        -Headers @{"App-Key"="YourAPIKey"; "Accept-Encoding"="gzip"}
    $outages.summary.states
}

function ConvertFrom-UnixTimestamp{
	Param(
		$TimeStamp
	)
	$Origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
	return $Origin.AddSeconds($TimeStamp).ToLocalTime()
}

###################################################################
# RUN THE COMMAND
###################################################################

Get-PingOutages | Select-Object `
    Status, `
    @{n="TimeFrom";e={ConvertFrom-UnixTimestamp -TimeStamp $_.TimeFrom}}, `
	@{n="TimeTo";e={ConvertFrom-UnixTimestamp -TimeStamp $_.TimeTo}} `
    | Sort-Object TimeFrom | Format-Table -AutoSize
