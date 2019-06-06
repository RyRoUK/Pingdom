###################################################################
# FUNCTIONS
###################################################################
function Get-PingChecks {
    $checks = Invoke-RestMethod `
        -Uri 'https://api.pingdom.com/api/2.1/checks'`
        -Credential 'user@domain.com'`
        -Method 'GET'`
        -Headers @{"App-Key"="YourAPIKey"; "Accept-Encoding"="gzip"}
    $checks.checks
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

Get-PingChecks | Select-Object `
    ID, `
    @{n="Created";e={ConvertFrom-UnixTimestamp -TimeStamp $_.Created}}, `
    Name, `
    Hostname, `
    Resolution, `
    Type, `
    IPv6, `
    Verify_Certificate, `
    @{n="LastErrorTime";e={ConvertFrom-UnixTimestamp -TimeStamp $_.LastErrorTime}}, `
    @{n="LastTestTime";e={ConvertFrom-UnixTimestamp -TimeStamp $_.LastTestTime}}, `
    Status `
    | Sort-Object Name | Format-Table -AutoSize 
