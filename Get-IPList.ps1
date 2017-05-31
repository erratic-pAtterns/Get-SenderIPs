param(
        [string[]]$domains,
        [Switch]$d,
        [String]$export
    )

function Get-SenderIPs {
    
    param(
        [Parameter(Mandatory)][string[]]$domains,
        # call-depth counter (do not specify)
        [Parameter(DontShow)][int]$cd,
        # add domain names to IP addresses
        [Switch]$d
    )

    # call-depth limit - the SPF 'redirect' modifier and 'include' mechanism may create infinite loops
    if ($cd -ge 11) {break}

    $ipList = @()

    foreach ($domain in $domains) {

        # validate domain name
        if ($domain -notmatch "^[\w]+([\-\.]{1}[\w]+)*\.[a-z]+$") {
            Write-Host "ERROR: `"$domain`" is not a valid domain name. Use <domain>.<tld>" -foreground "red"
            exit
        }
        
        # retrieve SPF record
        try {
            $txtQuery = Resolve-DnsName -Type TXT -Name $domain -ErrorAction Stop| where {$_.Strings -like "*spf1*"}
        } catch [System.ComponentModel.Win32Exception] {
            if ($_.Exception.Message -like "*name does not exist") {
                Write-Host "The domain `"$domain`" does not exist!`n" -foreground "cyan"
                continue
            }
        }
        
        # skip domain if no SPF record found
        if (!$txtQuery) {
            Write-Host "No SPF record found for `"$domain`"`n" -foreground "cyan"
            continue
        }
        
        $spfRecord = $txtQuery.Strings.Split(" ")

        foreach ($spfTerm in $spfRecord) {

            switch -wildcard ($spfTerm) 
                {
                    "mx"         {$ipList += Resolve-DnsName -Type MX -Name $domain | foreach {$_.IPAddress}; break}
                    "mx:*"       {$ipList += Resolve-DnsName -Type MX -Name $spfTerm.Substring(3) | foreach {$_.IPAddress}; break}
                    "a"          {$ipList += Resolve-DnsName -Type A -Name $domain | foreach {$_.IPAddress}; break}
                    "a:*"        {$ipList += Resolve-DnsName -Type A -Name $spfTerm.Substring(2) | foreach {$_.IPAddress}; break}
                    "ip4:*"      {$ipList += $spfTerm.Substring(4); break}
                    "include:*"  {$ipList += Get-SenderIPs -domains $spfTerm.Substring(8) -cd ($cd + 1) -d:$d; break}
                    "redirect=*" {$ipList += Get-SenderIPs -domains $spfTerm.Substring(9) -cd ($cd + 1) -d:$d; break}
                }
        }
        # Switch: add $domain to the end of the IP addresses
        if ($d -And $cd -eq 0) {
            # TAB delimited
            $ipList = $ipList -replace "[\d\.\/]+$", "$&`t$domain"
        }
    }
    
    # remove duplicate IPs and return the IP list
    Write-Output $ipList | select -unique
}

function Export-List {
    
    param(
        [Parameter(Mandatory)][array]$list,
        [Parameter(Mandatory)][string]$path
    )

    $fullPath = $path.Trim()
    
    # validate filepath syntax
    if ($fullPath -notmatch "^([a-zA-Z]:\\|\\\\)(((?![<>:`"/\\|?*]).)+((?<![ .])\\)?)*$") {
        Write-Host "EXPORT FAILED: Invalid path syntax!" -foreground "red"
        break       
    } else {
        $fullPath -match ".+\\" | Out-Null
        $parentPath = $matches[0]
    }
    # validate filename
    if ($fullPath -notmatch "(?<=[\\]).+\.(.+$)") {
        Write-Host "EXPORT FAILED: Filename not specified" -foreground "red"
        break
    } else {
        $fileType = $matches[1] 
    }
    # validate parent dir path
    if (!(Test-Path $parentPath)) {
        Write-Host "EXPORT FAILED: Path `"$parentPath`" does not exist!" -foreground "red"
        break
    } 
    # convert ipList into CSV format
    if ($fileType -eq "csv") {
        $ipList = $ipList -replace "[\w\.\/]+", "`"$&`""
        $ipList = $ipList -replace "`t", ","
    }
    # export list into file
    $ipList | Out-File $fullPath -Encoding ASCII
    Write-Host "The list has been exported successfully" -foreground "green"
}


if (!$domains) {
    Write-Host $("No domains given. Enter some domain(s)`n" +
               "Example1: .\Get-IPList.ps1 vamsoft.com`n" +
               "Example2: .\Get-IPList.ps1 -domains vamsoft.com, outlook.com, google.com -d -export " + 
               "C:\Scripts\GL_IP_Exceptions.csv") -foreground "cyan"
} else {
    $ipList = Get-SenderIPs $domains -d:$d
    if ($export) {
        Export-List -list $ipList -path $export
    } else {
        Write-Output $ipList
    }
}