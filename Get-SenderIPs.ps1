function Get-SenderIPs {
    
    param(
        [Parameter(Mandatory=$true)][string[]]$domains,
        [Parameter(Mandatory=$false)][int]$c
    )

    # infinite loop protection - the 'redirect' modifier and 'include' mechanism may create infinite loops
    if ($c -ge 11) {break}

    $ipList = @()

    foreach ($domain in $domains) {

        $txtQuery = Resolve-DnsName -Type TXT -Name $domain | where {$_.Strings -like "*spf1*"}
        # skip domain if no SPF record found
        if (!$txtQuery) {continue}
        
        $spfRecord = $txtQuery.Strings.Split(" ")

        foreach ($spfTerm in $spfRecord) {

            switch -wildcard ($spfTerm) 
                {
                    "mx"         {$ipList += Resolve-DnsName -Type MX -Name $domain | foreach {$_.IPAddress}; break}
                    "mx:*"       {$ipList += Resolve-DnsName -Type MX -Name $spfTerm.Substring(3) | foreach {$_.IPAddress}; break}
                    "a"          {$ipList += Resolve-DnsName -Type A -Name $domain | foreach {$_.IPAddress}; break}
                    "a:*"        {$ipList += Resolve-DnsName -Type A -Name $spfTerm.Substring(2) | foreach {$_.IPAddress}; break}
                    "ip4:*"      {$ipList += $spfTerm.Substring(4); break}
                    "include:*"  {$ipList += get-SenderIPs $spfTerm.Substring(8) ($c + 1); break}
                    "redirect=*" {$ipList += get-SenderIPs $spfTerm.Substring(9) ($c + 1); break}
                }
        }
    }
    # remove duplicate IPs and return the IP list
    Write-Output $ipList | select -unique
}
