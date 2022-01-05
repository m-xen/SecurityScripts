# Author : Martin Hill
# Version: 1.1


<#
.SYNOPSIS
    Creates a HTML report of AD Service Account Properties, useful for mitigating the Kerberoasting attack technique.
    https://attack.mitre.org/techniques/T1558/003/
    Plus trawls Domain Controller event logs for related Kerberos activity to help determine where each account is used.
    
.DESCRIPTION
    
    User accounts (or all accounts with parameter "-filter all") with Service Principal Names (SPN) set will be listed. 
    Account Properties related to mitigating the above attack will be listed (where set), including;

        GroupMembership - A common insecure configuration is to add a service account to an administrative group (e.g. Domain Admins)
        PasswordLastSet - Is the password being rotated?
                          Passwords set before the domain functional level is upgraded to 2008 do not have AES keys, the domain group Read-only Domain Controllers creation date indicates the upgrade date.
                          Reset service account passwords twice for accounts with a password older than the RODC Group created on date.  
        LogonTo...      - Is the account restricted to logon only to specific computers?
        LastLogon       - Is the account in use?
                          This is queried from the lastlogontimestamp attribute,
                          with default settings, this could have been replicated between domain controllers up to 14 days ago,
                          but is chosen over the lastlogon property as that is never replicated between domain controllers.
    Local Eventlog entries for Kerberos Ticket Granting Service (TGS) ticket requests related to the service account logon will be added if available
    EventID:4769 >>> https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769

N.B. Run with elevated administrator credentials, preferably on a Domain Controller.
        
.EXAMPLE 1

    Return an html report of *user* accounts that have registered SPNs in the current user's domain.
    
    PS .\Get-SPN.ps1  

    AZUREADSSOACC

    Description  
    SAMAccountName AZUREADSSOACC$ 
    UserPrincipalName  
    DistinguishedName CN=AZUREADSSOACC,CN=Computers,DC=domain,DC=local 
    GroupMembership  
    Created 01/01/2021 00:00:00 
    Modified 01/01/2021 00:00:00 
    PasswordLastSet 01/01/2021 00:00:00 
    LastLogon 01/01/1601 00:00:00 
    AccountExpires <Never> 
    SPN Count 10 

    SPNs

    HTTP/www.tm.a.prd.aadg.akadns.net 
    HTTP/www.tm.a.prd.aadg.trafficmanager.net 
    HTTP/aadg.windows.net.nsatc.net 
    HTTP/autologon.prda.aadg.msidentity.com 
    HTTP/autologon.microsoftazuread-sso.com 
    RestrictedKrbHost/www.tm.a.prd.aadg.akadns.net 
    RestrictedKrbHost/www.tm.a.prd.aadg.trafficmanager.net 
    RestrictedKrbHost/aadg.windows.net.nsatc.net 
    RestrictedKrbHost/autologon.prda.aadg.msidentity.com 
    RestrictedKrbHost/autologon.microsoftazuread-sso.com

    
    Eventlog Details

    Service Name: AZUREADSSOACC >>> Client Address: ::1 >>> Ticket Encryption Type: 0x12  


.EXAMPLE 2

Return an html report of *all* accounts that have registered SPNs in the current user's domain.
    
    PS .\Get-SPN.ps1 -filter all

#>
Param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("all")]
        [string]$filter
    )

Set-Strictmode -version latest
$ErrorActionPreference = "Continue"

$execDateTime = Get-Date
$execDateTimeYEAR = $execDateTime.Year
$execDateTimeMONTH = $execDateTime.Month
$execDateTimeDAY = $execDateTime.Day
$execDateTimeHOUR = $execDateTime.Hour
$execDateTimeMINUTE = $execDateTime.Minute
$execDateTimeSECOND = $execDateTime.Second
$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)

$currentScriptFolderPath = Get-Location
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
[string]$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Get-SPN.log")
[string]$reportFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_SPN_Audit_Report.htm")
$events = [System.Collections.ArrayList]::new()
$filtered = [System.Collections.ArrayList]::new()
$eventJunk = "This event is generated every time access is requested to a resource such as a computer or a Windows service.  The service name indicates the resource to which access was requested.

This event can be correlated with Windows logon events by comparing the Logon GUID fields in each event.  The logon event occurs on the machine that was accessed, which is often a different machine than the domain controller which issued the service ticket.

Ticket options, encryption types, and failure codes are defined in RFC 4120."

Function Logging($dataToLog) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
}

Function EventLogs($serviceName, $filteredEvents){
    $client = [System.Collections.ArrayList]::new()
    Foreach($event in $filteredEvents){
        $addThisEvent = $false
        If($event -like "*$serviceName*"){
            #split the event per line
            $event = $event -split "`n"
            #run through the event detail line by line
            Foreach($line in $event){
                #look for the events for this service account
                If($line -like "*$serviceName*"){
                    $addThisEvent = $true
                    $svc = $line
                    }
                If($line -like "*Client Address:*"){
                    $address = $line
                    }
                If($line -like "*Ticket Encryption Type:*"){
                    $enc = $line
                    }
                }
            }
        If($addThisEvent){
        $client.add($svc + ">>>" + $address + ">>>" + $enc) | Out-null
        $svc = $null
        $address = $null
        $enc = $null
        $addThisEvent = $false
        }
    }
    $client = $client | Sort-Object -Unique
    Return $client
}

#Load ActiveDirectory PowerShell Module
If(@(Get-Module -ListAvailable | Where-Object{$_.Name -eq 'ActiveDirectory'} ).count -ne 0){
    Import-Module 'ActiveDirectory'
    Logging "Loaded ActiveDirectory PowerShell Module"
    }
Else{
    Logging "Failed to load the ActiveDirectory Powershell Module"
    Exit
}


$domainControllers = (Get-ADDomainController -filter * | Select-Object name)

Logging "Found $($domainControllers.count) domain controllers"

Foreach($dc in $domainControllers){
    Try{
    $events += Get-WinEvent -FilterHashtable @{LogName='Security';ID='4769';ProviderName='Microsoft-Windows-Security-Auditing'} -ComputerName $dc.name | Select -ExpandProperty Message
    }
    Catch [System.Diagnostics.Eventing.Reader.EventLogException]{
       Logging "RPC Server unavailable on $($dc.name)"
    }
}
Foreach($event in $events){
$filtered.add(($event -Replace '(?={)(.*)(?>})','' -Replace '(\s+)Client Port:(\s+\d+)','' -Replace 'A Kerberos service ticket was requested.',"`r`n" -replace $eventJunk,''))
}
$filtered = $filtered | Sort-Object -Unique

$ObjDomain = [ADSI]""  
$ObjSearcher = New-Object System.DirectoryServices.DirectorySearcher $ObjDomain
$ObjSearcher.PageSize = 1000
$ObjSearcher.SearchScope = "Subtree"

#Check when domain was upgraded to 2008
$ObjSearcher.Filter = "(samAccountName=Read-only Domain Controllers)"
$Groupc = $ObjSearcher.FindAll()
$Groupc  | ForEach-Object { 
                        $GroupProps = [ordered]@{} 
                        $GroupProps.Add('RODCs Created On',"$($_.properties.whencreated)") | Out-null
                        }
[string]$RODC = $GroupProps.Values.GetEnumerator()

if ($filter){
$ObjSearcher.Filter = "(ServicePrincipalName=*)"
}else{
$ObjSearcher.Filter = "(|(&(objectCategory=user)(ServicePrincipalName=*))(sAMAccountName=AZUREADSSOACC$))"
}

# Get a count of the number of accounts that match the LDAP query
$Records = $ObjSearcher.FindAll()
$RecordCount = $Records.count

# Create report of search results, if results exist
if ($RecordCount -gt 0){
    New-Item $reportFilePath -Force
    $style = "<style>"
    $style = $style + "body{font-family:Sans-Serif;color:black;}"
    $style = $style + "table{border-width: 2px;border-style: solid;border-color:black;}"
    $style = $style + "table{background-color:#D0D0D0;border-collapse: collapse;}"
    $style = $style + "th{border-width:1px;padding-left:5px;border-style:solid;border-color:black;}"
    $style = $style + "td{border-width:1px;padding-left:5px;border-style:solid;border-color:black;}"
    $style = $style + "</style>"
    ConvertTo-Html -Title "Service Principal Names" -Head $style -Body "Script runtime = $execDateTimeCustom <br> <br> N.B. If the domain was upgraded from Windows Server 2003 functional level, any passwords older than $RODC should be changed twice." | Out-File -Append "$reportFilePath"
    # Display account records                
    $ObjSearcher.FindAll() | ForEach-Object {

        # Fill hash array with results                    
        $UserProps = [ordered]@{}               
        try{$UserProps.Add('Description', "$($_.properties.description)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{Logging "$($Userw.Path)  $_"}
        try{$UserProps.Add('SAMAccountName', "$($_.properties.samaccountname)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{Logging "$($Userw.Path)  $_"}
        try{$UserProps.Add('UserPrincipalName', "$($_.properties.userprincipalname)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{Logging "$($Userw.Path)  $_"}
        try{$UserProps.Add('DistinguishedName', "$($_.properties.distinguishedname)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{Logging "$($Userw.Path)  $_"}
        try{$UserProps.Add('GroupMembership', "$($_.properties.memberof)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{Logging "$($Userw.Path)  $_"}
        $Userw = [adsi]$_.Properties.adspath[0]
        try{$UserProps.Add('LogonTo...', "$($Userw.get("userWorkstations"))") | Out-null
        }catch{
        Logging "$($Userw.Path)  has no user workstations property"
        $UserProps.Add('LogonTo...', "")
        }
        try{$UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        $UserProps.Add('Created', "") | Out-null
        }
        try {$UserProps.Add('Modified', [dateTime]"$($_.properties.whenchanged)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        $UserProps.Add('Modified', "") | Out-null
        }
        try{$UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)")) | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        $UserProps.Add('PasswordLastSet', "") | Out-null
        }
        try{$UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogontimestamp)")) | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        $UserProps.Add('LastLogon',"") | Out-null
        }
        try{$UserProps.Add('AccountExpires',( &{$exval = "$($_.properties.accountexpires)"
                If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                {
                    $acctExpires = "<Never>"
                    $acctExpires
                }Else{
                    try{$Date = [DateTime]$exval
                        $acctExpires = $Date.AddYears(1600).ToLocalTime()
                        $acctExpires
                    }catch{
                    $acctExpires = ""
                    $acctExpires
                    }
                }
        })) | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        }
        try{$UserProps.Add('SPN Count', "$($_.properties['ServicePrincipalName'].count)") | Out-null
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        }
        try{$Spns = $_.properties['ServicePrincipalName']
        }catch [System.Management.Automation.PropertyNotFoundException]{
        Logging "$($Userw.Path)  $_"
        }
        $SPN_Count = $Spns.count
        if ($SPN_Count -gt 0)
        {
            [string]$PreContent = (($_.properties.name).GetEnumerator()).ToUpper()
            $UserProps.GetEnumerator() | ConvertTo-Html -Property Name,Value -Fragment -PreContent "<h2>$PreContent</h2>" | % { $_.replace('<tr><th>Name</th><th>Value</th></tr>', '<tr><th></th><th>AD Account Details</th></tr>')} | Out-File -Append "$reportFilePath"
            "<br> "| Out-File -Append "$reportFilePath"
            $Spns | ConvertTo-HTML @{ l='SPNs'; e={ $_ } } -Fragment | Out-File -Append "$reportFilePath"
            $eventDetails = [System.Collections.ArrayList]::new()
            $eventDetails = EventLogs $PreContent $filtered
            "<br> "| Out-File -Append "$reportFilePath"
            $eventDetails | ConvertTo-HTML @{ l='Eventlog Details (Encryption Type Codes >> 0x11=aes128,0x12=aes256,0x17=rc4)'; e={ $_ } } -Fragment | Out-File -Append "$reportFilePath"
        }
    }
Logging "Report $reportFilePath successfully generated"                       
}else{

    # Display fail
    Logging "No records were found that match your search."
}