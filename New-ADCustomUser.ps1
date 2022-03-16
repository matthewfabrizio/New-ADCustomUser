[CmdletBinding(SupportsShouldProcess)]
param ()

<#
.SYNOPSIS
Takes a list of users and checks them against Active Directory.

.DESCRIPTION
Takes a csv file of users and checks to see if they exist in Active Directory.
The goal is to see if the source list (from SIS) has a matching set of users in AD.

.PARAMETER Path
CSV File Path.

.EXAMPLE
Get-InactiveADUsers -Path Path\To\csv.csv

.NOTES
If you think you have a lot of differences between the source SIS and destination, then you should
run this function separately to try and clean up all users.
WIP
#>
function Get-InactiveADUsers {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Object]
        $Path
    )
    Write-Verbose -Message $MyInvocation.MyCommand

    # https://community.spiceworks.com/topic/2130306-list-users-not-in-csv
    $SourceUsers = Import-CSV -Path "$PSScriptRoot\import\users.csv"
    
    # pull searchbase from config file
    $Users = Get-ADUser -SearchBase $UserInfo.ActiveDirectory.UserOrgRoot -Filter * -Properties Description, employeeID -Server $Server |
    Where-Object { $SourceUsers.'Id Number' -notcontains $_.employeeID } |
    Where-Object { $PSItem.Description -notmatch 'Generic' }

    "LOG : $($Users.Count) users found in Active Directory but not in source file."
    $Users | Export-Csv -Path "$PSScriptRoot\users-in-ad-notin-source.csv" -NoTypeInformation

    <#
    This currently includes generic accounts as they will never be within the SIS.
    The only way to avoid this is to use an identifier to exclude the accounts. Viable methods are as follows:
        - Add the excluded accounts to the config file
            - Downside is that you always have to update the script files whenever you make an account, eh.
        - Add a specific word to the AD object that can be used in an exclude
            - ex. Office can be set to Generic. Get-ADUser is then set to exclude accounts with Office = Generic
            - Downside is that you always have to remember to enter this field or your account will get disabled the next day.
    #>

    # take $Users and move (Move-ADObject) to the disabled accounts org (specify in config)
    # having some method of organizing the org into sub orgs would be helpful for routine cleanup of disabled accounts
    # maybe create a sub ou for the current year and whenever an account is inactive it gets moved to that years ou
    # the Compare-UserProperties function isn't dependent on where any users are, it simply pulls the current dn of the user and moves them to where they should be based on users.csv
    
    # $CurrentYear = (Get-Date).Year
    # Test-OrganizationalUnit -Name $CurrentYear -Path $($UserInfo.ActiveDirectory.DisabledObjectOrg) -Description "$CurrentYear Disabled Accounts Organizational Unit"
    # $Users | Move-ADObject -TargetPath "OU=CurrentYear,OU=Disabled Accounts,DC=student,DC=com"
}

<#
.SYNOPSIS
Checks existence of organizational unit specified.

.DESCRIPTION
Checks to see if an organizational unit exists, if it doesn't create it.

.PARAMETER Name
Name of the Organizational Unit.

.PARAMETER Path
Root path of where the Organizational Unit should be created.

.PARAMETER Description
Description for the Organizational Unit.

.EXAMPLE
Test-OrganizationalUnit -Name "Test" -Path "OU=Org,DC=domain,DC=com"

.NOTES
WIP
#>
function Test-OrganiztionalUnit {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Name,

        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Description
    )

    $OUPath = "OU=$Name,$Path"

    try {
        Get-ADOrganizationalUnit -Identity $OUPath | Out-Null
        "LOG : $OUPath already exists."
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        "LOG : Creating $OUPath."
        New-ADOrganizationalUnit -Name $Name -Path $Path -Description $Description -WhatIf:$WhatIfPreference
    }
}

<#
.SYNOPSIS
Starts the GCDS Sync

.PARAMETER config
Path to the GCDS Config file

.PARAMETER gcdsInstallationDir
Parameter description

.EXAMPLE
An example

.NOTES
Script was found here (https://cloud.google.com/architecture/identity/federating-gcp-with-active-directory-synchronizing-user-accounts#scheduling)
WIP
#>
function Start-GoogleCloudSync {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$config,

        [Parameter(Mandatory = $True, Position = 1)]
        [string]$gcdsInstallationDir
    )

    Import-Module ActiveDirectory

    # Stop on error.
    $ErrorActionPreference = "Stop"

    # Ensure it's an absolute path.
    $rawConfigPath = [System.IO.Path]::Combine((Get-Location).Path, $config)

    # Discover closest GC in current domain.
    $dc = Get-ADDomainController -discover -Service "GlobalCatalog" -NextClosestSite
    Write-Host ("Using Global Catalog server {0} of domain {1} as LDAP source" -f [string]$dc.HostName, $dc.Domain)

    # Load XML and replace the endpoint.
    $dom = [xml](Get-Content $rawConfigPath)
    $ldapConfigNode = $dom.SelectSingleNode("//plugin[@class='com.google.usersyncapp.plugin.ldap.LDAPPlugin']/config")

    # Tweak the endpoint.
    $ldapConfigNode.hostname = [string]$dc.HostName
    $ldapConfigNode.ldapCredMachineName = [string]$dc.HostName
    $ldapConfigNode.port = "3268"   # Always use Global Catalog port

    # Tweak the tsv files location
    $googleConfigNode = $dom.SelectSingleNode("//plugin[@class='com.google.usersyncapp.plugin.google.GooglePlugin']/config")
    $googleConfigNode.nonAddressPrimaryKeyMapFile = [System.IO.Path]::Combine((Get-Location).Path, "nonAddressPrimaryKeyFile.tsv")
    $googleConfigNode.passwordTimestampFile = [System.IO.Path]::Combine((Get-Location).Path, "passwordTimestampCache.tsv")

    # Save resulting config.
    $targetConfigPath = $rawConfigPath + ".autodiscover"

    $writer = New-Object System.IO.StreamWriter($targetConfigPath, $False, (New-Object System.Text.UTF8Encoding($False)))
    $dom.Save($writer)
    $writer.Close()

    $GCDSplat = @{
        FilePath     = "$gcdsInstallationDir\sync-cmd"
        ArgumentList = -ArgumentList "--apply --loglevel INFO --config ""$targetConfigPath"""
        Wait         = $True
    }

    # Start provisioning.
    Start-Process @GCDSplat
}

<#
.SYNOPSIS
Iterates over nested objects and properties to compare their values and also support compact output.

.NOTES
This beauty of a function was found at the link below. All credit goes to the author.
The Compact parameter is truly a blessing.

https://powershellone.wordpress.com/2021/03/16/extending-powershells-compare-object-to-handle-custom-classes-and-arrays/
#>
function Compare-ObjectData($ReferenceObject, $DifferenceObject, $MaxDepth = -1, $__Property, $__Depth = 0, [switch]$IncludeEqual, [switch]$ExcludeDifferent, [switch]$PassThru, [switch]$Compact) {
    if ($MaxDepth -eq -1 -or $__Depth -le $MaxDepth) {
        #check for arrays of PSCustomObjects or arrays of custom class and iterate over those
        if (($ReferenceObject -is [array]) -and ($ReferenceObject[0] -is [PSCustomObject] -or $null -eq $ReferenceObject[0].GetType().Namespace)) {
            $__Depth++
            for ($i = 0; $i -lt $ReferenceObject.Count; $i++) {
                #recurse carrying the current Property name + index and Depth values forward
                Compare-ObjectData $ReferenceObject[$i] $DifferenceObject[$i] -__Property ($__Property + "[$i]") -__Depth $__Depth -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru -Compact:$Compact
            }
        }
        #check for custom classes or PSCutomObjects and iterate over their properties.
        elseif ($ReferenceObject -is [PSCustomObject] -or $null -eq $ReferenceObject.GetType().Namespace) {
            $__Depth++
            foreach ($prop in $ReferenceObject.PSObject.properties.name) {
                #build up the property name hiarachry
                $newProp = $prop
                if ($__Property) {
                    $newProp = $__Property + '.' + $prop
                }
                # handle ref. or diff. objects equal null
                $refValue = $ReferenceObject.$prop
                $diffValue = $DifferenceObject.$prop
                if ($Null -eq $refValue) {
                    $refValue = ''
                }
                if ($null -eq $diffValue) {
                    $diffValue = ''
                }
                #recurse carrying the current Property and Depth values forward
                Compare-ObjectData $refValue $diffValue  -__Property $newProp -__Depth $__Depth -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru -Compact:$Compact
            }
        }
        else {
            #if we reach here we are dealing with a scalar or array of scalars that the built-in cmdlet can already deal with
            $output = Compare-Object $ReferenceObject $DifferenceObject -IncludeEqual:$IncludeEqual -ExcludeDifferent:$ExcludeDifferent -PassThru:$PassThru |
            Select-Object @{n = 'Property'; e = { $__Property } }, @{n = 'Value'; e = { $_.InputObject } }, SideIndicator
            if ($Compact) {
                $output | Group-Object Property, { $_.SideIndicator -eq '==' } | ForEach-Object {
                    if ($_.Group[0].SideIndicator -eq '==') {
                        [PSCustomObject][Ordered]@{
                            Property        = $_.Group.Property
                            ReferenceValue  = $_.Group.Value
                            DifferenceValue = $_.Group.Value
                        }
                    }
                    else {
                        [PSCustomObject][Ordered]@{
                            Property        = $_.Group[0].Property
                            ReferenceValue  = ($_.Group.where{ $_.SideIndicator -eq '<=' }).Value
                            DifferenceValue = ($_.Group.where{ $_.SideIndicator -eq '=>' }).Value
                        }
                    }
                }
            }
            else {
                $output
            }
        }
    }
}

<#
.SYNOPSIS
Accepts user data and compares against Active Directory data

.DESCRIPTION
This function accepts user data (reference) and Active Directory user data (difference) and
builds objects for comparison.

.PARAMETER UserData
Defined user data passed in.

.PARAMETER DifferenceData
Active Directory data passed in.

.EXAMPLE
Compare-UserProperties -UserData $UserData -DifferenceData $UPNUser

.NOTES

#>
function Compare-UserProperties {
    param (
        [Parameter()]
        [hashtable]
        $UserData,

        [Parameter()]
        [Microsoft.ActiveDirectory.Management.ADAccount]
        $DifferenceData
    )
    
    # create blank objects
    $ReferenceObject = [PSCustomObject]@{}
    $DifferenceObject = [PSCustomObject]@{}

    # populate blank objects with defined data
    $UserInfo.ActiveDirectory.UserProperties | ForEach-Object {
        $ReferenceObject | Add-Member -Name $PSItem -MemberType NoteProperty -Value $UserData.$PSItem
        $DifferenceObject | Add-Member -Name $PSItem -MemberType NoteProperty -Value $DifferenceData.$PSItem
    }

    $Compare = (Compare-ObjectData -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -Compact)

    # check if user is in wrong org unit
    $UserDataDistinguishedName = ($DifferenceData.DistinguishedName -replace '^.+?(?<!\\),', '')
    if ($UserData.Path -ne $UserDataDistinguishedName) {
        "LOG : Difference in [DistinguishedName]. Modifying [$UserDataDistinguishedName] to [$($UserData.Path)]"
        $DifferenceData | Move-ADObject -TargetPath $UserData.Path -Server $Server -Credential $Credential -WhatIf:$WhatIfPreference
    }

    # if one or more fields are different, modify them
    if ($Compare) {
        $Compare | ForEach-Object {
            "LOG : Difference in [$($PSItem.Property)]. Modifying [$($PSItem.DifferenceValue)] to [$($PSItem.ReferenceValue)]"

            $SetADUserSplat = @{
                $PSItem.Property = $PSItem.ReferenceValue
            }

            $DifferenceData | Set-ADUser @SetADUserSplat -Server $Server -Credential $Credential -WhatIf:$WhatIfPreference
        }
    }
    # if no fields are different, log no changes
    else {
        "LOG : All AD user properties for [$($UserData.DisplayName)] are up to date"
    }
}

<#
.SYNOPSIS
Starts AAD Sync

.DESCRIPTION
Starts AAD Sync

.EXAMPLE
Start-AADConnectDeltaSync

.NOTES
WIP
#>
function Start-AADConnectDeltaSync {
    param ()
    "LOG : Starting delta sync..."
    $sync = Invoke-Command -ComputerName $UserInfo.ActiveDirectory.AADSyncServer -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta } -Credential (Get-Credential)
    if ($sync.Result -eq "Success") {
        "LOG : AD Sync successful"
    }
    else {
        "LOG : AD Sync failed"
    }
}

<#
.SYNOPSIS
Accepts user data and finds users in Active Directory.

.DESCRIPTION
Uses user data to find Active Directory users based on employeeID or UPN. Creates the user if both do not match.

.PARAMETER UserData
Hashtable of user data defined from the import file.

.EXAMPLE
Test-ValidUser -UserData $UserData

.NOTES

#>
function Test-ValidUser {
    [CmdletBinding()]
    param (
        [Parameter()]
        [hashtable]
        $UserData
    )

    # targeted properties
    $ADUserProperties = @{
        Properties = ($UserInfo.ActiveDirectory.UserProperties)
    }

    # check if a user has a direct ID match (direct verification of identity)
    if ($IDUser = Get-ADUser -LDAPFilter "(EmployeeID=$($UserData.EmployeeId))" @ADUserProperties -Server $Server) {
        "LOG : ID match [$($IDUser.EmployeeID)] found to user [$($IDUser.DisplayName)]."
        Compare-UserProperties -UserData $UserData -DifferenceData $IDUser
    }
    # elseif (no direct match) match by UPN
    elseif ($UPNUser = Get-ADUser -LDAPFilter "(UserPrincipalName=$($UserData.UserPrincipalName))" @ADUserProperties -Server $Server) {
        "LOG : UPN match [$($UPNUser.UserPrincipalName)] found."
        Compare-UserProperties -UserData $UserData -DifferenceData $UPNUser
    }
    # else (no direct match) match by UPN
    else {
        "LOG : No users match, creating user [$($UserData.DisplayName)] with Id [$($UserData.EmployeeId)]"
        $UserData
        "LOG : Creating user in AD"
        New-ADUser @UserData -WhatIf:$WhatIfPreference
    }
}

<#
Check if log folder exists, if not create it
Define the path of users to import (source)
Import the source users
Import the configuration data
#>
if (-not (Test-Path -Path "$PSScriptRoot\log")) {
    New-Item -Path $PSScriptRoot -Name "log" -ItemType Directory | Out-Null
}

$UserDataPath = "$PSScriptRoot\import\users.csv"
$UserDataCSVImport = Import-Csv -Path $UserDataPath | Sort-Object Course, Last
$Script:UserInfo = Get-Content "$PSScriptRoot\config\config.json" | ConvertFrom-Json

$Server = $UserInfo.ActiveDirectory.Server
$Credential = (Get-Credential)

$UserDataCSVImport | ForEach-Object {
    # csv columns
    $BuildingTitleCase = (Get-Culture).TextInfo.ToTitleCase($PSItem.School).Split('-')[0].trim()
    $UserLocalID = $PSItem.'Id Number'
    $LastNameTitleCase = $PSItem.'Last Name'
    $FirstNameTitleCase = $PSItem.'First Name'
    $CourseTitleCase = (Get-Culture).TextInfo.ToTitleCase($PSItem.'Course Name')
    $EmailAddress = $PSItem.'Student Email Address'

    # calculate config values
    $UserTitle = $UserInfo.Static.Title
    $UserCompany = $UserInfo.Static.Company
    $UserState = $UserInfo.Static.State
    $UserCountry = $UserInfo.Static.Country

    switch ($BuildingTitleCase) {
        $PSItem {
            Write-Verbose -Message "User located in $PSItem"
            $UserCity = "$($UserInfo.Buildings.$PSItem.City)"
            $UserAddress = "$($UserInfo.Buildings.$PSItem.Address)"
            $UserZip = "$($UserInfo.Buildings.$PSItem.Zip)"
            $Description = "$($UserInfo.Descriptions.$PSItem.$CourseTitleCase)"
            $Path = "OU=$Description,OU=$PSItem,$($UserInfo.ActiveDirectory.UserOrgRoot)"
        }
        Default { "LOG : Building for [$FullUserName] does not match config file." }
    }

    # calculate default password
    $UserPassword = $UserInfo.Static.DefaultPasswordPrefix + $UserLocalID

    # calculate full user name
    $FullUserName = '{0} {1}' -f $FirstNameTitleCase, $LastNameTitleCase

    # calculate email address; verify address matches approved emails
    $Username = $EmailAddress.Split("@")[0]
    
    if ($EmailAddress -notmatch $UserInfo.Static.EmailDomain) {
        "LOG : Email address for [$FullUserName] ($EmailAddress) does not match company standard [$($UserInfo.Static.EmailDomain)]. This issue can be resolved by updating the student record in the SIS."
        return
    }
    
    Write-Verbose -Message "Modified CSV data
    Campus = $BuildingTitleCase
    User ID = $UserLocalID
    Full Name = $FullUserName
    First Name = $FirstNameTitleCase
    Last Name = $LastNameTitleCase
    Course = $CourseTitleCase
    Password = $UserPassword
    Username = $Username
    "

    # define correct user data
    $NewUserParams = @{
        'Name'                 = '{0} {1}' -f $FirstNameTitleCase, $LastNameTitleCase
        'GivenName'            = $FirstNameTitleCase
        'Surname'              = $LastNameTitleCase
        'DisplayName'          = $FullUserName
        'EmailAddress'         = $EmailAddress
        'SamAccountName'       = $Username
        'UserPrincipalName'    = $EmailAddress
        'AccountPassword'      = (ConvertTo-SecureString $UserPassword -AsPlainText -Force)
        'City'                 = $UserCity
        'Company'              = $UserCompany
        'Description'          = $Description
        'Office'               = $BuildingTitleCase
        'StreetAddress'        = $UserAddress
        'State'                = $UserState
        'PostalCode'           = $UserZip
        'Country'              = $UserCountry
        'PasswordNeverExpires' = $true
        'CannotChangePassword' = $true
        'EmployeeID'           = $UserLocalID
        'Title'                = $UserTitle
        'Enabled'              = $true
        'Path'                 = $Path
        'Server'               = $Server
        'Credential'           = $Credential
    }

    # Verify this user against Active Directory, modify any incorrect data from existing accounts
    Test-ValidUser -UserData $NewUserParams

    # Run GCDS sync
    # Call password reset function
}