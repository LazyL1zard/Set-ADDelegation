function Set-ADDelegation {
    <#
    .Synopsis
    Short description
    .DESCRIPTION
    Long description
    .EXAMPLE
    Example of how to use this cmdlet
    .EXAMPLE
    Another example of how to use this cmdlet
    .INPUTS
    Inputs to this cmdlet (if any)
    .OUTPUTS
    Output from this cmdlet (if any)
    .NOTES
    General notes
    .COMPONENT
    The component this cmdlet belongs to
    .ROLE
    The role this cmdlet belongs to
    .FUNCTIONALITY
    The functionality that best describes this cmdlet
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory, 
                    Position=0)]
        [ValidateSet("User", "Computer", "Group")]
        $ObjectClass,

        # Param2 help description
        [Parameter(Mandatory, 
        Position=1)]
        [string]
        $ADGroup,

        # Param3 help description
        [Parameter(Mandatory, 
        Position=2)]
        [string]
        $OUPath
    )

    Begin
    {
        Write-Verbose "FUNCTION -- Set-ADDelegation -- START"


        Write-Verbose "Initialising Check variable"
        $Check = 0


        Write-Verbose "Indexing prompt location"
        $CurentLocation = Get-Location


        Write-Verbose "Retreving Root of a Directory Server information tree"
        try {
            $Rootdse = Get-ADRootDSE
        }
        catch {
            Write-Verbose "Unable to get Directory Server information tree"
            $Check = 1
            return
        }


        try {
            $OU = Get-ADOrganizationalUnit -Identity $OUPath
        }
        catch {
            Write-Verbose "Unable to find Organizational Unit : $($OUPath)"
            $Check = 1
            return
        }


        try {
            Write-Verbose "Retreving ADGroup Object"
        $ADGroupSID = (Get-ADGroup -Identity $ADGroup).SID
        }
        catch {
            Write-Verbose "Unable to find ADGroup : $($ADGroup)"
            $Check = 1
            return
        }


        Write-Verbose "Setting Location to AD:"
        try {
            Set-Location AD: 
        }
        catch {
            Write-Verbose "Unable to set location to AD"
            $Check = 1
            return
        }
        

        Write-Verbose "Creating ACE Collection"
        $AllAces = New-Object System.Collections.Generic.List[System.Object]


        Write-Verbose "Retriving ACL from Organisation Unit : $($OU.DistinguishedName)"
        $ACL = get-acl $OU

    }
    Process
    {      
        if ($Check -eq 1) {
            return
        }

        Write-Verbose "Retreving GUID value of each schema class and attribute"
        $GUIDMap = @{}
        Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID |
            ForEach-Object {
                $GUIDMap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID
            }


        Write-Verbose "Retreving GUID value for each extended permission right the is included in the forest"
        $ExtendedRightsMap = @{}
        Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid |
            ForEach-Object {
                $ExtendedRightsMap[$_.displayName]=[System.GUID]$_.rightsGuid
            }


        switch ($ObjectClass) {
            'User' {
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$GUIDMap["lockoutTime"],"Descendents",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $ACE = new-object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"CreateChild","Allow",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $ACE = new-object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"DeleteChild","Allow",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $UserWriteProperties = @("company","department","description",
                            "displayName","givenName","homeDrive","homeDirectory","homePhone",
                            "initials","title","userPrincipalName","sAMAccountName","manager","cn","name",
                            "pwdLastSet","streetAddress","postalCode","sn","userAccountControl")

                foreach ($UserWriteProperty in $UserWriteProperties){
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$GUIDMap["$UserWriteProperty"],"Descendents",$GUIDMap["user"]
                    $AllAces.Add($Ace)
                }
            }
            'Computer'{
                $ServerMainProperties = @("CreateChild","DeleteChild")
                
        
                foreach ($ServerMainProperty in $ServerMainProperties){
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$ServerMainProperty,"Allow",$GUIDMap["computer"]
                    $AllAces.Add($Ace)
                }



                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$GUIDMap["computer"]
                $AllAces.Add($Ace)

                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow","Descendents",$GUIDMap["computer"]
                $AllAces.Add($Ace)

                $ServerExtendedProperties = @("Reset Password","Account Restrictions",
                                        "Validated write to DNS host name",
                                        "Validated write to service principal name")
        
                foreach ($ServerExtendedProperty in $ServerExtendedProperties){                                                                                            
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ExtendedRight","Allow",$extendedrightsmap["$ServerExtendedProperty"],"Descendents",$GUIDMap["computer"]
                    $AllAces.Add($Ace)
                }
            }
            'Group'{
                $GroupMainProperties = @("CreateChild","DeleteChild")
                foreach ($GroupMainProperty in $GroupMainProperties){
                        $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$GroupMainProperty,"Allow",$GUIDMap["group"]
                        $AllAces.Add($Ace)
                }

                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$GUIDMap["group"]
                $AllAces.Add($Ace)

                $GroupWriteProperties = @("description","sAMAccountName","groupType",
                                        "member","cn","name","info")

                foreach ($GroupWriteProperty in $GroupWriteProperties){
                        $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$GUIDMap["$GroupWriteProperty"],"Descendents",$GUIDMap["group"]
                        $AllAces.Add($Ace)
                }
            }
        }


        ForEach ($Ace in $AllAces){
            $ACL.AddAccessRule($Ace)
        }

        try {
            if ($PSCmdlet.ShouldProcess("$($OUPath)", "Set-Acl")) {
                Set-Acl -AclObject $ACL -Path $OUPath
            }
            
        }
        catch {
            Write-Host $Error[0] -ForegroundColor Red
        }
    }
    End
    {
        Set-Location $CurentLocation
        Write-Verbose "FUNCTION -- Set-ADDelegation -- END"
    }
}