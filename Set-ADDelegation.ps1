function Set-ADDelegation {
    <#
    .Synopsis
    Set ACL on Active Directory Organizational Unit delegation
    .DESCRIPTION
    Sets the basic ACL to delegate Active Directory rights on User, computer and group objects.
    .SYNTAX
    Set-ADDelegation [[-ObjectClass] <ValidateSet[]>] [-ADGroup <string>] [-OUPath <string>]
    .EXAMPLE
    Set-ADDelegation -ObjectClass User -ADGroup DS_DEMO_OU_T2_USR -OUPath 'OU=Redirected Users,DC=infra,DC=demo'
    .EXAMPLE
    Set-ADDelegation -ObjectClass Computer -ADGroup DS_DEMO_OU_T2_COMP -OUPath 'OU=Redirected Computers,DC=infra,DC=demo'
    .PARAMETER
    ObjectClass 
    ValidateSet parameter
    Defines which Active Directory objectclass you want to delegate
    .PARAMETER
    ADGroup
    string
    The Active Directory group name you want the delegation to be applied
    .PARAMETER
    OUPath
    string
    The Organizational Unit DistinguidhedName you want the ACL to be applied to.
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


        Write-Verbose "Retriving ACLs from Organisation Unit : $($OU.DistinguishedName)"
        try {
            $ACL = get-acl $OU
        }
        catch {
            Write-Verbose "Unable to retrive ACLs from OU: $($OU.DistinguishedName) "
            $Check = 1
            return
        }
        

        Write-Verbose "Creating ACE Collection"
        $AllAces = New-Object System.Collections.Generic.List[System.Object]
    }


    Process
    {
        Write-Verbose 'Checking prerequisits'
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

                $UserMainProperties = @('CreateChild','DeleteChild')

                foreach ($UserMainProperty in $UserMainProperties) {

                    $ACE = new-object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$UserMainProperty,"Allow",$GUIDMap["user"]
                    $AllAces.Add($ACE)
                }

                $UserWriteProperties = @("company","department","description",
                            "displayName","givenName","homeDrive","homeDirectory","homePhone",
                            "initials","title","userPrincipalName","sAMAccountName","manager","cn","name",
                            "pwdLastSet","streetAddress","postalCode","sn","userAccountControl")
                            

                foreach ($UserWriteProperty in $UserWriteProperties){
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$GUIDMap["$($UserWriteProperty)"],"Descendents",$GUIDMap["user"]
                    $AllAces.Add($Ace)
                }


                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$GUIDMap["lockoutTime"],"Descendents",$GUIDMap["user"]
                $AllAces.Add($ACE)

                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$GUIDMap["user"]
                $AllAces.Add($ACE)

            }
            'Computer'{

                $ServerMainProperties = @("CreateChild","DeleteChild")
        
                foreach ($ServerMainProperty in $ServerMainProperties){

                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$ServerMainProperty,"Allow",$GUIDMap["computer"]
                    $AllAces.Add($Ace)
                }


                $ServerExtendedProperties = @("Reset Password","Account Restrictions",
                                        "Validated write to DNS host name",
                                        "Validated write to service principal name")
        
                foreach ($ServerExtendedProperty in $ServerExtendedProperties){    

                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ExtendedRight","Allow",$extendedrightsmap["$ServerExtendedProperty"],"Descendents",$GUIDMap["computer"]
                    $AllAces.Add($Ace)
                }


                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$GUIDMap["computer"]
                $AllAces.Add($Ace)


                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow","Descendents",$GUIDMap["computer"]
                $AllAces.Add($Ace)

                
            }
            'Group'{

                $GroupMainProperties = @("CreateChild","DeleteChild")

                foreach ($GroupMainProperty in $GroupMainProperties){

                        $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$GroupMainProperty,"Allow",$GUIDMap["group"]
                        $AllAces.Add($Ace)
                }


                $GroupWriteProperties = @("description","sAMAccountName","groupType",
                                        "member","cn","name","info")

                foreach ($GroupWriteProperty in $GroupWriteProperties){

                        $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$GUIDMap["$GroupWriteProperty"],"Descendents",$GUIDMap["group"]
                        $AllAces.Add($Ace)
                }


                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$GUIDMap["group"]
                $AllAces.Add($Ace)
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
            $Error[0]
        }
    }
    End
    {
        Set-Location $CurentLocation
        Write-Verbose "FUNCTION -- Set-ADDelegation -- END"
    }
}