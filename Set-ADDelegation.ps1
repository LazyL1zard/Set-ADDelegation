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
          $ObjectType,
  
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
      }
      Process
      {
          Write-Verbose "Setting Location to AD:"
          $CurentLocation = Get-Location
          Set-Location AD:
  
          Write-Verbose "Retreving Root of a Directory Server information tree"
          $Rootdse = Get-ADRootDSE
  
  
          Write-Verbose "Retreving OU Object"
          try {
              $OU = Get-ADOrganizationalUnit -Identity $OUPath
          }
          catch {
              $message = $Error[0]
              Write-Host "Unable to find Organizational Unit with Path:" -ForegroundColor Red -NoNewline
              Write-Host $OUPath -ForegroundColor DarkYellow
              Write-Host $message
              Set-Location $CurentLocation
              exit 1
          }
  
          Write-Verbose "Retreving ADGroup Object"
          try {
              $ADGroupSID = (Get-ADGroup -Identity $ADGroup).SID
          }
          catch {
              $message = $Error[0]
              Write-Host "Unable to find ADGroup with name:" -ForegroundColor Red -NoNewline
              Write-Host $ADGroup -ForegroundColor DarkYellow
              Write-Host $message
              Set-Location $CurentLocation
              exit 1
          }
          
  
          Write-Verbose "Retreving GUID value of each schema class and attribute"
          $GUIDMap = @{}
          Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID |
          ForEach-Object {$GUIDMap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}
  
          Write-Verbose "Retreving GUID value for each extended permission right the is included in the forest"
          $ExtendedRightsMap = @{}
          Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid |
          ForEach-Object {$ExtendedRightsMap[$_.displayName]=[System.GUID]$_.rightsGuid}
  
          $AllAces = New-Object System.Collections.Generic.List[System.Object]
  
          $ACL = get-acl $OU
  
          switch ($ObjectType) {
              'User' {
                  $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$guidmap["user"]
                  $AllAces.Add($ACE)
  
                  $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$guidmap["lockoutTime"],"Descendents",$guidmap["user"]
                  $AllAces.Add($ACE)
  
                  $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$guidmap["user"]
                  $AllAces.Add($ACE)
  
                  $ACE = new-object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"CreateChild","Allow",$guidmap["user"]
                  $AllAces.Add($ACE)
  
                  $ACE = new-object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"DeleteChild","Allow",$guidmap["user"]
                  $AllAces.Add($ACE)
  
                  $UserWriteProperties = @("company","department","description",
                                "displayName","facsimileTelephoneNumber",
                                "otherFacsimileTelephoneNumber","givenName",
                                "homeDrive","homeDirectory","homePhone",
                                "otherHomePhone","initials","title",
                                "userPrincipalName","sAMAccountName","manager",
                                "mobile","otherMobile","cn","name","info",
                                "otherTelephone","postOfficeBox","pwdLastSet",
                                "streetAddress","telephoneNumber","thumbnailPhoto",
                                "wWWHomePage","postalCode","sn","st","c","l",
                                "physicalDeliveryOfficeName","userAccountControl",
                                "extensionAttribute2","userWorkstations","logonHours")
  
                  foreach ($UserWriteProperty in $UserWriteProperties){
                      $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$guidmap["$UserWriteProperty"],"Descendents",$guidmap["user"]
                      $AllAces.Add($Ace)
                  }
              }
              'Computer'{
                  $ServerMainProperties = @("CreateChild","DeleteChild")
          
                  foreach ($ServerMainProperty in $ServerMainProperties){
                      $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$ServerMainProperty,"Allow",$guidmap["computer"]
                      $AllAces.Add($Ace)
                  }
  
                  $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]
                  $AllAces.Add($Ace)
  
                  $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]
                  $AllAces.Add($Ace)
  
                  $ServerExtendedProperties = @("Reset Password","Account Restrictions",
                                          "Validated write to DNS host name",
                                          "Validated write to service principal name")
          
                  foreach ($ServerExtendedProperty in $ServerExtendedProperties){                                                                                            
                      $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ExtendedRight","Allow",$extendedrightsmap["$ServerExtendedProperty"],"Descendents",$guidmap["computer"]
                      $AllAces.Add($Ace)
                  }
              }
              'Group'{
                  $GroupMainProperties = @("CreateChild","DeleteChild")
                  foreach ($GroupMainProperty in $GroupMainProperties){
                          $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,$GroupMainProperty,"Allow",$guidmap["group"]
                          $AllAces.Add($Ace)
                  }
  
                  $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"ReadProperty","Allow","Descendents",$guidmap["group"]
                  $AllAces.Add($Ace)
  
                  $GroupWriteProperties = @("description","sAMAccountName","groupType",
                                            "member","cn","name","info")
  
                  foreach ($GroupWriteProperty in $GroupWriteProperties){
                          $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ADGroupSID,"WriteProperty","Allow",$guidmap["$GroupWriteProperty"],"Descendents",$guidmap["group"]
                          $AllAces.Add($Ace)
                  }
              }
          }
  
  
          ForEach ($Ace in $AllAces){
              $ACL.AddAccessRule($Ace)
          }
  
          try {
              set-acl -aclobject $ACL -Path $OUPath
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