# ============================================
# Get Certificate Template Permissions (FIXED)
# Uses Get-Acl against AD path
# ============================================
 
$TemplateName = "__UH__Web Server__SAN__4096__Client__Server"
$SearchBase   = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=uhhs,DC=com"
 
# Get template object (use displayName for lookup)
$Template = Get-ADObject `
    -LDAPFilter "(displayName=$TemplateName)" `
    -SearchBase $SearchBase `
    -Properties distinguishedName, displayName, cn
 
if (-not $Template) {
    Write-Error "Template not found: $TemplateName"
    return
}
 
# Build AD path
$ADPath = "AD:\$($Template.DistinguishedName)"
 
# Get ACL properly
$ACL = Get-Acl -Path $ADPath
 
# Output permissions
$ACL.Access | ForEach-Object {
    [PSCustomObject]@{
        Identity        = $_.IdentityReference
        Rights          = $_.ActiveDirectoryRights
        AccessType      = $_.AccessControlType
        Inherited       = $_.IsInherited
        ObjectType      = $_.ObjectType
        InheritanceType = $_.InheritanceType
    }
} | Sort-Object Identity | Format-Table -AutoSize