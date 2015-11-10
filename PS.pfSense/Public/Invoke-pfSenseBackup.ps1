function Invoke-pfSenseBackup
{
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
    [CmdletBinding(SupportsShouldProcess=$false, 
                  PositionalBinding=$true,
                  ConfirmImpact='Medium')]
    [Alias("ipfb")]
    [OutputType([xml])]
    Param
    (
        # Specifies the URI(s) of the pfSense instance(s).
        [Parameter(Mandatory=$true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0)]
        [Alias("Hostname","Node","Instance")]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Uri[]]
        $Uri,

        # The crednentials used to access the pfSense instance.
        [Parameter(Mandatory=$true,
                   Position=1)]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        # If speicifed RRD graphs will be backed up.
        [Parameter(Mandatory=$false,
                  Position=2)]
        [ValidateNotNull()]
        [Switch]
        $BackupRRD,

        # If specified invalid SSL cerificated will be ignored.
        [Parameter(Mandatory=$false,
                   Position=3)]
        [ValidateNotNull()]
        [Switch]
        $DisableSSLValidation
    )

    Begin
    {
        $currentCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy
        $currentExpect100Continue = [System.Net.ServicePointManager]::Expect100Continue
        [System.Net.ServicePointManager]::Expect100Continue = $false
        if($DisableSSLValidation)
        {
            Disable-SSLValidation
            Write-Verbose "SSL validation has been disabled."
        }
        $webCredential = @{login='Login';usernamefld=$Credential.GetNetworkCredential().UserName;passwordfld=$Credential.GetNetworkCredential().Password}
        if($BackupRRD)
        {
            $pfBackupArgs = @{Submit='download&donotbackuprrd=no'}
            Write-Verbose "The RRD graphs will backed up."
        }
        else
        {
            $pfBackupArgs = @{Submit='download';donotbackuprrd='yes'}
            Write-Verbose "The RRD graphs will not be backed up."
        }
    }
    Process
    {
        $Uri.Host | ForEach-Object -Process {
            Invoke-WebRequest -Uri "https://$_/diag_backup.php" -Method POST -Body $webCredential -SessionVariable pfWebSession | Out-Null
            Invoke-WebRequest -WebSession $pfWebSession -Uri "https://$_/diag_backup.php" -Method POST -Body $pfBackupArgs -OutFile "$_-$(Get-Date -Format yyyy-mm-dd_HH.MM.ss).xml"
        }
    }
    End
    {
        [System.Net.ServicePointManager]::CertificatePolicy = $currentCertPolicy
        Write-Verbose "Certificate Policy reset to previous setting."
        [System.Net.ServicePointManager]::Expect100Continue = $currentExpect100Continue
        Write-Verbose "Expect100Continue reset to previous setting."
        Write-Verbose "End of cmdlet."
    }
}