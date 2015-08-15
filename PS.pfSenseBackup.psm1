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
        switch($BackupRRD)
        {
            $true {$pfBackupArgs = @{Submit='download&donotbackuprrd=no'}; Write-Verbose "The RRD graphs will backed up."}
            $false {$pfBackupArgs = @{Submit='download&donotbackuprrd=yes'}; Write-Verbose "The RRD graphs will not be backed up."}
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

function Disable-SSLValidation
{
<#
.SYNOPSIS
    Disables SSL certificate validation
.DESCRIPTION
    Disable-SSLValidation disables SSL certificate validation by using reflection to implement the System.Net.ICertificatePolicy class.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
.NOTES
    Reflection is ideal in situations when a script executes in an environment in which you cannot call csc.ese to compile source code. If compiling code is an option, then implementing System.Net.ICertificatePolicy in C# and Add-Type is trivial.
.LINK
    http://www.exploit-monday.com
#>

    Set-StrictMode -Version 2

    # You have already run this function
    if ([System.Net.ServicePointManager]::CertificatePolicy.ToString() -eq 'IgnoreCerts') { Return }

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('IgnoreCerts')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('IgnoreCerts', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('IgnoreCerts', 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit', [System.Object], [System.Net.ICertificatePolicy])
    $TypeBuilder.DefineDefaultConstructor('PrivateScope, Public, HideBySig, SpecialName, RTSpecialName') | Out-Null
    $MethodInfo = [System.Net.ICertificatePolicy].GetMethod('CheckValidationResult')
    $MethodBuilder = $TypeBuilder.DefineMethod($MethodInfo.Name, 'PrivateScope, Public, Virtual, HideBySig, VtableLayoutMask', $MethodInfo.CallingConvention, $MethodInfo.ReturnType, ([Type[]] ($MethodInfo.GetParameters() | % {$_.ParameterType})))
    $ILGen = $MethodBuilder.GetILGenerator()
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ldc_I4_1)
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ret)
    $TypeBuilder.CreateType() | Out-Null

    # Disable SSL certificate validation
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object IgnoreCerts
}