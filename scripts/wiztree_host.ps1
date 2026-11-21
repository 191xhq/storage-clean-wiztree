param([Parameter(Mandatory=$true)][string]$Request)
# Read-only Windows host bridge. The only elevated executable is verified WizTree.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
# PowerShell 7 can leave its module path in a child Windows PowerShell 5.1.
# Load the Windows inbox security module explicitly, without changing machine config.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$req = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Request)) | ConvertFrom-Json
$warnings = [Collections.Generic.List[string]]::new()
function Is-Admin {
    return [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Inspect-WizTree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    try {
        $item = Get-Item -LiteralPath $Path
        if ($item.Name -notmatch '^(?i)WizTree(64)?\.exe$') { return }
        $v = $item.VersionInfo
        $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(?i)Antibody Software' -or
            $v.ProductName -notmatch '(?i)WizTree' -or $v.CompanyName -notmatch '(?i)Antibody' -or
            $v.FileMajorPart -lt 3 -or ($v.FileMajorPart -eq 3 -and $v.FileMinorPart -lt 18)) {
            $warnings.Add("Skipped unverified/unsupported executable: $Path (signature=$($sig.Status))")
            return
        }
        [pscustomobject]@{path=$item.FullName; version=('{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart); is64=($item.Name -ieq 'WizTree64.exe'); signature='Valid'; publisher=$sig.SignerCertificate.Subject}
    } catch { $warnings.Add("Executable inspection failed: $Path : $($_.Exception.Message)") }
}
function Discover-WizTree {
    $candidates = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    function Add-Candidate([string]$value) {
        if (-not $value) { return }
        $value = [Environment]::ExpandEnvironmentVariables($value.Trim('"'))
        if ($value -match '(?i)\.exe$') {
            [void]$candidates.Add($value)
            $value = Split-Path -Parent $value
        }
        foreach ($exe in @('WizTree64.exe','WizTree.exe')) { [void]$candidates.Add((Join-Path $value $exe)) }
    }
    foreach ($p in ($env:PATH -split ';')) { if ($p.Trim()) { Add-Candidate $p } }
    foreach ($hive in @('HKLM:','HKCU:')) {
        foreach ($branch in @('SOFTWARE','SOFTWARE\WOW6432Node')) {
            foreach ($exe in @('WizTree64.exe','WizTree.exe')) {
                $key = "$hive\$branch\Microsoft\Windows\CurrentVersion\App Paths\$exe"
                if (Test-Path -LiteralPath $key) { Add-Candidate (Get-Item -LiteralPath $key).GetValue('') }
            }
            $key = "$hive\$branch\Microsoft\Windows\CurrentVersion\Uninstall"
            if (Test-Path -LiteralPath $key) {
                foreach ($subkey in (Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
                    $entry = Get-ItemProperty -LiteralPath $subkey.PSPath -ErrorAction SilentlyContinue
                    if ($entry.DisplayName -match '(?i)WizTree') {
                        Add-Candidate $entry.InstallLocation
                        if ($entry.DisplayIcon) { Add-Candidate ($entry.DisplayIcon -replace ',\s*-?\d+$','') }
                    }
                }
            }
        }
    }
    $bases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:LOCALAPPDATA,
        "$env:LOCALAPPDATA\Programs", "$env:USERPROFILE\scoop\apps\wiztree\current", 'C:\Tools','D:\Tools','D:\Program Files','D:\Program Files (x86)', 'C:\WizTree', 'D:\WizTree')
    foreach ($base in $bases) {
        if (-not $base) { continue }
        Add-Candidate $base
        foreach ($sub in @('WizTree','WizTree Portable','Antibody Software\WizTree')) { Add-Candidate (Join-Path $base $sub) }
        if (Test-Path -LiteralPath $base -PathType Container) {
            foreach ($dir in (Get-ChildItem -LiteralPath $base -Directory -Filter '*WizTree*' -ErrorAction SilentlyContinue)) {
                if (-not ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Add-Candidate $dir.FullName }
            }
        }
    }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($base in @("$env:USERPROFILE\Desktop","$env:PUBLIC\Desktop", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")) {
        if (Test-Path -LiteralPath $base) {
            foreach ($link in (Get-ChildItem -LiteralPath $base -Filter '*WizTree*.lnk' -Recurse -Depth 4 -ErrorAction SilentlyContinue)) {
                try { Add-Candidate ($shell.CreateShortcut($link.FullName).TargetPath) } catch { $warnings.Add("Shortcut unreadable: $($link.FullName)") }
            }
        }
    }
    $valid = @(foreach ($p in $candidates) { Inspect-WizTree $p })
    return @($valid | Sort-Object @{Expression={$_.is64};Descending=$true}, @{Expression={[version]$_.version};Descending=$true})
}
try {
    $admin = Is-Admin
    if ($req.action -eq 'probe') {
        $found = @(Discover-WizTree)
        $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
            [pscustomobject]@{name=($_.DeviceID+'\');total_bytes=[long]$_.Size;free_bytes=[long]$_.FreeSpace;filesystem=$_.FileSystem;drive_type='fixed'}
        })
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{ok=$true;admin=$admin;wiztree=$found;warnings=@($warnings);system_drive=($env:SystemDrive+'\');home=$env:USERPROFILE;local=$env:LOCALAPPDATA;roaming=$env:APPDATA;temp=$env:TEMP;program_files=$env:ProgramFiles;program_files_x86=${env:ProgramFiles(x86)};os=$os.Caption;build=$os.Version;arch=$os.OSArchitecture;user=$env:USERNAME;disks=$disks} | ConvertTo-Json -Depth 8 -Compress
    } elseif ($req.action -eq 'scan') {
        $exe = Inspect-WizTree $req.exe
        if (-not $exe) { throw 'Executable did not pass signature/version validation; not launched' }
        $target = [string]$req.target
        if ($target -notmatch '^[A-Za-z]:([\\/]|$)') { throw 'Only absolute local drive/folder targets are supported' }
        $driveRoot = [IO.Path]::GetPathRoot($target+'\')
        if ([IO.DriveInfo]::new($driveRoot).DriveType -ne [IO.DriveType]::Fixed) { throw 'Target is not a local fixed disk' }
        $target = [IO.Path]::GetFullPath($target+'\').TrimEnd('\')
        if (-not (Test-Path -LiteralPath ($target+'\') -PathType Container)) { throw 'Target does not exist' }
        $output = [IO.Path]::GetFullPath([string]$req.output)
        if ($output -notmatch '^[A-Za-z]:\\' -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($output)).DriveType -ne [IO.DriveType]::Fixed) { throw 'Export must be on a local fixed disk' }
        if (Test-Path -LiteralPath $output) { throw 'Refusing to overwrite an existing export' }
        # Quote all arguments as Windows argv, never interpolate paths as shell code.
        function Quote-Arg([string]$s) { return '"' + ($s -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1') + '"' }
        $wantAdmin = ($req.admin_mode -ne 'normal')
        $useAdmin = $admin -or $wantAdmin
        $args = @($target, ('/export='+$output), ('/admin='+[int]$useAdmin), '/exportfolders=1', ('/exportfiles='+[int][bool]$req.files), '/sortby=2')
        # /exportmaxdepth is an advanced option; only use with validated modern 4.x.
        if ([version]$exe.version -ge [version]'4.02') { $args += ('/exportmaxdepth='+[int]$req.depth) }
        else { $warnings.Add('WizTree older than 4.02 does not support bounded export depth; folder-only export may be large') }
        $start = @{FilePath=$exe.path; ArgumentList=(($args | ForEach-Object { Quote-Arg $_ }) -join ' '); PassThru=$true; WindowStyle='Hidden'}
        # A 32-bit bootstrap can launch WizTree64 and exit immediately. -Wait tracks
        # descendants on Windows; Python's outer timeout still bounds this operation.
        if (-not $exe.is64 -and [Environment]::Is64BitOperatingSystem) { $start.Wait=$true }
        $uac = 'not_required'
        if ($wantAdmin -and -not $admin) { $start.Verb='RunAs'; $uac='requested' }
        try { $proc = Start-Process @start } catch {
            if ($start.ContainsKey('Verb')) {
                $uac='cancelled_or_failed'
                $warnings.Add("UAC cancelled/failed; retrying once without administrator privileges: $($_.Exception.Message)")
                $start.Remove('Verb')
                $useAdmin=$false
                $args[2]='/admin=0'
                $start.ArgumentList=(($args | ForEach-Object { Quote-Arg $_ }) -join ' ')
                $proc=Start-Process @start
            } else { throw }
        }
        if (-not $proc.WaitForExit([int]$req.timeout * 1000)) { throw 'WizTree scan timed out; export is incomplete and will not be read. The scan process may still be running.' }
        $proc.Refresh()
        $code=$proc.ExitCode
        if ($null -ne $code -and $code -ne 0) { throw "WizTree exited with code $code" }
        if (-not (Test-Path -LiteralPath $output -PathType Leaf) -or (Get-Item -LiteralPath $output).Length -eq 0) { throw 'WizTree did not export a nonempty CSV' }
        # Exclusive open after process exit proves the exporter no longer has the CSV open.
        $stream=[IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        $length=$stream.Length
        $stream.Dispose()
        [pscustomobject]@{ok=$true;admin=$useAdmin;admin_evidence=$(if ($admin) {'inherited_windows_elevated_token'} elseif ($useAdmin) {'successful_standard_RunAs'} else {'normal_mode'});uac=$uac;output=$output;bytes=$length;exit_code=$code;version=$exe.version;warnings=@($warnings)} | ConvertTo-Json -Depth 5 -Compress
    } else { throw 'Unknown bridge action' }
} catch {
    [pscustomobject]@{ok=$false;error=$_.Exception.Message;warnings=@($warnings)} | ConvertTo-Json -Depth 4 -Compress
    exit 1
}
