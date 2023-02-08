# Empty space
Write-Host

if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{
    # Check if shortcut in Shell:SendTo exists
    $ScriptPath = $MyInvocation.MyCommand.Path
    $ScriptFileNameWoExt = (Get-Item $ScriptPath).BaseName
    $SendToFolder = [Environment]::GetFolderPath("SendTo")

    If ($false -eq (Test-Path "$SendToFolder\$ScriptFileNameWoExt.lnk"))
    {
        # %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "D:\Games\Special K\Do-Symlink.ps1"

        Write-Warning "Could not detect SendTo shortcut!"
        Write-Host
        Write-Host "It is recommended to add a shortcut to this script from the SendTo context menu."
        Write-Host
        Write-Host "This enables access to the script by holding down Shift and right clicking on"
        Write-Host " the desired target executable, expand the Send to menu, and clicking on"
        Write-Host "  $ScriptFileNameWoExt to run the script against that specific executable."
        Write-Host

        $Choice = "y"
        do
        {
            $Choice = Read-Host "Do you want us to add a link? (y/n)"
        } while ($Choice -ne "y" -and $Choice -ne "n")

        If ($Choice -eq "y")
        {
            $WScript = New-Object -ComObject WScript.Shell
            $Shortcut = $WScript.CreateShortcut("$SendToFolder\$ScriptFileNameWoExt.lnk")
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = ('-ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath)
            $Shortcut.Save()

            Write-Host
            Write-Host "Shortcut has been created!"
            Write-Host "Please rerun the script against the desired executable using the SendTo context menu."
            Write-Host

            Exit 0
        }
    }

    # Relaunch PowerShell as an elevated process with the permissions required to modify the AppInit_DLLs registry keys.
    If ($args)
    {
        $Path = $args[0]
        Start-Process powershell.exe "-ExecutionPolicy Bypass -File",('"{0}" "{1}"' -f $ScriptPath, $Path) -Verb RunAs
    } Elseif ($Choice -eq "n") {
        Start-Process powershell.exe "-ExecutionPolicy Bypass -File",('"{0}"' -f $ScriptPath) -Verb RunAs
    } Else {
        Write-Host "Please rerun the script against the desired executable using the SendTo context menu."
        Write-Host 

        # Pause (won't work in the ISE)
        $Host.UI.RawUI.FlushInputBuffer()
        Write-Host "Press any key to close the window."
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
        $Host.UI.RawUI.FlushInputBuffer()
    }

    Exit $LastExitCode
}


# Helper function to determine executable bitness
# From https://gist.github.com/MyITGuy/a0d462a6e218d1e5a940
function Get-FileBitness {
    [CmdletBinding(SupportsShouldProcess=$True,DefaultParameterSetName="None")]
    PARAM(
    	[Parameter(
    		HelpMessage = "Enter binary file(s) to examine",
    		Position = 0,
    		Mandatory = $true,
    		ValueFromPipeline = $true,
    		ValueFromPipelineByPropertyName = $true
    	)]
    	[ValidateNotNullOrEmpty()]
    	[ValidateScript({Test-Path $_.FullName})]
    	[IO.FileInfo[]]
    	$Path
    )
    
    BEGIN {
        # PE Header machine offset
        [int32]$MACHINE_OFFSET = 4
        # PE Header pointer offset
        [int32]$PE_POINTER_OFFSET = 60
        # Initial byte array size
        [int32]$PE_HEADER_SIZE = 4096
    }
    
    PROCESS {
        # Create a location to place the byte data
        [byte[]]$BYTE_ARRAY = New-Object -TypeName System.Byte[] -ArgumentList @(,$PE_HEADER_SIZE)
        # Open the file for read access
        $FileStream = New-Object -TypeName System.IO.FileStream -ArgumentList ($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        # Read the requested byte length into the byte array
        $FileStream.Read($BYTE_ARRAY, 0, $BYTE_ARRAY.Length) | Out-Null
        #
        [int32]$PE_HEADER_ADDR = [System.BitConverter]::ToInt32($BYTE_ARRAY, $PE_POINTER_OFFSET)
        try {
    	    [int32]$machineUint = [System.BitConverter]::ToUInt16($BYTE_ARRAY, $PE_HEADER_ADDR + $MACHINE_OFFSET)
        } catch {
    	    $machineUint = 0xffff
        }
        switch ($machineUint) {
    	    0x0000 {return 'UNKNOWN'}
    	    0x0184 {return 'ALPHA'}
    	    0x01d3 {return 'AM33'}
    	    0x8664 {return 'AMD64'}
    	    0x01c0 {return 'ARM'}
    	    0x01c4 {return 'ARMNT'} # aka ARMV7
    	    0xaa64 {return 'ARM64'} # aka ARMV8
    	    0x0ebc {return 'EBC'}
    	    0x014c {return 'I386'}
    	    0x014d {return 'I860'}
    	    0x0200 {return 'IA64'}
    	    0x0268 {return 'M68K'}
    	    0x9041 {return 'M32R'}
    	    0x0266 {return 'MIPS16'}
    	    0x0366 {return 'MIPSFPU'}
    	    0x0466 {return 'MIPSFPU16'}
    	    0x01f0 {return 'POWERPC'}
    	    0x01f1 {return 'POWERPCFP'}
    	    0x01f2 {return 'POWERPCBE'}
    	    0x0162 {return 'R3000'}
    	    0x0166 {return 'R4000'}
    	    0x0168 {return 'R10000'}
    	    0x01a2 {return 'SH3'}
    	    0x01a3 {return 'SH3DSP'}
    	    0x01a6 {return 'SH4'}
    	    0x01a8 {return 'SH5'}
    	    0x0520 {return 'TRICORE'}
    	    0x01c2 {return 'THUMB'}
    	    0x0169 {return 'WCEMIPSV2'}
    	    0x0284 {return 'ALPHA64'}
    	    0xffff {return 'INVALID'}
        }
    }
    
    END {
        $FileStream.Close()
        $FileStream.Dispose()
    }
}


# Begin core script
Write-Host

If ($args)
{
    $FullPath = $args[0]
    $FolderPath = Split-Path -Path $FullPath -Parent

    $Bitness = Get-FileBitness $FullPath

    Write-Host "Script Context:"
    Write-Host "Full Path: $FullPath"
    Write-Host "Folder Path: $FolderPath"
    Write-Host "Executable Bitness: $Bitness"
}

# Read SK path from registry
$Key = 'HKCU:\Software\Kaldaien\Special K'
$Value = Get-ItemProperty -Path $Key -Name Path -ErrorAction SilentlyContinue

If ([string]::IsNullOrEmpty($Value) -eq $false)
{
    $SKFolder = $Value.Path + "\"
    
    if ($Bitness -eq "AMD64") {
        $Target = $SKFolder + "SpecialK64.dll"
    } elseif ($Bitness -eq "I386") {
        $Target = $SKFolder + "SpecialK32.dll"
    }

    Write-Host "Target: $Target"
}


# Spacing...
Write-Host
Write-Host


# Filename
do
{
    $FileName = Read-Host "Name of the symlink file [dxgi.dll] "
    If ([string]::IsNullOrEmpty($FileName))
    {
        $FileName = "dxgi.dll"
    }
} while ([string]::IsNullOrEmpty($FileName))


# Folder/Path (only if executing script without any cmd line arguments)
if ($null -eq $FolderPath)
{
    do
    {
        $Path = Read-Host "Path of the folder to put the symlink in "
    } while ([string]::IsNullOrEmpty($FolderPath))
}


# Target (only if executing script without any cmd line arguments)
if ($null -eq $Target)
{
    do
    {
        $Target = Read-Host "Target of the symlink "
    } while ([string]::IsNullOrEmpty($Target))
}


# Create symlink
$Choice = "y"
If (Test-Path "$FolderPath\$FileName")
{
    Write-Warning "A file already exists at $FolderPath\$FileName"

    do
    {
        $Choice = Read-Host "Are you sure you want to proceed? Doing so will delete the existing file. (y/n)"
    } while ($Choice -ne "y" -and $Choice -ne "n")
}

if ($Choice -eq "y")
{
    New-Item -Path $FolderPath -Name $FileName -Type SymbolicLink -Target $Target -Force
    New-Item -Path $FolderPath -Name "SpecialK.central" -ItemType "file" -Force
} Else {
    Exit 1
}

# Some spacing to allow for the output of the New-Item cmdlet
Write-Host

# Pause at end (won't work in the ISE)
$Host.UI.RawUI.FlushInputBuffer()
Write-Host "Press any key to close the window."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
$Host.UI.RawUI.FlushInputBuffer()
