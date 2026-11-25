param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [Parameter(Mandatory = $true)]
    [string]$FallbackManifestPath
)

$ErrorActionPreference = "Stop"

try {
    $exe = (Resolve-Path $ExePath).Path
    $fallback = (Resolve-Path $FallbackManifestPath).Path

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class PeManifestPatcher {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, IntPtr lpType);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LockResource(IntPtr hResData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr BeginUpdateResourceW(string pFileName, bool bDeleteExistingResources);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateResourceW(IntPtr hUpdate, IntPtr lpType, IntPtr lpName, ushort wLanguage, byte[] lpData, uint cbData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool EndUpdateResourceW(IntPtr hUpdate, bool fDiscard);

    const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    static readonly IntPtr RT_MANIFEST = (IntPtr)24;
    static readonly IntPtr CREATEPROCESS_MANIFEST_RESOURCE_ID = (IntPtr)1;

    public static string ReadManifest(string exePath) {
        IntPtr hMod = LoadLibraryExW(exePath, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
        if (hMod == IntPtr.Zero) throw new Exception("LoadLibraryExW failed: " + Marshal.GetLastWin32Error());
        try {
            IntPtr hRes = FindResourceW(hMod, CREATEPROCESS_MANIFEST_RESOURCE_ID, RT_MANIFEST);
            if (hRes == IntPtr.Zero) return null;
            uint size = SizeofResource(hMod, hRes);
            IntPtr hData = LoadResource(hMod, hRes);
            IntPtr ptr = LockResource(hData);
            byte[] buf = new byte[size];
            Marshal.Copy(ptr, buf, 0, (int)size);
            return Encoding.UTF8.GetString(buf);
        } finally {
            FreeLibrary(hMod);
        }
    }

    public static void WriteManifest(string exePath, string xml) {
        byte[] bytes = new UTF8Encoding(false).GetBytes(xml);
        IntPtr hUpd = BeginUpdateResourceW(exePath, false);
        if (hUpd == IntPtr.Zero) throw new Exception("BeginUpdateResourceW failed: " + Marshal.GetLastWin32Error());
        UpdateResourceW(hUpd, RT_MANIFEST, CREATEPROCESS_MANIFEST_RESOURCE_ID, 1033, null, 0);
        if (!UpdateResourceW(hUpd, RT_MANIFEST, CREATEPROCESS_MANIFEST_RESOURCE_ID, 0, bytes, (uint)bytes.Length)) {
            int err = Marshal.GetLastWin32Error();
            EndUpdateResourceW(hUpd, true);
            throw new Exception("UpdateResourceW failed: " + err);
        }
        if (!EndUpdateResourceW(hUpd, false)) {
            throw new Exception("EndUpdateResourceW failed: " + Marshal.GetLastWin32Error());
        }
    }
}
'@

    $orig = [PeManifestPatcher]::ReadManifest($exe)
    if ([string]::IsNullOrWhiteSpace($orig)) {
        Write-Host "No existing manifest — embedding $fallback"
        $patched = Get-Content $fallback -Raw -Encoding UTF8
    } elseif ($orig -match 'level="asInvoker"') {
        Write-Host "Patched jpackage manifest: asInvoker -> requireAdministrator"
        $patched = $orig -replace 'level="asInvoker"', 'level="requireAdministrator"'
    } elseif ($orig -match 'requireAdministrator') {
        Write-Host "Manifest already contains requireAdministrator"
        $patched = $orig
    } else {
        Write-Host "Replacing manifest with $fallback"
        $patched = Get-Content $fallback -Raw -Encoding UTF8
    }

    [PeManifestPatcher]::WriteManifest($exe, $patched)

    $verify = [PeManifestPatcher]::ReadManifest($exe)
    if (-not ($verify -match 'requireAdministrator')) {
        throw "requireAdministrator not found after patching $exe"
    }
    Write-Host "OK: requireAdministrator verified in $exe"
} catch {
    Write-Host "::error title=patch-uac-manifest::$($_.Exception.Message)"
    exit 1
}
