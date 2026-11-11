#
# Win32 helpers for the runtime verification (dot-sourced by verify_runtime.ps1).
#
# Windows only: finds the visible top-level windows of a process, brings one to
# the front, types into it with SendInput, takes a screenshot cropped to that
# window, and asks it to close.
#
# Why SendInput and not WScript.Shell.SendKeys: SendKeys has a list of special
# characters to escape and goes through the keyboard layout. SendInput with
# KEYEVENTF_UNICODE delivers the exact characters whatever the layout is.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('PortableWin32' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class PortableWindowInfo
{
    public long Handle;
    public string Title;
    public string ClassName;
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
}

public static class PortableWin32
{
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo;
    }

    // The union starts at offset 8 on x64 (4 on x86). The verification only
    // runs on x64; InputStructSize() lets the caller assert that.
    [StructLayout(LayoutKind.Explicit)]
    private struct INPUT
    {
        [FieldOffset(0)] public uint type;
        [FieldOffset(8)] public MOUSEINPUT mi;
        [FieldOffset(8)] public KEYBDINPUT ki;
    }

    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint WM_CLOSE = 0x0010;

    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextLength(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hWnd, StringBuilder text, int max);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int cmd);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint SendInput(uint count, INPUT[] inputs, int size);
    [DllImport("user32.dll")] private static extern uint MapVirtualKey(uint code, uint mapType);
    [DllImport("user32.dll")] private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool attach);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] private static extern bool SetProcessDPIAware();
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();

    public static int InputStructSize() { return Marshal.SizeOf(typeof(INPUT)); }

    public static void MakeDpiAware() { SetProcessDPIAware(); }

    public static List<PortableWindowInfo> GetWindows(uint pid)
    {
        List<PortableWindowInfo> list = new List<PortableWindowInfo>();
        EnumWindows(delegate (IntPtr h, IntPtr l)
        {
            uint owner;
            GetWindowThreadProcessId(h, out owner);
            if (owner != pid || !IsWindowVisible(h)) { return true; }

            PortableWindowInfo info = new PortableWindowInfo();
            info.Handle = h.ToInt64();
            int len = GetWindowTextLength(h);
            StringBuilder title = new StringBuilder(len + 1);
            GetWindowText(h, title, title.Capacity);
            info.Title = title.ToString();
            StringBuilder cls = new StringBuilder(256);
            GetClassName(h, cls, cls.Capacity);
            info.ClassName = cls.ToString();
            RECT r;
            GetWindowRect(h, out r);
            info.Left = r.Left; info.Top = r.Top; info.Right = r.Right; info.Bottom = r.Bottom;
            list.Add(info);
            return true;
        }, IntPtr.Zero);
        return list;
    }

    public static int[] GetRect(IntPtr h)
    {
        RECT r;
        if (!GetWindowRect(h, out r)) { return null; }
        return new int[] { r.Left, r.Top, r.Right, r.Bottom };
    }

    // x, y, width, height of the whole virtual desktop.
    public static int[] GetVirtualScreen()
    {
        return new int[] { GetSystemMetrics(76), GetSystemMetrics(77), GetSystemMetrics(78), GetSystemMetrics(79) };
    }

    public static bool BringToFront(IntPtr h)
    {
        if (IsIconic(h)) { ShowWindow(h, 9); } // SW_RESTORE
        SetForegroundWindow(h);
        if (GetForegroundWindow() != h)
        {
            // A background process may not take the foreground directly. Sharing
            // the input queue of the current foreground window lifts that limit.
            uint ignored;
            IntPtr fg = GetForegroundWindow();
            uint fgThread = fg == IntPtr.Zero ? 0 : GetWindowThreadProcessId(fg, out ignored);
            uint me = GetCurrentThreadId();
            if (fgThread != 0 && fgThread != me) { AttachThreadInput(me, fgThread, true); }
            BringWindowToTop(h);
            SetForegroundWindow(h);
            if (fgThread != 0 && fgThread != me) { AttachThreadInput(me, fgThread, false); }
        }
        System.Threading.Thread.Sleep(300);
        return GetForegroundWindow() == h;
    }

    public static bool IsForeground(IntPtr h) { return GetForegroundWindow() == h; }

    public static bool Close(IntPtr h) { return PostMessage(h, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); }

    private static INPUT Key(ushort vk, ushort scan, uint flags)
    {
        INPUT i = new INPUT();
        i.type = INPUT_KEYBOARD;
        i.ki.wVk = vk;
        i.ki.wScan = scan;
        i.ki.dwFlags = flags;
        i.ki.time = 0;
        i.ki.dwExtraInfo = IntPtr.Zero;
        return i;
    }

    private static void Send(List<INPUT> inputs)
    {
        INPUT[] arr = inputs.ToArray();
        uint sent = SendInput((uint)arr.Length, arr, Marshal.SizeOf(typeof(INPUT)));
        if (sent != arr.Length)
        {
            throw new InvalidOperationException("SendInput delivered " + sent + " of " + arr.Length + " events (error " + Marshal.GetLastWin32Error() + ")");
        }
    }

    // Types the text character by character as Unicode key events. Line breaks
    // are skipped on purpose: Enter is a real key, see SendChord.
    public static void SendUnicode(string text, int delayMs)
    {
        foreach (char c in text)
        {
            if (c == '\r' || c == '\n') { continue; }
            List<INPUT> pair = new List<INPUT>();
            pair.Add(Key(0, c, KEYEVENTF_UNICODE));
            pair.Add(Key(0, c, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
            Send(pair);
            if (delayMs > 0) { System.Threading.Thread.Sleep(delayMs); }
        }
    }

    // Modifiers down, key down, key up, modifiers up.
    public static void SendChord(ushort[] modifiers, ushort key)
    {
        List<INPUT> seq = new List<INPUT>();
        foreach (ushort m in modifiers) { seq.Add(Key(m, (ushort)MapVirtualKey(m, 0), 0)); }
        seq.Add(Key(key, (ushort)MapVirtualKey(key, 0), 0));
        seq.Add(Key(key, (ushort)MapVirtualKey(key, 0), KEYEVENTF_KEYUP));
        for (int i = modifiers.Length - 1; i >= 0; i--)
        {
            seq.Add(Key(modifiers[i], (ushort)MapVirtualKey(modifiers[i], 0), KEYEVENTF_KEYUP));
        }
        Send(seq);
    }
}
'@
}

Add-Type -AssemblyName System.Drawing

if ([IntPtr]::Size -ne 8) {
    throw 'win32.ps1 supports 64-bit PowerShell only (INPUT struct layout).'
}
if ([PortableWin32]::InputStructSize() -ne 40) {
    throw "Unexpected INPUT struct size $([PortableWin32]::InputStructSize()); SendInput would fail."
}
# Without this, window rectangles are scaled on high-DPI displays and the
# screenshot crop would be wrong.
[PortableWin32]::MakeDpiAware()

function ConvertTo-WindowHandle {
    param([Parameter(Mandatory = $true)]$Handle)
    return [IntPtr]([int64]$Handle)
}

function Get-ProcessWindows {
    # Visible top-level windows owned by the process. Tiny windows (a few pixels,
    # helper windows) are dropped; the message box and the main window are well
    # above the limit.
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [int]$MinSize = 50
    )

    $found = [PortableWin32]::GetWindows([uint32]$ProcessId)
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($w in $found) {
        $width = $w.Right - $w.Left
        $height = $w.Bottom - $w.Top
        if ($width -lt $MinSize -or $height -lt $MinSize) { continue }
        $result.Add([pscustomobject]@{
                Handle    = [IntPtr]$w.Handle
                Title     = $w.Title
                ClassName = $w.ClassName
                Left      = $w.Left
                Top       = $w.Top
                Width     = $width
                Height    = $height
            })
    }
    return $result.ToArray()
}

function Wait-ProcessWindow {
    # Returns the first matching window, or $null when none appears in time or
    # the process exits first.
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [string]$TitleLike
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $windows = @(Get-ProcessWindows -ProcessId $ProcessId)
        if ($TitleLike) {
            $windows = @($windows | Where-Object { $_.Title -like $TitleLike })
        }
        if ($windows.Count -gt 0) { return $windows[0] }
        if ($null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { return $null }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Set-WindowForeground {
    # Returns $true when the window really is in the foreground afterwards.
    param([Parameter(Mandatory = $true)]$Handle)
    return [PortableWin32]::BringToFront((ConvertTo-WindowHandle -Handle $Handle))
}

function Save-WindowScreenshot {
    # Crops to the window rectangle only (never the whole desktop). The window
    # is brought to the front first so nothing else covers it; the rectangle is
    # clamped to the virtual screen because a maximised window reports a few
    # pixels of invisible border outside it.
    param(
        [Parameter(Mandatory = $true)]$Handle,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $hwnd = ConvertTo-WindowHandle -Handle $Handle
    [void][PortableWin32]::BringToFront($hwnd)
    Start-Sleep -Milliseconds 500

    $rect = [PortableWin32]::GetRect($hwnd)
    if ($null -eq $rect) { throw "GetWindowRect failed for handle $Handle" }
    $screen = [PortableWin32]::GetVirtualScreen()

    $left = [Math]::Max($rect[0], $screen[0])
    $top = [Math]::Max($rect[1], $screen[1])
    $right = [Math]::Min($rect[2], $screen[0] + $screen[2])
    $bottom = [Math]::Min($rect[3], $screen[1] + $screen[3])
    $width = $right - $left
    $height = $bottom - $top
    if ($width -le 0 -or $height -le 0) {
        throw "Window rectangle $($rect -join ',') is outside the screen $($screen -join ',')"
    }

    $bitmap = [System.Drawing.Bitmap]::new($width, $height)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.CopyFromScreen($left, $top, 0, 0, [System.Drawing.Size]::new($width, $height))
        } finally {
            $graphics.Dispose()
        }
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $dir -Force)
        }
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bitmap.Dispose()
    }
}

function Send-Text {
    # Foreground first, then type. Throws when the window could not be brought
    # to the front, because the keystrokes would go to some other window.
    param(
        [Parameter(Mandatory = $true)]$Handle,
        [Parameter(Mandatory = $true)][string]$Text,
        [int]$DelayMilliseconds = 8
    )

    if (-not (Set-WindowForeground -Handle $Handle)) {
        throw 'Could not bring the window to the foreground; not sending keystrokes.'
    }
    [PortableWin32]::SendUnicode($Text, $DelayMilliseconds)
}

function ConvertTo-KeyChord {
    # 'Ctrl+=' -> modifiers (0x11), key 0xBB. Supports Ctrl, Shift, Alt, Win and
    # the keys the verification needs.
    param([Parameter(Mandatory = $true)][string]$Keys)

    $modifierCodes = @{ 'ctrl' = 0x11; 'shift' = 0x10; 'alt' = 0x12; 'win' = 0x5B }
    $namedKeys = @{
        'enter' = 0x0D; 'escape' = 0x1B; 'esc' = 0x1B; 'tab' = 0x09; 'space' = 0x20
        'backspace' = 0x08; 'up' = 0x26; 'down' = 0x28; 'left' = 0x25; 'right' = 0x27
        '=' = 0xBB; '+' = 0xBB; '-' = 0xBD; ',' = 0xBC; '.' = 0xBE
    }

    # A trailing '+' means the plus key itself ('Ctrl++').
    $parts = [System.Collections.Generic.List[string]]::new()
    $rest = $Keys
    if ($rest.EndsWith('++')) {
        $rest = $rest.Substring(0, $rest.Length - 2)
        foreach ($p in ($rest -split '\+')) { if ($p) { $parts.Add($p) } }
        $parts.Add('+')
    } else {
        foreach ($p in ($rest -split '\+')) { $parts.Add($p) }
    }
    if ($parts.Count -eq 0) { throw "Empty key specification '$Keys'" }

    $modifiers = [System.Collections.Generic.List[uint16]]::new()
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        $name = $parts[$i].ToLowerInvariant()
        if (-not $modifierCodes.ContainsKey($name)) { throw "Unknown modifier '$($parts[$i])' in '$Keys'" }
        $modifiers.Add([uint16]$modifierCodes[$name])
    }

    $keyName = $parts[$parts.Count - 1].ToLowerInvariant()
    if ($namedKeys.ContainsKey($keyName)) {
        $key = [uint16]$namedKeys[$keyName]
    } elseif ($keyName -match '^[a-z0-9]$') {
        # Virtual-key codes of letters and digits equal their upper-case ASCII code.
        $key = [uint16][int][char]$keyName.ToUpperInvariant()
    } else {
        throw "Unknown key '$keyName' in '$Keys'"
    }
    return [pscustomobject]@{ Modifiers = $modifiers.ToArray(); Key = $key }
}

function Send-Keys {
    param(
        [Parameter(Mandatory = $true)]$Handle,
        [Parameter(Mandatory = $true)][string]$Keys
    )

    $chord = ConvertTo-KeyChord -Keys $Keys
    if (-not (Set-WindowForeground -Handle $Handle)) {
        throw 'Could not bring the window to the foreground; not sending keystrokes.'
    }
    [PortableWin32]::SendChord([uint16[]]$chord.Modifiers, $chord.Key)
}

function Close-ProcessWindow {
    # Asks every visible top-level window of the process to close (WM_CLOSE),
    # the same as the user clicking the X. Returns how many were asked.
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $count = 0
    foreach ($w in @(Get-ProcessWindows -ProcessId $ProcessId -MinSize 0)) {
        if ([PortableWin32]::Close($w.Handle)) { $count++ }
    }
    return $count
}
