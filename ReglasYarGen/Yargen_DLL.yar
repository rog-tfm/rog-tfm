/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-06
   Identifier: DLL
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_7c9f494ed4397ccedb3d5c8a10235669a31ae7eb79423b6fa785d141cb6d183d {
   meta:
      description = "DLL - file 7c9f494ed4397ccedb3d5c8a10235669a31ae7eb79423b6fa785d141cb6d183d.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "7c9f494ed4397ccedb3d5c8a10235669a31ae7eb79423b6fa785d141cb6d183d"
   strings:
      $s1 = "TaskBarNotifierDemo.dll" fullword ascii
      $s2 = "TaskBarNotifierDemo.exe" fullword wide
      $s3 = "RRRvvvsssxxx!!!" fullword ascii
      $s4 = "555222" ascii /* reversed goodware string '222555' */
      $s5 = "cccUUU" fullword ascii /* reversed goodware string 'UUUccc' */
      $s6 = "222EEE" ascii /* reversed goodware string 'EEE222' */
      $s7 = "            processorArchitecture=\"X86\" " fullword ascii
      $s8 = "<description>Your app description here</description> " fullword ascii
      $s9 = "    processorArchitecture=\"X86\" " fullword ascii
      $s10 = "!sssqssjjj!!!" fullword ascii
      $s11 = "ggg^^^XXXVVVUUUUUUQQQQQQTTTQQQMMMVVVUUUTTTYYYWWWWWWQQQUUUNNNGGGIIIOOOIIIEEEKKKDDDLLLKKKDDDKKKJJJBBBKKKLLLOOOQQQUUU" fullword ascii
      $s12 = "IEYEBH=E" fullword ascii
      $s13 = "'#\"60/-)'!" fullword ascii /* hex encoded string '`' */
      $s14 = "XTcZVcZWe[Xe[Xf\\Xf\\Yg]YLEBg]Zf\\Yg]Yf\\Yf\\Ye\\Xe[XdZWcZVbYVbXUaXT`WT_VS^UQ[SPYQN^UQbYVj`\\tie" fullword ascii
      $s15 = "sopeapeapea" fullword ascii
      $s16 = "            publicKeyToken=\"6595b64144ccf1df\" " fullword ascii
      $s17 = "wsrgcrgcrgc" fullword ascii
      $s18 = "# # # # $ $ $ $!$!$! $! $! $! %! %! %! %! %! %! %! %\" %\" %\" %\" %\" %\"!%\"!%\"!%\"!%\"!%\"!%\"!%\"!%\"!%\"!%\"!%\"!" ascii
      $s19 = "zxkfckec" fullword ascii
      $s20 = "zvwkgwkgvjf" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_5c3106248f206daef2fe467eb407f898d04b3fa5e69ce8ffb13d5d5726dd8e38 {
   meta:
      description = "DLL - file 5c3106248f206daef2fe467eb407f898d04b3fa5e69ce8ffb13d5d5726dd8e38.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "5c3106248f206daef2fe467eb407f898d04b3fa5e69ce8ffb13d5d5726dd8e38"
   strings:
      $s1 = "MyLinks.dll" fullword ascii
      $s2 = "ButtonSkin.dll" fullword ascii
      $s3 = "Demo.dll" fullword ascii
      $s4 = "Demo.EXE" fullword wide
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = " constructor or from DllMain." fullword ascii
      $s8 = "3.3}394/575" fullword ascii /* hex encoded string '39Eu' */
      $s9 = ":,:<:@:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s10 = ":$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:" fullword ascii
      $s11 = ":$:(:,:@:D:T:X:\\:`:h:" fullword ascii
      $s12 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s13 = ": :(:<:L:\\:" fullword ascii
      $s14 = " Class Hierarchy Descriptor'" fullword ascii
      $s15 = " Base Class Descriptor at (" fullword ascii
      $s16 = " Complete Object Locator'" fullword ascii
      $s17 = "lVXwAu2" fullword ascii
      $s18 = "CtrlList3" fullword ascii
      $s19 = "CtrlList2" fullword ascii
      $s20 = "CtrlList1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_4f53975d3d928a6a5f9abe635254b48f42ac119637f10d5237279288feb66c6f {
   meta:
      description = "DLL - file 4f53975d3d928a6a5f9abe635254b48f42ac119637f10d5237279288feb66c6f.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "4f53975d3d928a6a5f9abe635254b48f42ac119637f10d5237279288feb66c6f"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "<oooooooo" fullword ascii /* reversed goodware string 'oooooooo<' */
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "operator<=>" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = "ooooooooooooot" fullword ascii
      $s8 = "ooooooooooot" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = " Complete Object Locator'" fullword ascii
      $s13 = "5,50585@5H5L5T5h5p5" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "6<ooooooo" fullword ascii
      $s15 = ".detourc" fullword ascii
      $s16 = " delete[]" fullword ascii
      $s17 = "<ooooooooooooo|" fullword ascii
      $s18 = ":R;Z;a;" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "070Y0o0" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "@.detourd" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_3a53bd36b24bc40bdce289d26f1b6965c0a5e71f26b05d19c7aa73d9e3cfa6ff {
   meta:
      description = "DLL - file 3a53bd36b24bc40bdce289d26f1b6965c0a5e71f26b05d19c7aa73d9e3cfa6ff.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "3a53bd36b24bc40bdce289d26f1b6965c0a5e71f26b05d19c7aa73d9e3cfa6ff"
   strings:
      $s1 = "SmadHook32c.dll" fullword ascii
      $s2 = " Type Descriptor'" fullword ascii
      $s3 = " constructor or from DllMain." fullword ascii
      $s4 = "xiqdicpetllc" fullword ascii
      $s5 = "nlvursoyumhoavymabjlilfttkaqgptmyvxutidcjkwrclyk" fullword ascii
      $s6 = "lreatfsyeqkocjwbgfyqgsitncveohigfnyhpqhc" fullword ascii
      $s7 = "0D:H:\\:`:p:t:x:" fullword ascii
      $s8 = " Class Hierarchy Descriptor'" fullword ascii
      $s9 = " Base Class Descriptor at (" fullword ascii
      $s10 = " Complete Object Locator'" fullword ascii
      $s11 = " delete[]" fullword ascii
      $s12 = "?+?7???G?S?w?" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "O0a0s0" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "StartProtect" fullword ascii
      $s15 = "wslepsvndqwbwanamfimkadcaaq" fullword ascii
      $s16 = "> >(>,>0>4>8><>@>D>H>L>X>" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "=/=8=?=H=" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "0)1Y1k1" fullword ascii /* Goodware String - occured 1 times */
      $s19 = " delete" fullword ascii
      $s20 = "=!=(=,=0=4=8=<=@=D=" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_3cdd33dea12f21a4f222eb060e1e8ca8a20d5f6ca0fd849715f125b973f3a257 {
   meta:
      description = "DLL - file 3cdd33dea12f21a4f222eb060e1e8ca8a20d5f6ca0fd849715f125b973f3a257.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "3cdd33dea12f21a4f222eb060e1e8ca8a20d5f6ca0fd849715f125b973f3a257"
   strings:
      $x1 = "Content-length: GetModuleHandleAInternetOpenUrlAInternetConnectAHttpOpenRequestAWideCharToMultiBMultiByteToWideCGenerateConsoleC" ascii
      $x2 = "Shellcode.dll" fullword ascii
      $x3 = "RtlCompressBuffeTranslateMessageImpersonateLoggeCreateCompatibleInternetReadFileConnectNamedPipeContent-Type: teGetAsyncKeyState" ascii
      $s4 = "r%WINDIR%\\SYSTEM32\\SERVICES.EXE" fullword wide
      $s5 = "HttpSendRequestEWaitForMultipleOGetWindowThreadPDisconnectNamedPCONNECT %s:%d HTLookupPrivilegeVDispatchMessageWGetComputerNameW" ascii
      $s6 = "\\\\.\\PIPE\\RUN_AS_USER(%d)" fullword wide
      $s7 = "AdjustTokenPriviWaitForSingleObjInternetWriteFilEnumProcessModulGetModuleFileNamGetFileVersionInInternetCloseHanGetConsoleScreen" ascii
      $s8 = "SetConsoleScreenOpenProcessTokenExpandEnvironmenGetForegroundWinOutputDebugStrinChangeServiceConCreateDIBSectionProxy-Connection" ascii
      $s9 = "RtlGetCompressioOpenWindowStatioInternetSetOptioWriteProcessMemoUnhookWindowsHooooooooooooooooooGetSystemDirectoGetThreadDesktop" ascii
      $s10 = "CreateNamedPipeWSQLColAttributeWSHFileOperationWRegQueryValueExWCreateDirectoryWRemoveDirectoryWSetConsoleCtrlHaGetExtendedTcpTa" ascii
      $s11 = "SQLNumResultColsRtlNtStatusToDosFlushFileBuffersTerminateProcessGetTokenInformatQueryServiceStatEnumServicesStatGlobalMemoryStat" ascii
      $s12 = "HttpAddRequestHeDeleteCriticalSeGetDiskFreeSpaceQueryPerformanceWNetEnumResourceSetUnhandledExceRegOverridePredeLdrLoadShellcode" ascii
      $s13 = "Proxy-AuthorizatSQLDriverConnectGetWindowsDirectSfcIsFileProtectGetSystemDefaultRegisterRawInputGetConsoleOutputWriteConsoleInpu" ascii
      $s14 = "SetThreadDesktopOpenInputDesktopReadProcessMemorGetConsoleCursorRegOpenCurrentUsGetSystemMetricsGetOverlappedResGetCurrentProces" ascii
      $s15 = "ReadConsoleOutpuGetConsoleWindowGetProcessWindowSetProcessWindowSetWindowsHookEx" fullword ascii
      $s16 = "\\\\.\\pipe\\a%d" fullword wide
      $s17 = "\\\\.\\pipe\\b%d" fullword wide
      $s18 = "%ALLUSERSPROFILE%\\comsys2" fullword wide
      $s19 = "Protocol:[%4s], Host: [%s:%d], Proxy: [%d:%s:%d:%s:%s]" fullword ascii
      $s20 = "Content-length: GetModuleHandleAInternetOpenUrlAInternetConnectAHttpOpenRequestAWideCharToMultiBMultiByteToWideCGenerateConsoleC" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule a92dbfd52b23a42020e4470ffa8b3dd1199acfad7a84dae298a047b904f31710 {
   meta:
      description = "DLL - file a92dbfd52b23a42020e4470ffa8b3dd1199acfad7a84dae298a047b904f31710.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a92dbfd52b23a42020e4470ffa8b3dd1199acfad7a84dae298a047b904f31710"
   strings:
      $s1 = "cred.dll" fullword ascii
      $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData" fullword ascii
      $s3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\" fullword ascii
      $s4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword ascii
      $s5 = "IMAP Password" fullword ascii
      $s6 = "POP3 Password" fullword ascii
      $s7 = "\\Password" fullword ascii
      $s8 = "SOFTWARE\\RealVNC\\WinVNC4\\Password" fullword ascii
      $s9 = "Password=" fullword ascii
      $s10 = "SOFTWARE\\RealVNC\\vncserver\\Password" fullword ascii
      $s11 = "SOFTWARE\\TightVNC\\Server\\PasswordViewOnly" fullword ascii
      $s12 = "IMAP User" fullword ascii
      $s13 = "SOFTWARE\\TightVNC\\Server\\Password" fullword ascii
      $s14 = "SOFTWARE\\TigerVNC\\WinVNC4\\Password" fullword ascii
      $s15 = "\\Mikrotik\\Winbox\\Addresses.cdb" fullword ascii
      $s16 = "\\.purple\\accounts.xml" fullword ascii
      $s17 = "SOFTWARE\\RealVNC\\vncserver\\HttpPort" fullword ascii
      $s18 = "\\wcx_ftp.ini" fullword ascii
      $s19 = "\\Wcx_ftp.ini" fullword ascii
      $s20 = "SOFTWARE\\TigerVNC\\WinVNC4\\HTTPPortNumber" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799 {
   meta:
      description = "DLL - file fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "php4ts.dll" fullword wide
      $s3 = "is9eusersin3AdobeMozilla" fullword ascii
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "PHP Thread Safe" fullword wide
      $s18 = "4.4.4.4" fullword wide
      $s19 = "oLedward1" fullword ascii
      $s20 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc {
   meta:
      description = "DLL - file 4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "php4ts.dll" fullword wide
      $s3 = "is9eusersin3AdobeMozilla" fullword ascii
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "PHP Thread Safe" fullword wide
      $s18 = "4.4.4.4" fullword wide
      $s19 = "oLedward1" fullword ascii
      $s20 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc {
   meta:
      description = "DLL - file 13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "php4ts.dll" fullword wide
      $s3 = "is9eusersin3AdobeMozilla" fullword ascii
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "PHP Thread Safe" fullword wide
      $s18 = "4.4.4.4" fullword wide
      $s19 = "oLedward1" fullword ascii
      $s20 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2 {
   meta:
      description = "DLL - file a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "php4ts.dll" fullword wide
      $s3 = "is9eusersin3AdobeMozilla" fullword ascii
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "PHP Thread Safe" fullword wide
      $s18 = "4.4.4.4" fullword wide
      $s19 = "oLedward1" fullword ascii
      $s20 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2 {
   meta:
      description = "DLL - file 3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "php4ts.dll" fullword wide
      $s3 = "is9eusersin3AdobeMozilla" fullword ascii
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "PHP Thread Safe" fullword wide
      $s18 = "4.4.4.4" fullword wide
      $s19 = "oLedward1" fullword ascii
      $s20 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7 {
   meta:
      description = "DLL - file af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "php4ts.dll" fullword wide
      $s3 = "is9eusersin3AdobeMozilla" fullword ascii
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "PHP Thread Safe" fullword wide
      $s18 = "4.4.4.4" fullword wide
      $s19 = "oLedward1" fullword ascii
      $s20 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_89066791debd76a797f2839d53d85eb0ac62456f7eb73314f88ead7121bee95c {
   meta:
      description = "DLL - file 89066791debd76a797f2839d53d85eb0ac62456f7eb73314f88ead7121bee95c.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "89066791debd76a797f2839d53d85eb0ac62456f7eb73314f88ead7121bee95c"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
      $s2 = "https://sectigo.com/CPS0" fullword ascii
      $s3 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
      $s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s6 = "http://ocsp.sectigo.com0" fullword ascii
      $s7 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
      $s8 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
      $s9 = "ADRIATIK PORT SERVIS, d.o.o.0" fullword ascii
      $s10 = "ADRIATIK PORT SERVIS, d.o.o.1%0#" fullword ascii
      $s11 = "Sectigo Limited1$0\"" fullword ascii
      $s12 = "Koper1%0#" fullword ascii
      $s13 = "The USERTRUST Network1.0," fullword ascii /* Goodware String - occured 1 times */
      $s14 = "Jersey City1" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "New Jersey1" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "adriaticz@inbox.eu0" fullword ascii
      $s17 = "%USERTrust RSA Certification Authority0" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "LuKMX@kq" fullword ascii
      $s19 = "xlAutoOpen" fullword ascii
      $s20 = "Sectigo RSA Code Signing CA0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule sig_0e74bf09f32b2020d72de239ced4291970375366b26e0156bfdfc4eafa358349 {
   meta:
      description = "DLL - file 0e74bf09f32b2020d72de239ced4291970375366b26e0156bfdfc4eafa358349.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "0e74bf09f32b2020d72de239ced4291970375366b26e0156bfdfc4eafa358349"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
      $s2 = "https://sectigo.com/CPS0" fullword ascii
      $s3 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
      $s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s6 = "http://ocsp.sectigo.com0" fullword ascii
      $s7 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
      $s8 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
      $s9 = "ADRIATIK PORT SERVIS, d.o.o.0" fullword ascii
      $s10 = "ADRIATIK PORT SERVIS, d.o.o.1%0#" fullword ascii
      $s11 = "Sectigo Limited1$0\"" fullword ascii
      $s12 = "Koper1%0#" fullword ascii
      $s13 = "The USERTRUST Network1.0," fullword ascii /* Goodware String - occured 1 times */
      $s14 = "Jersey City1" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "New Jersey1" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "adriaticz@inbox.eu0" fullword ascii
      $s17 = "%USERTrust RSA Certification Authority0" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "xlAutoOpen" fullword ascii
      $s19 = "Sectigo RSA Code Signing CA0" fullword ascii
      $s20 = "Sectigo RSA Code Signing CA" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule ab052068c38c07ee3da41a2ed7670710b5fff0689bb9a6bad61d816b5b6bc0c1 {
   meta:
      description = "DLL - file ab052068c38c07ee3da41a2ed7670710b5fff0689bb9a6bad61d816b5b6bc0c1.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "ab052068c38c07ee3da41a2ed7670710b5fff0689bb9a6bad61d816b5b6bc0c1"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "is9eusersin3AdobeMozilla" fullword ascii
      $s3 = "sir_ehh8_12h.dll" fullword wide
      $s4 = "interface9Lprocessyellowautaylor" fullword ascii
      $s5 = "yyseew4.pdb" fullword ascii
      $s6 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s7 = "danielleOperaExample:GEF3y" fullword ascii
      $s8 = "been2exploitsused" fullword wide
      $s9 = "scycleprovideare" fullword wide
      $s10 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s11 = "Jowasturned5user" fullword ascii
      $s12 = "compromiseW3s" fullword ascii
      $s13 = "5wider1intoJz4systemis" fullword ascii
      $s14 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s15 = "zMIplatform.bejinitialF" fullword ascii
      $s16 = "ZthatotheseyWindows0computationally1" fullword wide
      $s17 = "oLedward1" fullword ascii
      $s18 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
      $s19 = "YTLJh37" fullword ascii
      $s20 = "gKtosydneyLV620155In" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799_4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae_0 {
   meta:
      description = "DLL - from files fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799.dll, 4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc.dll, 13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc.dll, a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2.dll, 3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2.dll, af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799"
      hash2 = "4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc"
      hash3 = "13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc"
      hash4 = "a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2"
      hash5 = "3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2"
      hash6 = "af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7"
   strings:
      $s1 = "php4ts.dll" fullword wide
      $s2 = "PHP Thread Safe" fullword wide
      $s3 = "4.4.4.4" fullword wide
      $s4 = "UhpU=*w" fullword ascii
      $s5 = "SJYkTgK" fullword ascii
      $s6 = "NXPn!}" fullword ascii
      $s7 = "WvXpX\"_" fullword ascii
      $s8 = "SWhp\\@v" fullword ascii
      $s9 = "gIyA\\*" fullword ascii
      $s10 = "EePSg|:" fullword ascii
      $s11 = "8 8$8(8,80848t8x8|8" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "WvXtXv[" fullword ascii
      $s13 = "hpTA?N[" fullword ascii
      $s14 = "WvXpXf{" fullword ascii
      $s15 = "hpTA'F%" fullword ascii
      $s16 = "gaMA\\*" fullword ascii
      $s17 = "eiWwdP&V|" fullword ascii
      $s18 = "^W.Xgp;}" fullword ascii
      $s19 = "gyYaL0J3j'" fullword ascii
      $s20 = "gqoA\\*" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _89066791debd76a797f2839d53d85eb0ac62456f7eb73314f88ead7121bee95c_0e74bf09f32b2020d72de239ced4291970375366b26e0156bfdfc4eafa_1 {
   meta:
      description = "DLL - from files 89066791debd76a797f2839d53d85eb0ac62456f7eb73314f88ead7121bee95c.dll, 0e74bf09f32b2020d72de239ced4291970375366b26e0156bfdfc4eafa358349.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "89066791debd76a797f2839d53d85eb0ac62456f7eb73314f88ead7121bee95c"
      hash2 = "0e74bf09f32b2020d72de239ced4291970375366b26e0156bfdfc4eafa358349"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
      $s2 = "https://sectigo.com/CPS0" fullword ascii
      $s3 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
      $s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s6 = "http://ocsp.sectigo.com0" fullword ascii
      $s7 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
      $s8 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
      $s9 = "ADRIATIK PORT SERVIS, d.o.o.0" fullword ascii
      $s10 = "ADRIATIK PORT SERVIS, d.o.o.1%0#" fullword ascii
      $s11 = "Sectigo Limited1$0\"" fullword ascii
      $s12 = "Koper1%0#" fullword ascii
      $s13 = "The USERTRUST Network1.0," fullword ascii /* Goodware String - occured 1 times */
      $s14 = "Jersey City1" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "New Jersey1" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "adriaticz@inbox.eu0" fullword ascii
      $s17 = "%USERTrust RSA Certification Authority0" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "xlAutoOpen" fullword ascii
      $s19 = "Sectigo RSA Code Signing CA0" fullword ascii
      $s20 = "Sectigo RSA Code Signing CA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _4f53975d3d928a6a5f9abe635254b48f42ac119637f10d5237279288feb66c6f_3a53bd36b24bc40bdce289d26f1b6965c0a5e71f26b05d19c7aa73d9e3_2 {
   meta:
      description = "DLL - from files 4f53975d3d928a6a5f9abe635254b48f42ac119637f10d5237279288feb66c6f.dll, 3a53bd36b24bc40bdce289d26f1b6965c0a5e71f26b05d19c7aa73d9e3cfa6ff.dll, 5c3106248f206daef2fe467eb407f898d04b3fa5e69ce8ffb13d5d5726dd8e38.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "4f53975d3d928a6a5f9abe635254b48f42ac119637f10d5237279288feb66c6f"
      hash2 = "3a53bd36b24bc40bdce289d26f1b6965c0a5e71f26b05d19c7aa73d9e3cfa6ff"
      hash3 = "5c3106248f206daef2fe467eb407f898d04b3fa5e69ce8ffb13d5d5726dd8e38"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Class Hierarchy Descriptor'" fullword ascii
      $s3 = " Base Class Descriptor at (" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799_4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae_3 {
   meta:
      description = "DLL - from files fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799.dll, 4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc.dll, 13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc.dll, ab052068c38c07ee3da41a2ed7670710b5fff0689bb9a6bad61d816b5b6bc0c1.dll, a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2.dll, 3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2.dll, af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7.dll"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fa287fe02d71ed4b44938c6cb1f08854c8d8be976b5df11dca5d5719d7555799"
      hash2 = "4677f1e144078256d846189d50113fa133ab8b971c9389bc1e302d89ae30dcfc"
      hash3 = "13fd29a172f41f378104be3d3b704afcce734cb8c1a5f578ce0db00de43613cc"
      hash4 = "ab052068c38c07ee3da41a2ed7670710b5fff0689bb9a6bad61d816b5b6bc0c1"
      hash5 = "a12cbc75dc6cf03d8e031e14a632ad79b7a580adcf07e7f3043afcceea279fd2"
      hash6 = "3c20bb376dc29063f3554c6b45f7e2528b70c24d3d4b1916b51d97d05f2e08a2"
      hash7 = "af8cc3de3c7c149a1f8e0d5d7530762cf75754547866f2da550f2d350ec315c7"
   strings:
      $s1 = "rrpokdmgnn``.dll" fullword ascii
      $s2 = "is9eusersin3AdobeMozilla" fullword ascii
      $s3 = "interface9Lprocessyellowautaylor" fullword ascii
      $s4 = "yyseew4.pdb" fullword ascii
      $s5 = "Ih196explained2011,MozillacZAj" fullword ascii
      $s6 = "danielleOperaExample:GEF3y" fullword ascii
      $s7 = "been2exploitsused" fullword wide
      $s8 = "scycleprovideare" fullword wide
      $s9 = "3uVSsupportSPDYVcformdo" fullword ascii
      $s10 = "Jowasturned5user" fullword ascii
      $s11 = "compromiseW3s" fullword ascii
      $s12 = "5wider1intoJz4systemis" fullword ascii
      $s13 = "LfUdevelopers,0usingsupport.29thatpermissionswith" fullword ascii
      $s14 = "zMIplatform.bejinitialF" fullword ascii
      $s15 = "ZthatotheseyWindows0computationally1" fullword wide
      $s16 = "oLedward1" fullword ascii
      $s17 = "sayingVaultasCanarywhenNewL2012).ChromeL" fullword ascii
      $s18 = "gKtosydneyLV620155In" fullword ascii
      $s19 = "rchannel,yf" fullword ascii
      $s20 = "chosen9Fpart" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

