/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-06
   Identifier: EXE
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8 {
   meta:
      description = "EXE - file a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP" fullword ascii
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s4 = "gtdytg.exe" fullword wide
      $s5 = "<Report xmlns=\"http://schemas.microsoft.com/sqlserver/reporting/2008/01/reportdefinition\" xmlns:rd=\"http://schemas.microsoft." ascii
      $s6 = "<Report xmlns=\"http://schemas.microsoft.com/sqlserver/reporting/2008/01/reportdefinition\" xmlns:rd=\"http://schemas.microsoft." ascii
      $s7 = "mp; Cstr(Cint(DateValue(Globals!ExecutionTime).Year) + 543)</Value>" fullword ascii
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s9 = "                <Value>=DateValue(Globals!ExecutionTime).Day &amp; \"/\" &amp; DateValue(Globals!ExecutionTime).Month &amp; \"/" ascii
      $s10 = "mp; Cint(DateValue(Globals!ExecutionTime).Year)+543</Value>" fullword ascii
      $s11 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s12 = "m_frmLogin" fullword ascii
      $s13 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s14 = "            compatibility then delete the requestedExecutionLevel node." fullword ascii
      $s15 = "                <Value>=DateValue(Globals!ExecutionTime).Day &amp; \"/\" &amp; DateValue(Globals!ExecutionTime).Month &amp; \"/" ascii
      $s16 = "                <Value>=DateValue(Globals!ExecutionTime).Day &amp; \"/\" &amp; DateValue(Globals!ExecutionTime).Month &amp; \"/" ascii
      $s17 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii
      $s18 = "login1" fullword wide
      $s19 = "MyTemplate" fullword ascii
      $s20 = "        <rd:SchemaPath>D:\\Customer3\\Stock\\Stock\\ReportDataSet\\dsWithdraw.xsd</rd:SchemaPath>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0 {
   meta:
      description = "EXE - file c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxHost+State, System.Windo" ascii
      $x4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii
      $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s6 = "pXFeGZZTMM61p7DlZH.DdD5tQG3bYfQyK3jq3+zux9rhwrwurZ9yybGe+mwO4aJkDbKZLqV5A4L`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
      $s7 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii
      $s8 = "StrongNameKeyPa.exe" fullword wide
      $s9 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii
      $s10 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s11 = "ws.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADP" fullword ascii
      $s12 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s13 = "pXFeGZZTMM61p7DlZH.DdD5tQG3bYfQyK3jq3+zux9rhwrwurZ9yybGe+mwO4aJkDbKZLqV5A4L`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
      $s14 = "5265616465725772697465724C6F636B54696D65644F757445786365707469" wide /* hex encoded string 'ReaderWriterLockTimedOutExcepti' */
      $s15 = "4B4C7076506C6541" wide /* hex encoded string 'KLpvPleA' */
      $s16 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s17 = "YABIOT9gZv" fullword ascii /* base64 encoded string '` H9?`f' */
      $s18 = " System.Globalization.CompareInfo" fullword ascii
      $s19 = "RntCQ0tvZe" fullword ascii /* base64 encoded string 'F{BCKoe' */
      $s20 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792 {
   meta:
      description = "EXE - file 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxH" ascii
      $s2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxH" ascii
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s4 = "ost+State, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089hSystem.Drawing.Bitmap, System" ascii
      $s5 = ".Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADP" fullword ascii
      $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s7 = "42696E617279417272" wide /* hex encoded string 'BinaryArr' */
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s9 = "get_eatGhosts" fullword ascii
      $s10 = "PERMAINAN SELESAI !!!" fullword wide
      $s11 = "SELAMAT !!!" fullword wide
      $s12 = "othello" fullword ascii
      $s13 = "!System.Windows.Forms.AxHost+State" fullword ascii
      $s14 = "OTHELLO .NET" fullword wide
      $s15 = "\\CLUE.txt" fullword wide
      $s16 = "get_pacClosedDown" fullword ascii
      $s17 = "get_PacClosedRight" fullword ascii
      $s18 = "get_pacClosedLeft" fullword ascii
      $s19 = "get_BinaryArr" fullword ascii
      $s20 = "get_PacClosedUp" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df {
   meta:
      description = "EXE - file e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxHost+State, System.Windo" ascii
      $x4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii
      $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s6 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii
      $s7 = "LTeKCSHUA72CV2fott.bBPce6SJXjkT9hhDiC+rTatHW3UM4d2f23Kwt+arhK8UKddt2t9ih0aV`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
      $s8 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii
      $s9 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s10 = "SecurityConte.exe" fullword wide
      $s11 = "ws.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADP" fullword ascii
      $s12 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s13 = "LTeKCSHUA72CV2fott.bBPce6SJXjkT9hhDiC+rTatHW3UM4d2f23Kwt+arhK8UKddt2t9ih0aV`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
      $s14 = "4C6F6E675061746848656C70" wide /* hex encoded string 'LongPathHelp' */
      $s15 = "326B65324E52354374" wide /* hex encoded string '2ke2NR5Ct' */
      $s16 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s17 = " System.Globalization.CompareInfo" fullword ascii
      $s18 = "KFxHZDx1V5" fullword ascii /* base64 encoded string '(\Gd<uW' */
      $s19 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s20 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5 {
   meta:
      description = "EXE - file 9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADF" fullword ascii
      $s4 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '                                                                                                                                                                                                                                                                           ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '                                                                                                                                                                                                       ' */
      $s7 = "UnSafeCharBuff.exe" fullword wide
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s9 = "33735671584F4B4C58" wide /* hex encoded string '3sVqXOKLX' */
      $s10 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s11 = "AAqAAARFSwoACs4Kzl9OwAABCs1Gi01JgArOHs8AAAEKzQrNSwKKzQrNW+aAAAGAH5XAAAEAijhAAAGGyzaABYt1yoCK8UDK8QCK8gokgAABivFAivFCivJBivIBivJA" wide
      $s12 = "ETACIEFAETACUEFAETACgEIQETACsELAETAIoLLAETAC4ELAETAI4LLAETADEELAETAKALLAETADQELAETALgLLAETADcELAETAMILLAETADoELAETAMYLLAETAD0ELA" wide
      $s13 = "vdXJjZU1hbmFnZXIAU3lzdGVtLlJlc291cmNlcwByZXNvdXJjZUN1bHR1cmUAQ3VsdHVyZUluZm8AU3lzdGVtLkdsb2JhbGl6YXRpb24AZGVmYXVsdEluc3RhbmNlAGN" wide /* base64 encoded string 'urceManager System.Resources resourceCulture CultureInfo System.Globalization defaultInstance components IContainer System.ComponentModel _MephTheme1 _MephButton1 _MephTabcontrol1 _TabPage1 TabPage _TabPage2 var1 var2 var3 d value__ None Over Down Block _subHeader _a' */
      $s14 = "ZGRfQ2hlY2tlZENoYW5nZWQAb2JqAHJlbW92ZV9DaGVja2VkQ2hhbmdlZABUYXJnZXRPYmplY3QAVGFyZ2V0TWV0aG9kAEJlZ2luSW52b2tlAElBc3luY1Jlc3VsdABB" wide /* base64 encoded string 'dd_CheckedChanged obj remove_CheckedChanged TargetObject TargetMethod BeginInvoke IAsyncResult AsyncCallback sender DelegateCallback DelegateAsyncState EndInvoke DelegateAsyncResult Invoke get_txtbox set_txtbox get_UseSystemPasswordChar v get_MaxLength get_TextAlignm' */
      $s15 = "jdABtZXRob2QAaQBjYWxsYmFjawByZXN1bHQAR2V0AHN0cmluZ0lEAEdldENhY2hlZE9yUmVzb3VyY2UAR2V0RnJvbVJlc291cmNlAENhY2hlU3RyaW5nAENoZWNrZWR" wide /* base64 encoded string 't method i callback result Get stringID GetCachedOrResource GetFromResource CacheString CheckedChanged Application Forms WebServices GetInstance Culture Default Settings MephTheme1 MephButton1 MephTabcontrol1 TabPage1 TabPage2 WrappedObject SubHeader AccentColor Head' */
      $s16 = "ZXJfTGluZQBDaGVja2VkAHR4dGJveABVc2VTeXN0ZW1QYXNzd29yZENoYXIATWF4TGVuZ3RoAFRleHRBbGlnbm1lbnQATXVsdGlMaW5lAFdvcmRXcmFwAE1heGltdW0A" wide /* base64 encoded string 'er_Line Checked txtbox UseSystemPasswordChar MaxLength TextAlignment MultiLine WordWrap Maximum ShowPercentage StartIndex DisplayRectangle ItemHighlightColor CompilationRelaxationsAttribute RuntimeCompatibilityAttribute DebuggableAttribute System.Diagnostics Debuggin' */
      $s17 = "1bHRFdmVudEF0dHJpYnV0ZQBBdHRyaWJ1dGVVc2FnZUF0dHJpYnV0ZQBBdHRyaWJ1dGVUYXJnZXRzAFRocmVhZFN0YXRpY0F0dHJpYnV0ZQBEZWJ1Z2dlckJyb3dzYWJ" wide /* base64 encoded string 'ltEventAttribute AttributeUsageAttribute AttributeTargets ThreadStaticAttribute DebuggerBrowsableAttribute DebuggerBrowsableState AccessedThroughPropertyAttribute DebuggerHiddenAttribute DebuggerStepThroughAttribute HelpKeywordAttribute System.ComponentModel.Design T' */
      $s18 = "othello" fullword ascii
      $s19 = "yblR5cGUARHluYW1pY01ldGhvZABTeXN0ZW0uUmVmbGVjdGlvbi5FbWl0AEdldElMR2VuZXJhdG9yAElMR2VuZXJhdG9yAE9wQ29kZXMATGRhcmdfMABPcENvZGUARW1" wide /* base64 encoded string 'nType DynamicMethod System.Reflection.Emit GetILGenerator ILGenerator OpCodes Ldarg_0 OpCode Emit Ldarg_1 Ldarg_2 Ldarg_3 Ldarg_S Tailcall Call Callvirt Ret SetValue GetFields BindingFlags Char InitializeArray RuntimeFieldHandle GetModules Module get_ModuleHandle get' */
      $s20 = "get_Kambing1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_4650f39d7dbcca87b71d772a850f8cd91c1279e8081ce9de9bcc97310641e564 {
   meta:
      description = "EXE - file 4650f39d7dbcca87b71d772a850f8cd91c1279e8081ce9de9bcc97310641e564.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "4650f39d7dbcca87b71d772a850f8cd91c1279e8081ce9de9bcc97310641e564"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "5eKGLab.exe" fullword wide
      $s3 = "stuSys.Login.resources" fullword ascii
      $s4 = "https://github.com/seungyup26/minulazer" fullword wide
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s6 = "sqlCommand1" fullword ascii
      $s7 = "threadLogBox" fullword wide
      $s8 = "'and password='" fullword wide
      $s9 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s10 = "select * from syuser where Use_name='" fullword wide
      $s11 = "ConvertWorker_RunWorkerCompleted" fullword ascii
      $s12 = "get_OffsetMarshaler" fullword ascii
      $s13 = "get_FileContext" fullword ascii
      $s14 = "get_cDvUnNB" fullword ascii
      $s15 = "GetRangeset" fullword ascii
      $s16 = "getCourseIdByCourseName" fullword ascii
      $s17 = "get_BlocksToWrite" fullword ascii
      $s18 = "get_ReturnMessage" fullword ascii
      $s19 = "MinuFlood" fullword ascii
      $s20 = "stateLogBox" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f {
   meta:
      description = "EXE - file 368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f"
   strings:
      $x1 = "C:\\xampp\\htdocs\\Loct\\8f82ea882f9343e29650dd73cff42a99\\Loader\\Project1\\Release\\Project1.pdb" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = ">{cFTpfJ]p" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = "operator co_await" fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = " Base Class Descriptor at (" fullword ascii
      $s11 = "fn9irc" fullword ascii
      $s12 = " Class Hierarchy Descriptor'" fullword ascii
      $s13 = "VsPFqV9" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "}\\- A}%" fullword ascii
      $s16 = "  </trustInfo>" fullword ascii
      $s17 = ":uDXI8>;\\" fullword ascii
      $s18 = "Z|8.ggO" fullword ascii
      $s19 = "__swift_1" fullword ascii
      $s20 = "wz+mInK%g9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13 {
   meta:
      description = "EXE - file b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13"
   strings:
      $x1 = "C:\\xampp\\htdocs\\Cryptor\\80e0fef346e64caeb35e33835572a689\\Loader\\Project1\\Release\\Project1.pdb" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "vFoq:\"" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = "iRclwLna" fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = "vWK\"RUnC~A|" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = " Class Hierarchy Descriptor'" fullword ascii
      $s13 = " Complete Object Locator'" fullword ascii
      $s14 = "\\.tzu#;" fullword ascii
      $s15 = "DialogClass" fullword wide
      $s16 = "  </trustInfo>" fullword ascii
      $s17 = "__swift_1" fullword ascii
      $s18 = "__swift_2" fullword ascii
      $s19 = " delete[]" fullword ascii
      $s20 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d {
   meta:
      description = "EXE - file ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d"
   strings:
      $s1 = "C:\\xampp\\htdocs\\Loct\\7062b30a99b3466ca1bdf4119c1796ab\\Loader\\pr2\\Release\\pr2.pdb" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "operator<=>" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = ".data$rs" fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = "Read from file" fullword wide
      $s11 = "File open error" fullword wide
      $s12 = "pr2, Version 1.0" fullword wide
      $s13 = " Base Class Descriptor at (" fullword ascii
      $s14 = " Class Hierarchy Descriptor'" fullword ascii
      $s15 = "\\-<- \\" fullword ascii
      $s16 = "vector too long" fullword ascii
      $s17 = " Complete Object Locator'" fullword ascii
      $s18 = "j;1+ >" fullword ascii
      $s19 = "  </trustInfo>" fullword ascii
      $s20 = "__swift_1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule f949b78b040cbfc95aafb50ef30ac3e8c16771c6b926b6f8f1efe44a1f437d51 {
   meta:
      description = "EXE - file f949b78b040cbfc95aafb50ef30ac3e8c16771c6b926b6f8f1efe44a1f437d51.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f949b78b040cbfc95aafb50ef30ac3e8c16771c6b926b6f8f1efe44a1f437d51"
   strings:
      $s1 = "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "AcroRd32.exe" fullword ascii
      $s3 = "hex.dll" fullword ascii
      $s4 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide
      $s5 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s6 = "&Enter password for the encrypted file:" fullword wide
      $s7 = "  processorArchitecture=\"*\"" fullword ascii
      $s8 = "      <requestedExecutionLevel level=\"asInvoker\"            " fullword ascii
      $s9 = "adobeupdate.dat" fullword ascii
      $s10 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s11 = "  version=\"1.0.0.0\"" fullword ascii
      $s12 = "ErroraErrors encountered while performing the operation" fullword wide
      $s13 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide
      $s14 = "      processorArchitecture=\"*\"" fullword ascii
      $s15 = "Please download a fresh copy and retry the installation" fullword wide
      $s16 = "plkjjii" fullword ascii
      $s17 = "      publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s18 = "aaaaaaaaaaaaaaaaaaaaf" ascii
      $s19 = "      version=\"6.0.0.0\"" fullword ascii
      $s20 = "    <!--The ID below indicates application support for Windows 7 -->" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414 {
   meta:
      description = "EXE - file a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii
      $x2 = "pe=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64" ascii
      $s3 = "el level=\"asInvoker\" uiAccess=\"false\"></v3:requestedExecutionLevel></v3:requestedPrivileges></v3:security></v3:trustInfo></a" ascii
      $s4 = "C:\\cuhifuvetab.pdb" fullword ascii
      $s5 = "rue</dpiAware></v3:windowsSettings></v3:application><v3:trustInfo><v3:security><v3:requestedPrivileges><v3:requestedExecutionLev" ascii
      $s6 = "on></compatibility><v3:application><v3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAware" ascii
      $s7 = "Vudoni yefesixosi vohiyeyasicok. Tepez yoxekocamebino. Yotusacawazi. Yokivitotuv pozudafipod kekefufojajup yaciperecijukew seyov" ascii
      $s8 = "oxicex. Tefiricorerakon bimagijilido. Xinogas forif neyebut mowinayayaf. Yiv. Gesezeticevote kehimulifez tozuvucovakeyo boseloce" ascii
      $s9 = "entity version=\"1.1.00.00\" name=\"AutoHotkey\" type=\"win32\"></assemblyIdentity><dependency><dependentAssembly><assemblyIdent" ascii
      $s10 = "Mayuye xocakis pomawekeresereh. Lefilinipoxawol vafepuk dicafuban. Hujapopumoy. Masatafuri. Didalorigu. Zikugerivifaw hociyudupe" ascii
      $s11 = "hapawikitozibozipusi dagetegopuwikafox" fullword ascii
      $s12 = " Type Descriptor'" fullword ascii
      $s13 = "kogzmuadeke.exi" fullword wide
      $s14 = " constructor or from DllMain." fullword ascii
      $s15 = "wijiwifalipimetibuligijabudidozo fed rolujalajuliv fomij docoxewicudavobinidegamu" fullword ascii
      $s16 = " Rideyetex. Zigopidaj guyubife. Nafawat naxamiliyifamu rijipifenitonuw jir gutediweyokojop. Kotogob nobasane xid. Fefihuzakiney " ascii
      $s17 = "22222222/2////2" fullword ascii /* hex encoded string '"""""' */
      $s18 = "xobudazureri jabep dugod gunuyojigoyicowucomeyacebupef" fullword wide
      $s19 = "guzodehuxipecuhojax velagajuyovuwozemihe sasewikufirunuma" fullword wide
      $s20 = "hizejikekacuwawidobikopaganinetayizufuluyijoyegixoyobohamepoxedujohuyokuyusu" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1 {
   meta:
      description = "EXE - file fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                            ' */
      $s2 = "Jun lehekamaxovef wexiz lazirele. Gubuhilowukuyuh nirusikif. Puza luvelolaragif liwev zozozemujex. Xikil ruyesosaxag yiwamu hipe" ascii
      $s3 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s4 = "C:\\koguroca walagaxawa\\ranoja.pdb" fullword ascii
      $s5 = "LetucogdRopuhotihu vazopipehet tabubotocenur codosubop paxejiforifirib xewi hiniw jedemuv zemafeginuhune has" fullword wide
      $s6 = "PPPPP^" fullword ascii /* reversed goodware string '^PPPPP' */
      $s7 = "Cup zuxezuvacivek musi gewuposawakow tuyu. Dazuronicepotok lepasasi kulopad jimu potobezedabaxam. Yafifosicakax gelojiv laleruci" ascii
      $s8 = " Type Descriptor'" fullword ascii
      $s9 = "kogzmuahoke.exi" fullword wide
      $s10 = "fa bevi rulejijakug depaciriyugovis sep. Vojigexesuwah zimilefave lerog pukekisuyizuk xoko. Nusirabapuy josamak zedeme tafeyehor" ascii
      $s11 = "asasiyovih gabof bopum. Pehaxolalufinak leniwuku. Tig civuhiz sozefi. Laxilazufijibac. Tav. Zej rafeheyecij xopimo yupazokidezex" ascii
      $s12 = "huhe gahonigunuroxag zaharifuyilirid. Logozixivetud. Guzukovino sucuviv. Fimem viraxayavot bizabaluz juhotulirubari. Wegogevoj f" ascii
      $s13 = "ujo hupog mapaf peta nabucileja. Nowohap goveyemogay sovuk. Zahebip wimi gapibuwokona juzitujimola fanakexanazajov. Nalo sasawix" ascii
      $s14 = "paw tal. Fedegocunozir bezosibunizi sohahakunis vofixi luh. Doku dutobemal. Pune pumamiwi buniruz. Pururoyes mamalozupeci meyeh " ascii
      $s15 = "uvexak yap. Filabusin vebicosuluxijah fesolamopavoxu. Bipifadojukujow bagetulumuso xigagobokiya. Wojolalor hir rewa deredile won" ascii
      $s16 = " constructor or from DllMain." fullword ascii
      $s17 = "fofaji lobu sacorubuka xuvotilut. Gefo. Yotipasopojaxu. Rocopomadod yesinobununa. Tavidezedoxiga soyowu cezumakimega halogokehax" ascii
      $s18 = "7'____'_'7" fullword ascii /* hex encoded string 'w' */
      $s19 = "jego. Hetofedac. Kut sulanonidij. Cedereraxugaw heyehimodoretu. Ginipafaduj. Jarotak femu juhisebomesu fibegakogico nododu. Jojo" ascii
      $s20 = "fexajewu. Zozininuhiludu wekobisujehipi wiwusozositemo. Sasasefilo gisozelateben hetukeyesatura. Cajohujad nuxez fugoyigimoyilu " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c {
   meta:
      description = "EXE - file 8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c"
   strings:
      $s1 = "Jun lehekamaxovef wexiz lazirele. Gubuhilowukuyuh nirusikif. Puza luvelolaragif liwev zozozemujex. Xikil ruyesosaxag yiwamu hipe" ascii
      $s2 = "__head_C__Users_Peter_Code_winapi_rs_i686_lib_libwinapi_kernel32_a" fullword ascii
      $s3 = "C:\\fokagixes.pdb" fullword ascii
      $s4 = "__ZN3std10sys_common11thread_info11THREAD_INFO7__getit5__KEY17h6b183f349bf17a92E" fullword ascii
      $s5 = "__head_C__Users_Peter_Code_winapi_rs_i686_lib_libwinapi_crypt32_a" fullword ascii
      $s6 = "__head_C__Users_Peter_Code_winapi_rs_i686_lib_libwinapi_gdi32_a" fullword ascii
      $s7 = "__head_C__Users_Peter_Code_winapi_rs_i686_lib_libwinapi_user32_a" fullword ascii
      $s8 = "__head_C__Users_Peter_Code_winapi_rs_i686_lib_libwinapi_advapi32_a" fullword ascii
      $s9 = "__C__Users_Peter_Code_winapi_rs_i686_lib_libwinapi_kernel32_a_iname" fullword ascii
      $s10 = "__imp__Process32Next@8" fullword ascii
      $s11 = "__ZN3std3sys7windows5mutex5Mutex7remutex17h1b6258974367227aE" fullword ascii
      $s12 = "__imp__Process32First@8" fullword ascii
      $s13 = "__ZN3std3sys7windows5mutex5Mutex4lock17h5b0fa897b97e120eE" fullword ascii
      $s14 = "__ZN3std3sys7windows5mutex4kind4KIND17h3bf68051c1d3f7c9E" fullword ascii
      $s15 = "__ZN6kaguya5gecko5Gecko12read_cookies28_$u7b$$u7b$closure$u7d$$u7d$17hb05eb7f5be3cbf8dE" fullword ascii
      $s16 = "__ZN3std4sync5mutex14Mutex$LT$T$GT$4lock17h431878f89ebc0aa2E" fullword ascii
      $s17 = "__ZN3std3sys7windows5mutex4kind17h15a0613674f8d4e2E" fullword ascii
      $s18 = "__ZN3std3sys7windows5mutex5Mutex6unlock17h894acd9f8c13644dE" fullword ascii
      $s19 = "__ZN3std3sys7windows5mutex14ReentrantMutex6unlock17hf0dd3eb09284451aE" fullword ascii
      $s20 = "__ZN6kaguya10encryption27default_dp_api_decrypt_fail17h217132cbb2d34f4bE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d {
   meta:
      description = "EXE - file b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d"
   strings:
      $s1 = "Jun lehekamaxovef wexiz lazirele. Gubuhilowukuyuh nirusikif. Puza luvelolaragif liwev zozozemujex. Xikil ruyesosaxag yiwamu hipe" ascii
      $s2 = "C:\\suwotedo\\zorurotanijef-jiye\\cawisoxemod bisakeveyilu56-jip.pdb" fullword ascii
      $s3 = "LetucogdRopuhotihu vazopipehet tabubotocenur codosubop paxejiforifirib xewi hiniw jedemuv zemafeginuhune has" fullword wide
      $s4 = "Cup zuxezuvacivek musi gewuposawakow tuyu. Dazuronicepotok lepasasi kulopad jimu potobezedabaxam. Yafifosicakax gelojiv laleruci" ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "kogzmuahoke.exi" fullword wide
      $s7 = "fa bevi rulejijakug depaciriyugovis sep. Vojigexesuwah zimilefave lerog pukekisuyizuk xoko. Nusirabapuy josamak zedeme tafeyehor" ascii
      $s8 = "asasiyovih gabof bopum. Pehaxolalufinak leniwuku. Tig civuhiz sozefi. Laxilazufijibac. Tav. Zej rafeheyecij xopimo yupazokidezex" ascii
      $s9 = "huhe gahonigunuroxag zaharifuyilirid. Logozixivetud. Guzukovino sucuviv. Fimem viraxayavot bizabaluz juhotulirubari. Wegogevoj f" ascii
      $s10 = "ujo hupog mapaf peta nabucileja. Nowohap goveyemogay sovuk. Zahebip wimi gapibuwokona juzitujimola fanakexanazajov. Nalo sasawix" ascii
      $s11 = "paw tal. Fedegocunozir bezosibunizi sohahakunis vofixi luh. Doku dutobemal. Pune pumamiwi buniruz. Pururoyes mamalozupeci meyeh " ascii
      $s12 = "uvexak yap. Filabusin vebicosuluxijah fesolamopavoxu. Bipifadojukujow bagetulumuso xigagobokiya. Wojolalor hir rewa deredile won" ascii
      $s13 = " constructor or from DllMain." fullword ascii
      $s14 = "fofaji lobu sacorubuka xuvotilut. Gefo. Yotipasopojaxu. Rocopomadod yesinobununa. Tavidezedoxiga soyowu cezumakimega halogokehax" ascii
      $s15 = "jego. Hetofedac. Kut sulanonidij. Cedereraxugaw heyehimodoretu. Ginipafaduj. Jarotak femu juhisebomesu fibegakogico nododu. Jojo" ascii
      $s16 = "fexajewu. Zozininuhiludu wekobisujehipi wiwusozositemo. Sasasefilo gisozelateben hetukeyesatura. Cajohujad nuxez fugoyigimoyilu " ascii
      $s17 = "dojatatenek" fullword ascii
      $s18 = "gojolazodicufevaxasirenam" fullword ascii
      $s19 = "riwopeninifoxucekewenepe" fullword ascii
      $s20 = "ppppppppppppppppv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5 {
   meta:
      description = "EXE - file 9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5"
   strings:
      $s1 = "ciporugis.exe" fullword ascii
      $s2 = "C:\\xozub\\pitaz10-kurixaziwivosu\\5.pdb" fullword ascii
      $s3 = "7777777777777777777777777777777777777777" ascii /* hex encoded string 'wwwwwwwwwwwwwwwwwwww' */
      $s4 = "ffffft" fullword ascii /* reversed goodware string 'tfffff' */
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "Xuhey sezezag husegux hihorujo fetoxupaxanizi. Tokopipifuk gibojobupubiga xibimenuwuc. Tumize yet. Hiyazipi mibuwiv bibetepepate" ascii
      $s7 = "DD!!!!!!!" fullword ascii
      $s8 = "kogzmuafoke.exu" fullword wide
      $s9 = " constructor or from DllMain." fullword ascii
      $s10 = " bafolezecubeb riyujuboxosipi. Tutufevaw gakuyulecoy neguwog bopi pexijekov. Nefoba. Hotas jeyerab hib. Rilusinitabeyum nunitiru" ascii
      $s11 = "hohehalifacomuzigakemazonotacidi wimumofobuponetesu yakafif codizokubuguwe" fullword ascii
      $s12 = "@GetViceVersa@12" fullword ascii
      $s13 = "m tavibayic. Wuh. Yaya zalozaxudapibon gegeta. Joxelezasivujit huhekolotecic. Pekisaxodikozu penusukigas witexewenebonow. Yizore" ascii
      $s14 = "@GetSecondsVice@0" fullword ascii
      $s15 = "! 777777777777" fullword ascii /* hex encoded string 'wwwwww' */
      $s16 = "Hojufih wuz coyur codo gene*Yoz jeyimaboxax tokaluk mosovu madeterorux[Fif ginariti xekizuko hefuk sowaruhi fiduzanoco yihe johu" wide
      $s17 = "dddddddddddddde" ascii
      $s18 = "nagodusoxacohusunasuranogub" fullword ascii
      $s19 = "wsrsqvs" fullword ascii
      $s20 = "vaxohuhigicixaxofopuy" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02 {
   meta:
      description = "EXE - file be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02"
   strings:
      $s1 = "godojog.exe" fullword ascii
      $s2 = "C:\\temugev zituwa\\54-zujitihutukoye\\bawatubo.pdb" fullword ascii
      $s3 = "ffffft" fullword ascii /* reversed goodware string 'tfffff' */
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "Xuhey sezezag husegux hihorujo fetoxupaxanizi. Tokopipifuk gibojobupubiga xibimenuwuc. Tumize yet. Hiyazipi mibuwiv bibetepepate" ascii
      $s6 = "DD!!!!!!!" fullword ascii
      $s7 = "kogzmuafoke.exu" fullword wide
      $s8 = " constructor or from DllMain." fullword ascii
      $s9 = " bafolezecubeb riyujuboxosipi. Tutufevaw gakuyulecoy neguwog bopi pexijekov. Nefoba. Hotas jeyerab hib. Rilusinitabeyum nunitiru" ascii
      $s10 = "hohehalifacomuzigakemazonotacidi wimumofobuponetesu yakafif codizokubuguwe" fullword ascii
      $s11 = "@GetViceVersa@12" fullword ascii
      $s12 = "m tavibayic. Wuh. Yaya zalozaxudapibon gegeta. Joxelezasivujit huhekolotecic. Pekisaxodikozu penusukigas witexewenebonow. Yizore" ascii
      $s13 = "@GetSecondsVice@0" fullword ascii
      $s14 = "Hojufih wuz coyur codo gene*Yoz jeyimaboxax tokaluk mosovu madeterorux[Fif ginariti xekizuko hefuk sowaruhi fiduzanoco yihe johu" wide
      $s15 = "dddddddddddddde" ascii
      $s16 = "nagodusoxacohusunasuranogub" fullword ascii
      $s17 = "wsrsqvs" fullword ascii
      $s18 = "vaxohuhigicixaxofopuy" fullword ascii
      $s19 = "ddddddddde" ascii
      $s20 = "zukucesufofebuherozinigel" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6 {
   meta:
      description = "EXE - file 22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6"
   strings:
      $s1 = "9 :):;:F:S:\\:z:" fullword ascii
      $s2 = ":%:A:`:" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "585A5[5" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "?!?&?2?7?C?H?T?Y?e?j?v?{?" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "_^ZY[]" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "SQRVW3" fullword ascii
      $s7 = "B<6@OK" fullword ascii
      $s8 = "8&8@8^8i8~8" fullword ascii
      $s9 = ">eL. j0*" fullword ascii
      $s10 = "3C3J3Q3X3" fullword ascii
      $s11 = ";><^<y<" fullword ascii
      $s12 = "4E5L5S5Z5" fullword ascii
      $s13 = "4I5V5f5p5" fullword ascii
      $s14 = "0$0B0I0P0W0" fullword ascii
      $s15 = "555O5X5\"656?6,7?7`7v7" fullword ascii
      $s16 = "909?9W9m9" fullword ascii
      $s17 = "6)6;6h6z6" fullword ascii
      $s18 = ":+:S:q:" fullword ascii
      $s19 = "1#1O1U1[1i1" fullword ascii
      $s20 = "3!3*333N3u3~3" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984 {
   meta:
      description = "EXE - file 7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984"
   strings:
      $s1 = "9 :):;:F:S:\\:z:" fullword ascii
      $s2 = ":%:A:`:" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "585A5[5" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "?!?&?2?7?C?H?T?Y?e?j?v?{?" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "56aa185e0ae34568a72a9fd88e0337b8" ascii
      $s6 = "_^ZY[]" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "SQRVW3" fullword ascii
      $s8 = "B<6@OK" fullword ascii
      $s9 = "8&8@8^8i8~8" fullword ascii
      $s10 = ">eL. j0*" fullword ascii
      $s11 = "3C3J3Q3X3" fullword ascii
      $s12 = ";><^<y<" fullword ascii
      $s13 = "4E5L5S5Z5" fullword ascii
      $s14 = "4I5V5f5p5" fullword ascii
      $s15 = "0$0B0I0P0W0" fullword ascii
      $s16 = "555O5X5\"656?6,7?7`7v7" fullword ascii
      $s17 = "909?9W9m9" fullword ascii
      $s18 = "6)6;6h6z6" fullword ascii
      $s19 = ":+:S:q:" fullword ascii
      $s20 = "1#1O1U1[1i1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_84d7f98350c50be6f36ffac192a8fa44b63b1378f4ae648fa092af7d210b91b9 {
   meta:
      description = "EXE - file 84d7f98350c50be6f36ffac192a8fa44b63b1378f4ae648fa092af7d210b91b9.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "84d7f98350c50be6f36ffac192a8fa44b63b1378f4ae648fa092af7d210b91b9"
   strings:
      $s1 = "eBuser32.dll" fullword ascii
      $s2 = "* U|^=" fullword ascii
      $s3 = "* Xf>ct4j" fullword ascii
      $s4 = "* k|Q`" fullword ascii
      $s5 = "* ~pc.I" fullword ascii
      $s6 = "* bQR\"," fullword ascii
      $s7 = "* PrRO" fullword ascii
      $s8 = " 7tBNM@^+ " fullword ascii
      $s9 = "Gqljnbcf" fullword ascii
      $s10 = " FtpH$" fullword ascii
      $s11 = "S! -($h" fullword ascii
      $s12 = "f -?d>YT" fullword ascii
      $s13 = "<X /gw" fullword ascii
      $s14 = " -\"=/gSj" fullword ascii
      $s15 = " A* d]" fullword ascii
      $s16 = " v- c}" fullword ascii
      $s17 = "g[j8* " fullword ascii
      $s18 = "xDv- z" fullword ascii
      $s19 = "h6 /Sm" fullword ascii
      $s20 = " -wo6Wr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_0b350577e82bb333a55a1ee5977a04b14ad3c274c3f8ee374c0329c309df0e2a {
   meta:
      description = "EXE - file 0b350577e82bb333a55a1ee5977a04b14ad3c274c3f8ee374c0329c309df0e2a.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "0b350577e82bb333a55a1ee5977a04b14ad3c274c3f8ee374c0329c309df0e2a"
   strings:
      $s1 = "PSRRRQV" fullword ascii
      $s2 = "RWWWWWWWSW" fullword ascii
      $s3 = "SSSSWSV" fullword ascii
      $s4 = "<0POSTt" fullword ascii
      $s5 = "QHRich9" fullword ascii
      $s6 = "IvoX=t:" fullword ascii
      $s7 = "pCyay m!)[>" fullword ascii
      $s8 = "XSVWj4" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "Cebb5lO" fullword ascii
      $s10 = "Sudac^O" fullword ascii
      $s11 = "RSSSSSSS" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "OgGilJ%|" fullword ascii
      $s13 = "IRdNM_F,T" fullword ascii
      $s14 = "(v.ZHc" fullword ascii
      $s15 = "SRRRQV" fullword ascii
      $s16 = "PSWQVR" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "\\hB_HtMR" fullword ascii
      $s18 = "SSSPQV" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "\\?MDaR" fullword ascii
      $s20 = "$vi3\"2W" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0_771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d_0 {
   meta:
      description = "EXE - from files c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0.exe, 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe, e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0"
      hash2 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
      hash3 = "e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df"
   strings:
      $s1 = "PERMAINAN SELESAI !!!" fullword wide
      $s2 = "SELAMAT !!!" fullword wide
      $s3 = "!System.Windows.Forms.AxHost+State" fullword ascii
      $s4 = "OTHELLO .NET" fullword wide
      $s5 = "\\CLUE.txt" fullword wide
      $s6 = "bintang" fullword wide
      $s7 = "Maryhay.mid" fullword wide
      $s8 = "$STATIC$eatGhosts_Tick$20211C1280E9$count" fullword ascii
      $s9 = "eatGhosts" fullword ascii
      $s10 = "\\TK.txt" fullword wide
      $s11 = "bgbottom" fullword wide
      $s12 = "BmYMK)- " fullword ascii
      $s13 = "eggbreak" fullword wide
      $s14 = "majalah" fullword wide
      $s15 = "kalender" fullword wide
      $s16 = "\\shot.wav" fullword wide
      $s17 = "\\lose.wav" fullword wide
      $s18 = "\\oink.wav" fullword wide
      $s19 = "PacClosedUp" fullword wide
      $s20 = "PacClosedRight" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0_e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e7_1 {
   meta:
      description = "EXE - from files c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0.exe, e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0"
      hash2 = "e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxHost+State, System.Windo" ascii
      $x4 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii
      $s5 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii
      $s6 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=n" ascii
      $s7 = "ributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s8 = "ws.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADP" fullword ascii
      $s9 = " System.Globalization.CompareInfo" fullword ascii
      $s10 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s11 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii
      $s12 = " System.Globalization.SortVersion" fullword ascii
      $s13 = "typemdt" fullword ascii
      $s14 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" fullword ascii
      $s15 = " System.Globalization.CultureInfo" fullword ascii
      $s16 = "progressBar1.Modifiers" fullword wide
      $s17 = "progressBar1.Locked" fullword wide
      $s18 = "MD5CryptoServiceProvider" fullword ascii /* Goodware String - occured 50 times */
      $s19 = "CipherMode" fullword ascii /* Goodware String - occured 54 times */
      $s20 = "CreateDecryptor" fullword ascii /* Goodware String - occured 76 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6_7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b43199_2 {
   meta:
      description = "EXE - from files 22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6.exe, 7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6"
      hash2 = "7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984"
   strings:
      $s1 = "9 :):;:F:S:\\:z:" fullword ascii
      $s2 = ":%:A:`:" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "585A5[5" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "?!?&?2?7?C?H?T?Y?e?j?v?{?" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "_^ZY[]" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "SQRVW3" fullword ascii
      $s7 = "B<6@OK" fullword ascii
      $s8 = "8&8@8^8i8~8" fullword ascii
      $s9 = ">eL. j0*" fullword ascii
      $s10 = "3C3J3Q3X3" fullword ascii
      $s11 = ";><^<y<" fullword ascii
      $s12 = "4E5L5S5Z5" fullword ascii
      $s13 = "4I5V5f5p5" fullword ascii
      $s14 = "0$0B0I0P0W0" fullword ascii
      $s15 = "555O5X5\"656?6,7?7`7v7" fullword ascii
      $s16 = "909?9W9m9" fullword ascii
      $s17 = "6)6;6h6z6" fullword ascii
      $s18 = ":+:S:q:" fullword ascii
      $s19 = "1#1O1U1[1i1" fullword ascii
      $s20 = "3!3*333N3u3~3" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5_be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6_3 {
   meta:
      description = "EXE - from files 9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5.exe, be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5"
      hash2 = "be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02"
   strings:
      $s1 = "ffffft" fullword ascii /* reversed goodware string 'tfffff' */
      $s2 = "Xuhey sezezag husegux hihorujo fetoxupaxanizi. Tokopipifuk gibojobupubiga xibimenuwuc. Tumize yet. Hiyazipi mibuwiv bibetepepate" ascii
      $s3 = "DD!!!!!!!" fullword ascii
      $s4 = "kogzmuafoke.exu" fullword wide
      $s5 = " bafolezecubeb riyujuboxosipi. Tutufevaw gakuyulecoy neguwog bopi pexijekov. Nefoba. Hotas jeyerab hib. Rilusinitabeyum nunitiru" ascii
      $s6 = "hohehalifacomuzigakemazonotacidi wimumofobuponetesu yakafif codizokubuguwe" fullword ascii
      $s7 = "@GetViceVersa@12" fullword ascii
      $s8 = "m tavibayic. Wuh. Yaya zalozaxudapibon gegeta. Joxelezasivujit huhekolotecic. Pekisaxodikozu penusukigas witexewenebonow. Yizore" ascii
      $s9 = "@GetSecondsVice@0" fullword ascii
      $s10 = "Hojufih wuz coyur codo gene*Yoz jeyimaboxax tokaluk mosovu madeterorux[Fif ginariti xekizuko hefuk sowaruhi fiduzanoco yihe johu" wide
      $s11 = "dddddddddddddde" ascii
      $s12 = "nagodusoxacohusunasuranogub" fullword ascii
      $s13 = "wsrsqvs" fullword ascii
      $s14 = "vaxohuhigicixaxofopuy" fullword ascii
      $s15 = "ddddddddde" ascii
      $s16 = "zukucesufofebuherozinigel" fullword ascii
      $s17 = "dddddddde" ascii
      $s18 = "wegocefusoboyok" fullword ascii
      $s19 = "gavesuhemapusidil" fullword wide
      $s20 = "hilufihojibos" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1_8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a0_4 {
   meta:
      description = "EXE - from files fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1.exe, 8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c.exe, b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1"
      hash2 = "8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c"
      hash3 = "b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d"
   strings:
      $s1 = "Jun lehekamaxovef wexiz lazirele. Gubuhilowukuyuh nirusikif. Puza luvelolaragif liwev zozozemujex. Xikil ruyesosaxag yiwamu hipe" ascii
      $s2 = "LetucogdRopuhotihu vazopipehet tabubotocenur codosubop paxejiforifirib xewi hiniw jedemuv zemafeginuhune has" fullword wide
      $s3 = "Cup zuxezuvacivek musi gewuposawakow tuyu. Dazuronicepotok lepasasi kulopad jimu potobezedabaxam. Yafifosicakax gelojiv laleruci" ascii
      $s4 = "kogzmuahoke.exi" fullword wide
      $s5 = "fa bevi rulejijakug depaciriyugovis sep. Vojigexesuwah zimilefave lerog pukekisuyizuk xoko. Nusirabapuy josamak zedeme tafeyehor" ascii
      $s6 = "asasiyovih gabof bopum. Pehaxolalufinak leniwuku. Tig civuhiz sozefi. Laxilazufijibac. Tav. Zej rafeheyecij xopimo yupazokidezex" ascii
      $s7 = "huhe gahonigunuroxag zaharifuyilirid. Logozixivetud. Guzukovino sucuviv. Fimem viraxayavot bizabaluz juhotulirubari. Wegogevoj f" ascii
      $s8 = "ujo hupog mapaf peta nabucileja. Nowohap goveyemogay sovuk. Zahebip wimi gapibuwokona juzitujimola fanakexanazajov. Nalo sasawix" ascii
      $s9 = "paw tal. Fedegocunozir bezosibunizi sohahakunis vofixi luh. Doku dutobemal. Pune pumamiwi buniruz. Pururoyes mamalozupeci meyeh " ascii
      $s10 = "uvexak yap. Filabusin vebicosuluxijah fesolamopavoxu. Bipifadojukujow bagetulumuso xigagobokiya. Wojolalor hir rewa deredile won" ascii
      $s11 = "fofaji lobu sacorubuka xuvotilut. Gefo. Yotipasopojaxu. Rocopomadod yesinobununa. Tavidezedoxiga soyowu cezumakimega halogokehax" ascii
      $s12 = "jego. Hetofedac. Kut sulanonidij. Cedereraxugaw heyehimodoretu. Ginipafaduj. Jarotak femu juhisebomesu fibegakogico nododu. Jojo" ascii
      $s13 = "fexajewu. Zozininuhiludu wekobisujehipi wiwusozositemo. Sasasefilo gisozelateben hetukeyesatura. Cajohujad nuxez fugoyigimoyilu " ascii
      $s14 = "dojatatenek" fullword ascii
      $s15 = "gojolazodicufevaxasirenam" fullword ascii
      $s16 = "riwopeninifoxucekewenepe" fullword ascii
      $s17 = "Zazulejumosubo fed nasecuzakamec yuvoxahos sedokeyovocecov" fullword ascii
      $s18 = "pava zoyeyayede. Hofibinowox tehigiwile lizug vozu cegizicineba. Yodayikelijeber xekefi. Bejelug pokubadur baduyege pac hiri. Wo" ascii
      $s19 = "eyomitaful yec molekugejijariz. Tarituviwer. Cekigozupo. Lelaxibel koduturizo marafuraceroyuj sizehawufi. Tek. Xowusefaruno kuga" ascii
      $s20 = "LOMELIBEGOCIROVURILOHIYESAD" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1_8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a0_5 {
   meta:
      description = "EXE - from files fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1.exe, 8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c.exe, b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d.exe, a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1"
      hash2 = "8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c"
      hash3 = "b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d"
      hash4 = "a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414"
   strings:
      $s1 = "Copyrighz (C) 2020, vodkagats" fullword wide
      $s2 = "G09_(u" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "YYhh#@" fullword ascii
      $s4 = "t hX#@" fullword ascii
      $s5 = "u&h@\"@" fullword ascii
      $s6 = "t$ht\"@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f_b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb_6 {
   meta:
      description = "EXE - from files 368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f.exe, b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13.exe, ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f"
      hash2 = "b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13"
      hash3 = "ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s3 = "operator co_await" fullword ascii
      $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s6 = "__swift_1" fullword ascii
      $s7 = "__swift_2" fullword ascii
      $s8 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s9 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "      <requestedPrivileges>" fullword ascii
      $s11 = "api-ms-" fullword wide
      $s12 = "ext-ms-" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8_c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a7_7 {
   meta:
      description = "EXE - from files a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8.exe, c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0.exe, 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe, e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df.exe, 4650f39d7dbcca87b71d772a850f8cd91c1279e8081ce9de9bcc97310641e564.exe, 9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8"
      hash2 = "c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0"
      hash3 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
      hash4 = "e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df"
      hash5 = "4650f39d7dbcca87b71d772a850f8cd91c1279e8081ce9de9bcc97310641e564"
      hash6 = "9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5"
   strings:
      $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s3 = "16.0.0.0" fullword ascii
      $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "untimeResourceSet" fullword ascii
      $s6 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s7 = "b77a5c561934e089" ascii /* Goodware String - occured 2 times */
      $s8 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
      $s9 = "b03f5f7f11d50a3a" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f_fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13d_8 {
   meta:
      description = "EXE - from files 368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f.exe, fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1.exe, 8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c.exe, b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d.exe, b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13.exe, 9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5.exe, ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d.exe, a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414.exe, be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "368b6977de3879f6399b1199a740aea7457cbdc53aac44823d3d3f704fac1d7f"
      hash2 = "fd2af8d36668693ee87be023b563e3bdf9aa3bd0cb75aa3bf0ab0fb13da9cff1"
      hash3 = "8a2365761853f027da2895b4f4a24f7f988255b00b837fe6caa6e8a5a067e99c"
      hash4 = "b1f38f5cd07a1eb5ba0af0be636be2d3414e54c51d673044a3626b257249f39d"
      hash5 = "b0831c1f23202cd936470a346b97d37f39a27a364db9a15f3d2d5d33bb53de13"
      hash6 = "9735f688e3338582266589c582a22bdac2a0accbc423225ffb5d792801d0d1a5"
      hash7 = "ed0e89048233a80fdebcbae8982ff3120c323e78172eccbd893383f289c6ed3d"
      hash8 = "a26803d8e53b6a759a71245e8b973ac9c8eaf9ebfe7356d7e4b4cd5e03bb5414"
      hash9 = "be8b6e6da114bdcb1a060a06ace28d03550173a4a719b4704510e65ee6e47f02"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Base Class Descriptor at (" fullword ascii
      $s3 = " Class Hierarchy Descriptor'" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8_c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a7_9 {
   meta:
      description = "EXE - from files a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8.exe, c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0.exe, 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe, e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df.exe, 9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8"
      hash2 = "c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0"
      hash3 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
      hash4 = "e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df"
      hash5 = "9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s3 = "MyTemplate" fullword ascii
      $s4 = "My.Computer" fullword ascii
      $s5 = "System.Windows.Forms.Form" fullword ascii
      $s6 = "My.WebServices" fullword ascii
      $s7 = "CompareString" fullword ascii /* Goodware String - occured 28 times */
      $s8 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 98 times */
      $s9 = "GetResourceString" fullword ascii /* Goodware String - occured 124 times */
      $s10 = "Hashtable" fullword ascii /* Goodware String - occured 645 times */
      $s11 = "Create__Instance__" fullword ascii
      $s12 = "My.MyProject.Forms" fullword ascii
      $s13 = "Dispose__Instance__" fullword ascii
      $s14 = "My.User" fullword ascii
      $s15 = "My.Settings" fullword ascii
      $s16 = "Remove" fullword ascii /* Goodware String - occured 1247 times */
      $s17 = "My.Forms" fullword ascii
      $s18 = "My.Application" fullword ascii
      $s19 = "LateGet" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0_771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d_10 {
   meta:
      description = "EXE - from files c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0.exe, 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe, e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df.exe, 9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "c7e2522e9de0314bf88eaf726500e09abcaad24a53c6d9fb7848e447a712b7e0"
      hash2 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
      hash3 = "e830ffa639964fa44135b16ac5a9abb98052bcace0f2a8efc6236fd5e74030df"
      hash4 = "9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5"
   strings:
      $s1 = "ThreadPool.Light" fullword wide
      $s2 = "PictureBox1" fullword wide
      $s3 = "MySettingsProperty" fullword ascii
      $s4 = "MySettings" fullword ascii
      $s5 = "Property can only be set to Nothing" fullword wide /* Goodware String - occured 1 times */
      $s6 = "Bauhaus 93" fullword wide
      $s7 = "Label3" fullword wide
      $s8 = "Label4" fullword wide
      $s9 = "Label5" fullword wide
      $s10 = "Timer2" fullword ascii /* Goodware String - occured 4 times */
      $s11 = "Label2" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792_9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de469_11 {
   meta:
      description = "EXE - from files 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe, 9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
      hash2 = "9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5"
   strings:
      $s1 = "othello" fullword ascii
      $s2 = "get_ParamArray0" fullword ascii
      $s3 = "get_PictureBox1" fullword ascii
      $s4 = "DialogsLib" fullword ascii
      $s5 = "get_ArrayAttribute" fullword ascii
      $s6 = "ThreadSafeObjectProvider`1" fullword ascii
      $s7 = "MyWebServices" fullword ascii
      $s8 = "get_Label3" fullword ascii
      $s9 = "get_Label4" fullword ascii
      $s10 = "get_Label2" fullword ascii
      $s11 = "get_Label5" fullword ascii
      $s12 = "get_Timer2" fullword ascii
      $s13 = "get_Timer1" fullword ascii
      $s14 = "Timer2_Tick" fullword ascii
      $s15 = "set_PictureBox1" fullword ascii
      $s16 = "Timer1_Tick" fullword ascii
      $s17 = "MyForms" fullword ascii
      $s18 = "set_Button1" fullword ascii
      $s19 = "MyProject" fullword ascii
      $s20 = "get_Button1" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8_771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d_12 {
   meta:
      description = "EXE - from files a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8.exe, 771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792.exe, 9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5.exe"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "a09b27f0e56a772894ce2213d62e8411f163f98d9da988f2b8e0e57e591889c8"
      hash2 = "771bd71228626d14e109d6f2153aa3935e02f33b1593fdda42e99f3c0d39c792"
      hash3 = "9b9e02a40d66398a2d29e0f0b89e83e092180ee0ebed9b1c5ca31de4697954c5"
   strings:
      $s1 = "m_MyWebServicesObjectProvider" fullword ascii
      $s2 = "m_ComputerObjectProvider" fullword ascii
      $s3 = "m_UserObjectProvider" fullword ascii
      $s4 = "m_ThreadStaticValue" fullword ascii
      $s5 = "m_AppObjectProvider" fullword ascii
      $s6 = "m_MyFormsObjectProvider" fullword ascii
      $s7 = "m_FormBeingCreated" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

