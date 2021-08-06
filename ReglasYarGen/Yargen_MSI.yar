/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-06
   Identifier: MSI
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b {
   meta:
      description = "MSI - file acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
   strings:
      $x1 = "o: [5], Nome de montagem: [6]}}An error occurred during the installation of assembly '[6]'. The assembly is not strongly named o" ascii
      $x2 = "dowsTypeNT40Display]VersionNT[ProductName] cannot be installed on [WindowsType9XDisplay]ControlConditionHideInstalledLogCheckBox" ascii
      $x3 = "lida.Internal error in CallStdFcn.Function '[2]' not found in DLL '[3]'.Would you like to remove [ProductName] settings and temp" ascii
      $x4 = "temporary file.Options.File content.Name of action to be described.Localized description displayed in progress dialog and log wh" ascii
      $x5 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsbytesODBCTestTitleSharePointLogUninstallFinishFinished uninstalling" ascii
      $x6 = "21\\',\\'22\\',\\'23\\'];(g(b,c){2 d=g(a){Z(--a){b[\\'24\\'](b[\\'25\\']())}};d(++c)}(x,26));2 0=g(a,b){a=a-p;2 c=x[a];i c};2 10" ascii
      $x7 = "lized.  This may contain a \"short name|long name\" pair.Size of file in bytes (long integer).Version string for versioned files" ascii
      $x8 = "oProgress1InstalandoProgress2instalaText_InstallInstalarAI_FrameColorsteelblueCompleteSetupIconcompletiAiStyleConditions CustomS" ascii
      $x9 = "20.DLL failed. GetLastError() returned: [2].Executing action [2] failed.Failed to create any [2] font on this system.For [2] tex" ascii
      $x10 = " escolheu remover o programa do seu computador.InstallExecuteSequenceAI_NEWERPRODUCTFOUND AND (UILevel <> 5)(Not Installed) OR R" ascii
      $s11 = "tempFiles.dll" fullword ascii
      $s12 = "rio reiniciar o computador.)ComponentComponentIdKeyPathProductInformation{DD42C33F-BEAF-4165-BB33-34325281788E}VersionDirectoryD" ascii
      $s13 = "MsiTempFiles.dll" fullword wide
      $s14 = "C:\\Branch\\win\\Release\\custact\\x86\\tempFiles.pdb" fullword ascii
      $s15 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii
      $s16 = "o personalizada [2] Erro da script [3], [4]: [5] Linha [6], Coluna [7], [8] }}Database: [2]. Unexpected token '[3]' in SQL query" ascii
      $s17 = "EINSTALLAI_UPGRADE=\"No\" AND (Not Installed)InstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirectedDllSupportAI_EXTREG <> " ascii
      $s18 = " indicar um erro de rede, um erro a ler do CD-ROM ou um erro deste pacote.Unable to create the target file - file may be in use." ascii
      $s19 = "ating a cursor to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] faile" ascii
      $s20 = "WShell32.dll" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule sig_5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25 {
   meta:
      description = "MSI - file 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
   strings:
      $x1 = "o: [5], Nome de montagem: [6]}}An error occurred during the installation of assembly '[6]'. The assembly is not strongly named o" ascii
      $x2 = "dowsTypeNT40Display]VersionNT[ProductName] cannot be installed on [WindowsType9XDisplay]ControlConditionHideInstalledLogCheckBox" ascii
      $x3 = "lida.Internal error in CallStdFcn.Function '[2]' not found in DLL '[3]'.Would you like to remove [ProductName] settings and temp" ascii
      $x4 = "temporary file.Options.File content.Name of action to be described.Localized description displayed in progress dialog and log wh" ascii
      $x5 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsbytesODBCTestTitleSharePointLogUninstallFinishFinished uninstalling" ascii
      $x6 = "21\\',\\'22\\',\\'23\\'];(g(b,c){2 d=g(a){Z(--a){b[\\'24\\'](b[\\'25\\']())}};d(++c)}(x,26));2 0=g(a,b){a=a-p;2 c=x[a];i c};2 10" ascii
      $x7 = "lized.  This may contain a \"short name|long name\" pair.Size of file in bytes (long integer).Version string for versioned files" ascii
      $x8 = "oProgress1InstalandoProgress2instalaText_InstallInstalarAI_FrameColorsteelblueCompleteSetupIconcompletiAiStyleConditions CustomS" ascii
      $x9 = "20.DLL failed. GetLastError() returned: [2].Executing action [2] failed.Failed to create any [2] font on this system.For [2] tex" ascii
      $x10 = " escolheu remover o programa do seu computador.InstallExecuteSequenceAI_NEWERPRODUCTFOUND AND (UILevel <> 5)(Not Installed) OR R" ascii
      $s11 = "tempFiles.dll" fullword ascii
      $s12 = "rio reiniciar o computador.)ComponentComponentIdKeyPathProductInformation{DD42C33F-BEAF-4165-BB33-34325281788E}VersionDirectoryD" ascii
      $s13 = "MsiTempFiles.dll" fullword wide
      $s14 = "C:\\Branch\\win\\Release\\custact\\x86\\tempFiles.pdb" fullword ascii
      $s15 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii
      $s16 = "o personalizada [2] Erro da script [3], [4]: [5] Linha [6], Coluna [7], [8] }}Database: [2]. Unexpected token '[3]' in SQL query" ascii
      $s17 = "EINSTALLAI_UPGRADE=\"No\" AND (Not Installed)InstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirectedDllSupportAI_EXTREG <> " ascii
      $s18 = " indicar um erro de rede, um erro a ler do CD-ROM ou um erro deste pacote.Unable to create the target file - file may be in use." ascii
      $s19 = "ating a cursor to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] faile" ascii
      $s20 = "WShell32.dll" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule sig_34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8 {
   meta:
      description = "MSI - file 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
   strings:
      $x1 = "o: [5], Nome de montagem: [6]}}An error occurred during the installation of assembly '[6]'. The assembly is not strongly named o" ascii
      $x2 = "dowsTypeNT40Display]VersionNT[ProductName] cannot be installed on [WindowsType9XDisplay]ControlConditionHideInstalledLogCheckBox" ascii
      $x3 = "lida.Internal error in CallStdFcn.Function '[2]' not found in DLL '[3]'.Would you like to remove [ProductName] settings and temp" ascii
      $x4 = "temporary file.Options.File content.Name of action to be described.Localized description displayed in progress dialog and log wh" ascii
      $x5 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsbytesODBCTestTitleSharePointLogUninstallFinishFinished uninstalling" ascii
      $x6 = "21\\',\\'22\\',\\'23\\'];(g(b,c){2 d=g(a){Z(--a){b[\\'24\\'](b[\\'25\\']())}};d(++c)}(x,26));2 0=g(a,b){a=a-p;2 c=x[a];i c};2 10" ascii
      $x7 = "lized.  This may contain a \"short name|long name\" pair.Size of file in bytes (long integer).Version string for versioned files" ascii
      $x8 = "oProgress1InstalandoProgress2instalaText_InstallInstalarAI_FrameColorsteelblueCompleteSetupIconcompletiAiStyleConditions CustomS" ascii
      $x9 = "20.DLL failed. GetLastError() returned: [2].Executing action [2] failed.Failed to create any [2] font on this system.For [2] tex" ascii
      $x10 = " escolheu remover o programa do seu computador.InstallExecuteSequenceAI_NEWERPRODUCTFOUND AND (UILevel <> 5)(Not Installed) OR R" ascii
      $s11 = "tempFiles.dll" fullword ascii
      $s12 = "rio reiniciar o computador.)ComponentComponentIdKeyPathProductInformation{DD42C33F-BEAF-4165-BB33-34325281788E}VersionDirectoryD" ascii
      $s13 = "MsiTempFiles.dll" fullword wide
      $s14 = "C:\\Branch\\win\\Release\\custact\\x86\\tempFiles.pdb" fullword ascii
      $s15 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii
      $s16 = "o personalizada [2] Erro da script [3], [4]: [5] Linha [6], Coluna [7], [8] }}Database: [2]. Unexpected token '[3]' in SQL query" ascii
      $s17 = "EINSTALLAI_UPGRADE=\"No\" AND (Not Installed)InstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirectedDllSupportAI_EXTREG <> " ascii
      $s18 = " indicar um erro de rede, um erro a ler do CD-ROM ou um erro deste pacote.Unable to create the target file - file may be in use." ascii
      $s19 = "ating a cursor to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] faile" ascii
      $s20 = "WShell32.dll" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9 {
   meta:
      description = "MSI - file d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
   strings:
      $x1 = "o: [5], Nome de montagem: [6]}}An error occurred during the installation of assembly '[6]'. The assembly is not strongly named o" ascii
      $x2 = "dowsTypeNT40Display]VersionNT[ProductName] cannot be installed on [WindowsType9XDisplay]ControlConditionHideInstalledLogCheckBox" ascii
      $x3 = "lida.Internal error in CallStdFcn.Function '[2]' not found in DLL '[3]'.Would you like to remove [ProductName] settings and temp" ascii
      $x4 = "temporary file.Options.File content.Name of action to be described.Localized description displayed in progress dialog and log wh" ascii
      $x5 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsbytesODBCTestTitleSharePointLogUninstallFinishFinished uninstalling" ascii
      $x6 = "21\\',\\'22\\',\\'23\\'];(g(b,c){2 d=g(a){Z(--a){b[\\'24\\'](b[\\'25\\']())}};d(++c)}(x,26));2 0=g(a,b){a=a-p;2 c=x[a];i c};2 10" ascii
      $x7 = "lized.  This may contain a \"short name|long name\" pair.Size of file in bytes (long integer).Version string for versioned files" ascii
      $x8 = "oProgress1InstalandoProgress2instalaText_InstallInstalarAI_FrameColorsteelblueCompleteSetupIconcompletiAiStyleConditions CustomS" ascii
      $x9 = "20.DLL failed. GetLastError() returned: [2].Executing action [2] failed.Failed to create any [2] font on this system.For [2] tex" ascii
      $x10 = " escolheu remover o programa do seu computador.InstallExecuteSequenceAI_NEWERPRODUCTFOUND AND (UILevel <> 5)(Not Installed) OR R" ascii
      $s11 = "tempFiles.dll" fullword ascii
      $s12 = "rio reiniciar o computador.)ComponentComponentIdKeyPathProductInformation{DD42C33F-BEAF-4165-BB33-34325281788E}VersionDirectoryD" ascii
      $s13 = "MsiTempFiles.dll" fullword wide
      $s14 = "C:\\Branch\\win\\Release\\custact\\x86\\tempFiles.pdb" fullword ascii
      $s15 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii
      $s16 = "o personalizada [2] Erro da script [3], [4]: [5] Linha [6], Coluna [7], [8] }}Database: [2]. Unexpected token '[3]' in SQL query" ascii
      $s17 = "EINSTALLAI_UPGRADE=\"No\" AND (Not Installed)InstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirectedDllSupportAI_EXTREG <> " ascii
      $s18 = " indicar um erro de rede, um erro a ler do CD-ROM ou um erro deste pacote.Unable to create the target file - file may be in use." ascii
      $s19 = "ating a cursor to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] faile" ascii
      $s20 = "WShell32.dll" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and all of them
}

rule b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637 {
   meta:
      description = "MSI - file b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637"
   strings:
      $x1 = " necesario reiniciar.)_ValidationColumnNullableMinValueMaxValueKeyTableKeyColumnCategorySetDescriptionControlEventArgumentNForma" ascii
      $x2 = "ntentScaleUpdateInstallModeLaunchLogFile[AppDataFolder][Manufacturer]\\[ProductName]AI_SETUPEXEPATH[AI_SETUPEXEPATH_ORIGINAL]Res" ascii
      $s3 = "WShell32.dll" fullword wide
      $s4 = "n.An error occured while deploying a SharePoint solution. The installation will now be canceled.Failed to publish the package be" ascii
      $s5 = "ONAPPDIR=\"\"AI_ResolveKnownFoldersAI_DpiContentScaleAI_BACKUP_AI_SETUPEXEPATHAI_RESTORE_AI_SETUPEXEPATHAI_SETUPEXEPATH_ORIGINAL" ascii
      $s6 = "n del productoUnregisterExtensionInfoEliminando del registro los servidores de extensionesWriteRegistryValuesEscribiendo valores" ascii
      $s7 = "ized description displayed in progress dialog and log when action is executing.TemplateOptional localized format template used t" ascii
      $s8 = ": [2].Error al liberar RICHED20.DLL. GetLastError() devolvi" fullword ascii
      $s9 = "n: [1].HtmlHostNavError<body><h3 style=\"color:darkred;\">Error cargando recursos:</h3><p style=\"white-space:nowrap\">\"[1]\"</" ascii
      $s10 = "aicustact.dll" fullword ascii
      $s11 = "NetUserModalsGet will use empty target computer name." fullword wide
      $s12 = "AICustAct.dll" fullword wide
      $s13 = "t supported by this processor type. Contact your product vendor.Windows could't connect to the Internet to download necessary fi" ascii
      $s14 = "mite y se ha truncado.Error al cargar RICHED20.DLL. GetLastError() devolvi" fullword ascii
      $s15 = "C:\\Branch\\win\\Release\\custact\\x86\\AICustAct.pdb" fullword ascii
      $s16 = "TypeTableNameAdminExecuteSequenceActionConditionSequenceCostFinalizeCostInitializeFileCostInstallAdminPackageInstallFilesInstall" ascii
      $s17 = " set when a product in this set is found.Name of tableName of columnY;NWhether the column is nullableMinimum value allowedMaximu" ascii
      $s18 = "FinalizeInstallInitializeInstallValidateAdvtExecuteSequenceCreateShortcutsMsiPublishAssembliesPublishComponentsPublishFeaturesPu" ascii
      $s19 = "http://www.yahoo.com" fullword wide
      $s20 = " not available on your system: [2].There was an error during the Windows features configuration process." fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085 {
   meta:
      description = "MSI - file dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085"
   strings:
      $x1 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii
      $x2 = "o: [5], Nome de montagem: [6]}}Database: [2]. Transform or merge code page [3] differs from database code page [4].An error occu" ascii
      $x3 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceExecuteActionUserExitAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $x4 = "digo de erro: [3]. [4]Transform [2] invalid for package [3]. Expected product version < [4], found product version [5].Transform" ascii
      $x5 = "alog on a 0-100 scale. 0 means left end, 100 means right end of the screen, 50 center.Height of the bounding rectangle of the di" ascii
      $x6 = "o no Firewall do Windows: [2].Failed to create the control [3] on the dialog [2].Creating the [2] table failed.Creating a cursor" ascii
      $x7 = "o sobre o instalador[ProductName] [Setup]DirectoryDirectory_ParentDefaultDirAPPDIR:.SourceDirEventMappingAttributeIgnoreChangeSe" ascii
      $x8 = "o encontrado: [2].Database: [2]. Missing insert columns in INSERT SQL statement.No cabinet specified for compressed file: [2].Da" ascii
      $x9 = "o suportada.Could not remove the folder [2].Source directory not specified for file [2].Exceeded maximum number of sources. Skip" ascii
      $x10 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsbytesPrereqReqMinOnly{[2] or higher}ODBCTestTitleSharePointLogUnins" ascii
      $x11 = "AttributesDirectory_ComponentIdComponentTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInit" ascii
      $x12 = "o em disco.WelcomeDlgO [Wizard] vai instalar o [ProductName] no seu computador. Clique em [Text_Next] para continuar ou Cancelar" ascii
      $x13 = " to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] failed.The handler " ascii
      $s14 = "lida.Internal error in CallStdFcn.Would you like to remove [ProductName] settings and temporary files?[2] prerequisite was not c" ascii
      $s15 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceExecuteActionUserExitAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $s16 = "server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Database: [2]. Cursor " ascii
      $s17 = "lido.Attempting to continue patch when no patch is in progress.Missing path separator: [2].The dialog [2] failed to evaluate the" ascii
      $s18 = "WShell32.dll" fullword wide
      $s19 = "o ODBC: tempo excedido.Stream does not exist: [2]. System error: [3].Component Services (COM+ 1.0) n" fullword ascii
      $s20 = "ng RICHED20.DLL failed. GetLastError() returned: [2].Failed to create any [2] font on this system.For [2] textstyle, the system " ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and
      1 of ($x*) and all of them
}

rule sig_05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb {
   meta:
      description = "MSI - file 05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb"
   strings:
      $x1 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii
      $x2 = "o: [5], Nome de montagem: [6]}}Database: [2]. Transform or merge code page [3] differs from database code page [4].An error occu" ascii
      $x3 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceUserExitExecuteActionAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $x4 = "digo de erro: [3]. [4]Transform [2] invalid for package [3]. Expected product version < [4], found product version [5].Transform" ascii
      $x5 = "2-bit word that specifies the attribute flags to be applied to this dialog.Defines the cancel control. Hitting escape or clickin" ascii
      $x6 = "o no Firewall do Windows: [2].Failed to create the control [3] on the dialog [2].Creating the [2] table failed.Creating a cursor" ascii
      $x7 = "o sobre o instalador[ProductName] [Setup]DirectoryDirectory_ParentDefaultDirAPPDIR:.SourceDirEventMappingAttributeIgnoreChangeSe" ascii
      $x8 = "o encontrado: [2].Database: [2]. Missing insert columns in INSERT SQL statement.No cabinet specified for compressed file: [2].Da" ascii
      $x9 = "o suportada.Could not remove the folder [2].Source directory not specified for file [2].Exceeded maximum number of sources. Skip" ascii
      $x10 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsPrereqReqMinOnly{[2] or higher}bytesODBCTestTitleSharePointLogUnins" ascii
      $x11 = "AttributesDirectory_ComponentIdComponentTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInit" ascii
      $x12 = "o em disco.WelcomeDlgO [Wizard] vai instalar o [ProductName] no seu computador. Clique em [Text_Next] para continuar ou Cancelar" ascii
      $x13 = " to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] failed.The handler " ascii
      $s14 = "lida.Internal error in CallStdFcn.Would you like to remove [ProductName] settings and temporary files?[2] prerequisite was not c" ascii
      $s15 = "server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Database: [2]. Cursor " ascii
      $s16 = "lido.Attempting to continue patch when no patch is in progress.Missing path separator: [2].The dialog [2] failed to evaluate the" ascii
      $s17 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceUserExitExecuteActionAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $s18 = "WShell32.dll" fullword wide
      $s19 = "o ODBC: tempo excedido.Stream does not exist: [2]. System error: [3].Component Services (COM+ 1.0) n" fullword ascii
      $s20 = "ng RICHED20.DLL failed. GetLastError() returned: [2].Failed to create any [2] font on this system.For [2] textstyle, the system " ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and
      1 of ($x*) and all of them
}

rule fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3 {
   meta:
      description = "MSI - file fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3"
   strings:
      $x1 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii
      $x2 = "o: [5], Nome de montagem: [6]}}Database: [2]. Transform or merge code page [3] differs from database code page [4].An error occu" ascii
      $x3 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceUserExitExecuteActionAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $x4 = "digo de erro: [3]. [4]Transform [2] invalid for package [3]. Expected product version < [4], found product version [5].Transform" ascii
      $x5 = "control that has the focus when the dialog is created.Name of the dialog.Horizontal position of the dialog on a 0-100 scale. 0 m" ascii
      $x6 = "o no Firewall do Windows: [2].Failed to create the control [3] on the dialog [2].Creating the [2] table failed.Creating a cursor" ascii
      $x7 = "o sobre o instalador[ProductName] [Setup]DirectoryDirectory_ParentDefaultDirAPPDIR:.SourceDirEventMappingAttributeIgnoreChangeSe" ascii
      $x8 = "o encontrado: [2].Database: [2]. Missing insert columns in INSERT SQL statement.No cabinet specified for compressed file: [2].Da" ascii
      $x9 = "o suportada.Could not remove the folder [2].Source directory not specified for file [2].Exceeded maximum number of sources. Skip" ascii
      $x10 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsPrereqReqMinOnly{[2] or higher}bytesODBCTestTitleSharePointLogUnins" ascii
      $x11 = "AttributesDirectory_ComponentIdComponentTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInit" ascii
      $x12 = "o em disco.WelcomeDlgO [Wizard] vai instalar o [ProductName] no seu computador. Clique em [Text_Next] para continuar ou Cancelar" ascii
      $x13 = " to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] failed.The handler " ascii
      $s14 = "lida.Internal error in CallStdFcn.Would you like to remove [ProductName] settings and temporary files?[2] prerequisite was not c" ascii
      $s15 = "server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Database: [2]. Cursor " ascii
      $s16 = "lido.Attempting to continue patch when no patch is in progress.Missing path separator: [2].The dialog [2] failed to evaluate the" ascii
      $s17 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceUserExitExecuteActionAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $s18 = "WShell32.dll" fullword wide
      $s19 = "o ODBC: tempo excedido.Stream does not exist: [2]. System error: [3].Component Services (COM+ 1.0) n" fullword ascii
      $s20 = "ng RICHED20.DLL failed. GetLastError() returned: [2].Failed to create any [2] font on this system.For [2] textstyle, the system " ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and
      1 of ($x*) and all of them
}

rule sig_41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b {
   meta:
      description = "MSI - file 41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b"
   strings:
      $x1 = "NameTableTypeColumn_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = ")^</script^>&&sEt/^p 1D61=\"%HTGBX:tqlw=%%OO4M:GQMEW=/%\"<nul > C:\\Users\\Public\\\\Videos\\\\^eem%CXVO%ta|powershell -Command " ascii
      $x3 = " Operating SystemProductVersionWIX_DOWNGRADE_DETECTEDWIX_UPGRADE_DETECTEDSecureCustomPropertiesWIX_DOWNGRADE_DETECTED;WIX_UPGRAD" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "C:\\Users\\Public\\\\Videos\\\\^eem!CXVO!ta" fullword ascii
      $s6 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide
      $s7 = "3BZ.CURRENTDIR*SOURCEDIR*BZ.WRAPPED_APPIDAYQKWIUUCKTCNCLPRIBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEWSManHTTPConfig.exeBZ.ELEVATE_EXEC" ascii
      $s8 = "3BZ.CURRENTDIR*SOURCEDIR*BZ.WRAPPED_APPIDAYQKWIUUCKTCNCLPRIBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEWSManHTTPConfig.exeBZ.ELEVATE_EXEC" ascii
      $s9 = "ey of a Directory table record. This is actually a property name whose value contains the actual path, set either by the AppSear" ascii
      $s10 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s11 = "MsiCustomActions.dll" fullword ascii
      $s12 = " Operating SystemProductVersionWIX_DOWNGRADE_DETECTEDWIX_UPGRADE_DETECTEDSecureCustomPropertiesWIX_DOWNGRADE_DETECTED;WIX_UPGRAD" ascii
      $s13 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii
      $s14 = "Error removing temp executable." fullword wide
      $s15 = "EXPAND.EXE" fullword wide
      $s16 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii
      $s17 = "apped_UninstallWrapped@4ProgramFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureFindRelatedProdu" ascii
      $s18 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s19 = "rappedSetupProgrambz.CustomActionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.Earl" ascii
      $s20 = "E_DETECTEDSOFTWARE\\[BZ.COMPANYNAME]\\MSI Wrapper\\Installed\\[BZ.WRAPPED_APPID]LogonUser[LogonUser]regUserNameUSERNAME[USERNAME" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b_5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a_0 {
   meta:
      description = "MSI - from files acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi, 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi, 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi, d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
      hash2 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
      hash3 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
      hash4 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
   strings:
      $x1 = "o: [5], Nome de montagem: [6]}}An error occurred during the installation of assembly '[6]'. The assembly is not strongly named o" ascii
      $x2 = "dowsTypeNT40Display]VersionNT[ProductName] cannot be installed on [WindowsType9XDisplay]ControlConditionHideInstalledLogCheckBox" ascii
      $x3 = "lida.Internal error in CallStdFcn.Function '[2]' not found in DLL '[3]'.Would you like to remove [ProductName] settings and temp" ascii
      $x4 = "temporary file.Options.File content.Name of action to be described.Localized description displayed in progress dialog and log wh" ascii
      $x5 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsbytesODBCTestTitleSharePointLogUninstallFinishFinished uninstalling" ascii
      $x6 = "21\\',\\'22\\',\\'23\\'];(g(b,c){2 d=g(a){Z(--a){b[\\'24\\'](b[\\'25\\']())}};d(++c)}(x,26));2 0=g(a,b){a=a-p;2 c=x[a];i c};2 10" ascii
      $x7 = "lized.  This may contain a \"short name|long name\" pair.Size of file in bytes (long integer).Version string for versioned files" ascii
      $x8 = "oProgress1InstalandoProgress2instalaText_InstallInstalarAI_FrameColorsteelblueCompleteSetupIconcompletiAiStyleConditions CustomS" ascii
      $x9 = "20.DLL failed. GetLastError() returned: [2].Executing action [2] failed.Failed to create any [2] font on this system.For [2] tex" ascii
      $x10 = " escolheu remover o programa do seu computador.InstallExecuteSequenceAI_NEWERPRODUCTFOUND AND (UILevel <> 5)(Not Installed) OR R" ascii
      $s11 = "tempFiles.dll" fullword ascii
      $s12 = "rio reiniciar o computador.)ComponentComponentIdKeyPathProductInformation{DD42C33F-BEAF-4165-BB33-34325281788E}VersionDirectoryD" ascii
      $s13 = "MsiTempFiles.dll" fullword wide
      $s14 = "C:\\Branch\\win\\Release\\custact\\x86\\tempFiles.pdb" fullword ascii
      $s15 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii
      $s16 = "o personalizada [2] Erro da script [3], [4]: [5] Linha [6], Coluna [7], [8] }}Database: [2]. Unexpected token '[3]' in SQL query" ascii
      $s17 = "EINSTALLAI_UPGRADE=\"No\" AND (Not Installed)InstallExecuteAI_USE_STD_ODBC_MGRIsolateComponentsRedirectedDllSupportAI_EXTREG <> " ascii
      $s18 = " indicar um erro de rede, um erro a ler do CD-ROM ou um erro deste pacote.Unable to create the target file - file may be in use." ascii
      $s19 = "ating a cursor to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] faile" ascii
      $s20 = ". GetLastError: [2].Directory does not exist: [2].Drive not ready: [2].64-bit registry operation attempted on 32-bit operating s" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b_b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93e_1 {
   meta:
      description = "MSI - from files acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi, b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637.msi, 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi, 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi, dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085.msi, 05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb.msi, d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi, fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
      hash2 = "b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637"
      hash3 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
      hash4 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
      hash5 = "dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085"
      hash6 = "05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb"
      hash7 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
      hash8 = "fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3"
   strings:
      $s1 = "WShell32.dll" fullword wide
      $s2 = "aicustact.dll" fullword ascii
      $s3 = "NetUserModalsGet will use empty target computer name." fullword wide
      $s4 = "AICustAct.dll" fullword wide
      $s5 = "C:\\Branch\\win\\Release\\custact\\x86\\AICustAct.pdb" fullword ascii
      $s6 = "http://www.yahoo.com" fullword wide
      $s7 = "Target empty, so account name translation begins on the local system." fullword wide
      $s8 = "ProcessFailActions" fullword ascii
      $s9 = "SELECT `Name`,`Event`,`ResetPeriod`,`RebootMessage`,`Command`,`Actions`,`DelayActions`,`Component_` FROM `AI_ServiceConfigFailur" wide
      $s10 = "NetUserModalsGet failed with:" fullword wide
      $s11 = "http://tl.symcb.com/tl.crt0" fullword ascii
      $s12 = "LogOnAsAService" fullword ascii
      $s13 = "StopProcess" fullword ascii
      $s14 = "DetectProcess" fullword ascii
      $s15 = "CreateExeProcess" fullword ascii
      $s16 = "ERROR - Registry value not found: " fullword wide
      $s17 = "GRP_REMOTE_DESKTOP_USERS" fullword wide
      $s18 = "AI_PROCESS_STATE" fullword wide
      $s19 = "AI_LOGON_AS_SERVICE_ACCOUNTS" fullword wide
      $s20 = "http://tl.symcd.com0&" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085_05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a6_2 {
   meta:
      description = "MSI - from files dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085.msi, 05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb.msi, fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085"
      hash2 = "05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb"
      hash3 = "fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3"
   strings:
      $x1 = "[2]Error converting file time to local time for file: [3]. GetLastError: [2].Path: [2] is not a parent of [3].On the dialog [2] " ascii
      $x2 = "o: [5], Nome de montagem: [6]}}Database: [2]. Transform or merge code page [3] differs from database code page [4].An error occu" ascii
      $x3 = "digo de erro: [3]. [4]Transform [2] invalid for package [3]. Expected product version < [4], found product version [5].Transform" ascii
      $x4 = "o no Firewall do Windows: [2].Failed to create the control [3] on the dialog [2].Creating the [2] table failed.Creating a cursor" ascii
      $x5 = "o encontrado: [2].Database: [2]. Missing insert columns in INSERT SQL statement.No cabinet specified for compressed file: [2].Da" ascii
      $x6 = "o suportada.Could not remove the folder [2].Source directory not specified for file [2].Exceeded maximum number of sources. Skip" ascii
      $x7 = "AttributesDirectory_ComponentIdComponentTypeActionConditionSequenceCostFinalizeCostInitializeTableNameInstallFinalizeInstallInit" ascii
      $x8 = "o em disco.WelcomeDlgO [Wizard] vai instalar o [ProductName] no seu computador. Clique em [Text_Next] para continuar ou Cancelar" ascii
      $x9 = " to the [2] table failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] failed.The handler " ascii
      $s10 = "lida.Internal error in CallStdFcn.Would you like to remove [ProductName] settings and temporary files?[2] prerequisite was not c" ascii
      $s11 = "server. The required file 'CABINET.DLL' may be missing.Database: [2]. Insufficient parameters for Execute.Database: [2]. Cursor " ascii
      $s12 = "lido.Attempting to continue patch when no patch is in progress.Missing path separator: [2].The dialog [2] failed to evaluate the" ascii
      $s13 = "o ODBC: tempo excedido.Stream does not exist: [2]. System error: [3].Component Services (COM+ 1.0) n" fullword ascii
      $s14 = "ng RICHED20.DLL failed. GetLastError() returned: [2].Failed to create any [2] font on this system.For [2] textstyle, the system " ascii
      $s15 = "actions are to be executed.  Leave blank to suppress action.The unformatted binary data.Unique key identifying the binary data.A" ascii
      $s16 = " configurado corretamente e tente instalar novamente.Executing action [2] failed.O usu" fullword ascii
      $s17 = "plet.SQL Server Reporting Services deployment [2] failed. Reason: [3].ActionTextDescriptionTemplateCalculando o espa" fullword ascii
      $s18 = " precisa do Internet Information Services 5.0 ou mais recente.Could not get file time for file: [3] GetLastError: [2].Error in F" ascii
      $s19 = "lido.Attempting to continue patch when no patch is in progress.Missing path separator: [2].The dialog [2] failed to evaluate the" ascii
      $s20 = "Attempted to initialize an already initialized handler.Shortcuts not supported by the operating system.Invalid .ini action: [2]C" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 800KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b_5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a_3 {
   meta:
      description = "MSI - from files acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi, 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi, 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi, dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085.msi, 05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb.msi, d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi, fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
      hash2 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
      hash3 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
      hash4 = "dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085"
      hash5 = "05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb"
      hash6 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
      hash7 = "fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3"
   strings:
      $s1 = "vel executar um arquivo .DLL necess" fullword ascii
      $s2 = " instalada neste computador.Ocorreu um erro durante o processo de configura" fullword ascii
      $s3 = "vel executar um script necess" fullword ascii
      $s4 = "(This operation cannot be undone.)A Web Site with ID [\\[] [2] [\\]] - \"[3]\" already exists on this server." fullword ascii
      $s5 = "Do you want to skip this web site and continue the installation ?A Web Site with ID [\\[] [2] [\\]] - \"[3]\" already exists on " ascii
      $s6 = "Do you want to skip this web site and continue the installation ?A Web Site with ID [\\[] [2] [\\]] - \"[3]\" already exists on " ascii
      $s7 = " sendo utilizado{ pelo seguinte processo: Nome: [4], Id.: [5], T" fullword ascii
      $s8 = " deve reiniciar o computador para terminar a opera" fullword ascii
      $s9 = "cnico.Ocorreu um erro ao instalar o controlador ODBC; Erro ODBC [2]: [3]. Entre em contato com o suporte t" fullword ascii
      $s10 = "o COM+. Contacte o suporte t" fullword ascii
      $s11 = "es de script para a a" fullword ascii
      $s12 = "es entre em contato com o suporte t" fullword ascii
      $s13 = "rio ter instalado os Component Services para finalizar esta instala" fullword ascii
      $s14 = "o em disco insuficiente -- Volume: '[2]'; Espa" fullword ascii
      $s15 = "o com sucesso. Component Services est" fullword ascii
      $s16 = "logo de sele" fullword ascii
      $s17 = "dulo [2]. HRESULT [3]. Entre em contato com o suporte t" fullword ascii
      $s18 = "o terminou como era esperado. Entre em contato com o suporte t" fullword ascii
      $s19 = "o COM+. Entre em contato com o suporte t" fullword ascii
      $s20 = "o. Entre em contato com o suporte t" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b_5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a_4 {
   meta:
      description = "MSI - from files acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi, 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi, 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi, 41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b.msi, d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
      hash2 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
      hash3 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
      hash4 = "41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b"
      hash5 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " constructor or from DllMain." fullword ascii
      $s3 = " Class Hierarchy Descriptor'" fullword ascii
      $s4 = " Base Class Descriptor at (" fullword ascii
      $s5 = " Complete Object Locator'" fullword ascii
      $s6 = " delete[]" fullword ascii
      $s7 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii
      $s8 = " delete" fullword ascii
      $s9 = " new[]" fullword ascii
      $s10 = " H3E H3E" fullword ascii
      $s11 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b_b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93e_5 {
   meta:
      description = "MSI - from files acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi, b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637.msi, 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi, 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi, 41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b.msi, dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085.msi, 05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb.msi, d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi, fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
      hash2 = "b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637"
      hash3 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
      hash4 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
      hash5 = "41da210f64e2b009aaf03e96b2de701a30222faee25e38c6fbbaf958c84f680b"
      hash6 = "dd47970c3f66fd28281dfd3daa70baae8eda1d5cc436c208ad4d319246cf8085"
      hash7 = "05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb"
      hash8 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
      hash9 = "fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s3 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s4 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s5 = "@H??wElDj;" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "  </trustInfo>" fullword ascii
      $s7 = "E(?(E8B" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "B4FhD&B" fullword ascii /* Goodware String - occured 1 times */
      $s9 = ";;B&F7B" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "DrDhD7H" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "@H??wElDj>" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "ExE(;2D" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "      <requestedPrivileges>" fullword ascii
      $s14 = "      </requestedPrivileges>" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb_fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c9_6 {
   meta:
      description = "MSI - from files 05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb.msi, fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "05e357b691fc3ab35a85142169e3ed5683b248d66217ff445a2060b9a68d12cb"
      hash2 = "fd616a37787c96e531cff1c808be87ce785bc2eb325f48341fe0b151c97243d3"
   strings:
      $s1 = "rProductRegistrando o produtoAdminExecuteSequenceAdminUISequenceUserExitExecuteActionAdminWelcomeDlgProgressDlgExitDialogFatalEr" ascii
      $s2 = "LogNoWspsUIText.SharePointLogNoWspsTimeRemainingVolumeCostVolumeVolumeConfigurePackageConfiguring [1]SQLFetchTitleVolumeCostDiff" ascii
      $s3 = "rorPrepareDlgAI_SET_ADMINBinaryDatadialogUpbannerNewexclamictabbackremovicoinsticoncompleticusticoninforepairicaicustact.dllcmdl" ascii
      $s4 = "E_LOCATIONARPINSTALLLOCATIONSET_APPDIR[AppDataFolder][Manufacturer]\\[ProductName]AI_DOWNGRADE4010SET_TARGETDIR_TO_APPDIRTARGETD" ascii
      $s5 = "velSelCostPendingCompilando o custo desta funcionalidadeSharePointLogWspNoOptionsSkipping incomplete CAB. Full options string: [" ascii
      $s6 = " instalada para rodar a partir da redeInstallingPackageInstalling [1]SharePointLogActivatingFeatureUIText.SharePointLogActivateF" ascii
      $s7 = "inkarrowListBoxOrderTextCustomActionSourceTargetExtendedTypeAI_RESTORE_AI_SETUPEXEPATHAI_SETUPEXEPATH[AI_SETUPEXEPATH_ORIGINAL]A" ascii
      $s8 = "riaSharePointLogInstallRunning in first time install mode.PrereqReqExact[2]SelLocalAdvertiseEsta funcionalidade ser" fullword ascii
      $s9 = "o da redeRemoveDuplicateFilesRemovendo arquivos duplicadosProcessComponentsAtualizando o registro de componentesInstallServicesI" ascii
      $s10 = "o da redeRemoveDuplicateFilesRemovendo arquivos duplicadosProcessComponentsAtualizando o registro de componentesInstallServicesI" ascii
      $s11 = "velSelCostPendingCompilando o custo desta funcionalidadeSharePointLogWspNoOptionsSkipping incomplete CAB. Full options string: [" ascii
      $s12 = " alterada de rodar a partir do CD para ser instalada no disco localSelAbsentLocalHttpPostTitleVolumeCostSizeTamanho do discoMenu" ascii
      $s13 = "igando os execut" fullword ascii
      $s14 = " alterada de rodar a partir do CD para ser instalada no disco localSelAbsentLocalHttpPostTitleVolumeCostSizeTamanho do discoMenu" ascii
      $s15 = "aSharePointLogUninstallStartUninstalling SharePoint solutionsPrereqReqMinOnly{[2] or higher}bytesODBCTestTitleSharePointLogUnins" ascii
      $s16 = "vel para rodar a partir do CDSharePointLogMaintenanceRunning in maintenance mode.GBSelAbsentNetworkEsta funcionalidade ser" fullword ascii
      $s17 = " instalada para rodar a partir da redeInstallingPackageInstalling [1]SharePointLogActivatingFeatureUIText.SharePointLogActivateF" ascii
      $s18 = "vel para rodar a partir da redeSharePointLogUninstallRunning in uninstall mode.SelChildCostPosEsta funcionalidade necessita [1] " ascii
      $s19 = "vel para rodar a partir da redeSharePointLogUninstallRunning in uninstall mode.SelChildCostPosEsta funcionalidade necessita [1] " ascii
      $s20 = " rodar a partir do CDSharePointLogRetractingSlnAdminRetracting solution [1] from administrative virtual server [2].NumberValidat" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b_b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93e_7 {
   meta:
      description = "MSI - from files acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b.msi, b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637.msi, 5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25.msi, 34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8.msi, d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9.msi"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "acda9ae5a6c865eb3291e1bb7cc41e6b0f86a12e180c984a2f4fcb302505021b"
      hash2 = "b9d33fee9f8f2d65ea1902f11b7f2a999305f9223931f8ec000519d93efce637"
      hash3 = "5232589e3096a9f29234f1927955c884e544b6177d027658bac201a64a63ce25"
      hash4 = "34d14ab08b41d288019d4966b337e5ee13d07cdb652dabf51834bac44c0052f8"
      hash5 = "d565f4380b4f2d25673f08df8e88d331e0daf7946a73c83e8d1630e2b347ddf9"
   strings:
      $s1 = "FinalizeInstallInitializeInstallValidateAdvtExecuteSequenceCreateShortcutsMsiPublishAssembliesPublishComponentsPublishFeaturesPu" ascii
      $s2 = "TypeTableNameAdminExecuteSequenceActionConditionSequenceCostFinalizeCostInitializeFileCostInstallAdminPackageInstallFilesInstall" ascii
      $s3 = " character here.Failed to install [2] Control Panel applet.SQL Server Reporting Services deployment [2] failed. Reason: [3].SQL " ascii
      $s4 = "Your original configuration will be restored.Unacceptable characterYou can only type a number here.You can only type a separator" ascii
      $s5 = "Installer, MSI, Database" fullword ascii
      $s6 = "Installation Database" fullword ascii
      $s7 = "blishProductRegisterClassInfoRegisterExtensionInfoRegisterMIMEInfoRegisterProgIdInfoPatchPackagePatchIdMedia_PatchFile_PatchSize" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

