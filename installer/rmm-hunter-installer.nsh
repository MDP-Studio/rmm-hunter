!include LogicLib.nsh
!include MUI2.nsh
!include nsDialogs.nsh
!include WordFunc.nsh

!ifndef BUILD_UNINSTALLER

!define /ifndef INSTALL_REGISTRY_KEY "Software\${APP_GUID}"
!define /ifndef UNINSTALL_REGISTRY_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}"

!insertmacro VersionCompare

Var RMMHunterExistingInstallFound
Var RMMHunterExistingInstallPath
Var RMMHunterExistingVersion
Var RMMHunterExistingScope
Var RMMHunterVersionCompareResult
Var RMMHunterExistingInstallDialog
Var RMMHunterExistingInstallLabel

!macro customInit
  Call RMMHunterLoadExistingInstall
  ${If} $RMMHunterExistingInstallFound == "1"
    StrCpy $INSTDIR "$RMMHunterExistingInstallPath"
    Call RMMHunterBlockDowngrade
  ${EndIf}
!macroend

!macro customPageAfterChangeDir
  Page custom RMMHunterExistingInstallPageCreate RMMHunterExistingInstallPageLeave
!macroend

Function RMMHunterLoadExistingInstall
  StrCpy $RMMHunterExistingInstallFound "0"
  StrCpy $RMMHunterExistingInstallPath ""
  StrCpy $RMMHunterExistingVersion ""
  StrCpy $RMMHunterExistingScope ""

  ReadRegStr $RMMHunterExistingInstallPath HKCU "${INSTALL_REGISTRY_KEY}" InstallLocation
  ReadRegStr $RMMHunterExistingVersion HKCU "${UNINSTALL_REGISTRY_KEY}" DisplayVersion
  StrCpy $RMMHunterExistingScope "current user"

  ${If} $RMMHunterExistingInstallPath != ""
    StrCpy $RMMHunterExistingInstallFound "1"
    ${If} $RMMHunterExistingVersion == ""
      StrCpy $RMMHunterExistingVersion "unknown version"
    ${EndIf}
  ${EndIf}
FunctionEnd

Function RMMHunterBlockDowngrade
  ${If} $RMMHunterExistingInstallFound != "1"
    Return
  ${EndIf}

  ${If} $RMMHunterExistingVersion == ""
  ${OrIf} $RMMHunterExistingVersion == "unknown version"
    Return
  ${EndIf}

  ${VersionCompare} "$RMMHunterExistingVersion" "${VERSION}" $RMMHunterVersionCompareResult
  ${If} $RMMHunterVersionCompareResult == "1"
    ${IfNot} ${Silent}
      MessageBox MB_OK|MB_ICONSTOP "A newer RMM Hunter version ($RMMHunterExistingVersion) is already installed for $RMMHunterExistingScope.$\r$\n$\r$\nThis installer contains ${VERSION}, so it will not continue. Download the newest installer from the official GitHub Releases page."
    ${EndIf}
    SetErrorLevel 2
    Quit
  ${EndIf}
FunctionEnd

Function RMMHunterExistingInstallPageCreate
  Call RMMHunterLoadExistingInstall
  ${If} $RMMHunterExistingInstallFound != "1"
    Abort
  ${EndIf}

  StrCpy $INSTDIR "$RMMHunterExistingInstallPath"
  Call RMMHunterBlockDowngrade

  !insertmacro MUI_HEADER_TEXT "Existing RMM Hunter installation found" "This installer will update the existing copy instead of creating a duplicate."

  nsDialogs::Create 1018
  Pop $RMMHunterExistingInstallDialog
  ${If} $RMMHunterExistingInstallDialog == error
    Abort
  ${EndIf}

  ${If} $RMMHunterExistingVersion == "${VERSION}"
    StrCpy $0 "Repair RMM Hunter ${VERSION}"
  ${Else}
    StrCpy $0 "Update RMM Hunter $RMMHunterExistingVersion to ${VERSION}"
  ${EndIf}

  ${NSD_CreateLabel} 0u 0u 100% 26u "$0"
  Pop $RMMHunterExistingInstallLabel

  ${NSD_CreateLabel} 0u 34u 100% 74u "Install scope: $RMMHunterExistingScope$\r$\nInstall location: $RMMHunterExistingInstallPath$\r$\n$\r$\nReports, saved AI provider settings, update settings, and local app data will be kept."
  Pop $RMMHunterExistingInstallLabel

  ${NSD_CreateLabel} 0u 120u 100% 48u "If RMM Hunter is running, the installer will ask to close it before replacing files. Click Next to continue."
  Pop $RMMHunterExistingInstallLabel

  nsDialogs::Show
FunctionEnd

Function RMMHunterExistingInstallPageLeave
  Call RMMHunterLoadExistingInstall
  ${If} $RMMHunterExistingInstallFound == "1"
    StrCpy $INSTDIR "$RMMHunterExistingInstallPath"
    Call RMMHunterBlockDowngrade
  ${EndIf}
FunctionEnd

!endif
