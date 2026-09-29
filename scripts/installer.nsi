Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!define VERSION "0.3.0"
Name "ShareGuard"
OutFile "../dist/ShareGuard-Setup-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\Programs\ShareGuard"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "ShareGuard"
!define MUI_ICON "../assets/shareguard.ico"
!define MUI_UNICON "../assets/shareguard.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\ShareGuard.exe"
!define MUI_FINISHPAGE_RUN_TEXT "ShareGuard uygulamasını aç"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Turkish"
VIProductVersion "0.3.0.0"
VIAddVersionKey /LANG=1055 "ProductName" "ShareGuard"
VIAddVersionKey /LANG=1055 "FileDescription" "ShareGuard Kurulum"
VIAddVersionKey /LANG=1055 "FileVersion" "0.3.0"
VIAddVersionKey /LANG=1055 "LegalCopyright" "ShareGuard Project"

Function .onInit
    ${IfNot} ${RunningX64}
        MessageBox MB_ICONSTOP "ShareGuard, 64 bit Windows gerektirir."
        Abort
    ${EndIf}
FunctionEnd

Section "ShareGuard"
    SetShellVarContext current
    SetOutPath "$INSTDIR"
    ClearErrors
    File /oname=ShareGuard.exe "../dist/ShareGuard-0.3.0-windows-x64.exe"
    IfErrors install_failed
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    CreateShortcut "$SMPROGRAMS\ShareGuard.lnk" "$INSTDIR\ShareGuard.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "DisplayName" "ShareGuard"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "DisplayVersion" "${VERSION}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "Publisher" "ShareGuard Project"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "DisplayIcon" "$INSTDIR\ShareGuard.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "NoModify" 1
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard" "NoRepair" 1
    Goto done
    install_failed:
    Abort "ShareGuard yüklenemedi. Açık uygulamayı kapatıp tekrar deneyin."
    done:
SectionEnd

Section "Uninstall"
    SetShellVarContext current
    Delete "$INSTDIR\ShareGuard.exe"
    IfFileExists "$INSTDIR\ShareGuard.exe" 0 +2
        Abort "Önce ShareGuard uygulamasını kapatın."
    Delete "$SMPROGRAMS\ShareGuard.lnk"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareGuard"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"
SectionEnd
