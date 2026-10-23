; ==============================================================================
; Sentinela HIDS - NSIS Installer Script (Windows x64)
; ==============================================================================

!include "MUI2.nsh"
!include "x64.nsh"

!ifndef VERSION
  !define VERSION "0.3.0"
!endif

Name "Sentinela v${VERSION}"
OutFile "..\sentinela-windows-x64-setup.exe"
InstallDir "$PROGRAMFILES64\Sentinela"
InstallDirRegKey HKLM "Software\Sentinela" "Install_Dir"
RequestExecutionLevel admin

; Configuracao Visual
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Paginas do Instalador
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN "$INSTDIR\sentinela.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Executar Sentinela agora"
!insertmacro MUI_PAGE_FINISH

; Paginas do Desinstalador
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Idiomas
!insertmacro MUI_LANGUAGE "Portuguese"
!insertmacro MUI_LANGUAGE "English"

Section "Sentinela (Requerido)" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"
    File "..\target\x86_64-pc-windows-msvc\release\sentinela.exe"
    File "..\README.md"
    File "..\LICENSE"
    File "install.ps1"
    File "install.bat"

    ; Atalhos no Menu Iniciar e Ambiente de Trabalho
    CreateDirectory "$SMPROGRAMS\Sentinela"
    CreateShortcut "$SMPROGRAMS\Sentinela\Sentinela.lnk" "$INSTDIR\sentinela.exe" "" "$INSTDIR\sentinela.exe" 0
    CreateShortcut "$SMPROGRAMS\Sentinela\Desinstalar Sentinela.lnk" "$INSTDIR\uninstall.exe"
    CreateShortcut "$DESKTOP\Sentinela HIDS.lnk" "$INSTDIR\sentinela.exe" "" "$INSTDIR\sentinela.exe" 0

    ; Registo no Painel de Controlo / Definicoes (Adicionar/Remover Programas)
    WriteRegStr HKLM "Software\Sentinela" "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela" "DisplayName" "Sentinela HIDS"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela" "Publisher" "Salvador Pontes (teizinh)"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela" "NoRepair" 1

    ; Adiciona INSTDIR a variavel de ambiente PATH da maquina
    ExecWait 'powershell -NoProfile -WindowStyle Hidden -Command "$p=[Environment]::GetEnvironmentVariable(\"Path\",\"Machine\"); if (-not ($p -split \";\" -contains \"$INSTDIR\")) { [Environment]::SetEnvironmentVariable(\"Path\", \"$p;$INSTDIR\", \"Machine\") }"'

    ; Cria desinstalador
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
    ; Remove do PATH
    ExecWait 'powershell -NoProfile -WindowStyle Hidden -Command "$p=[Environment]::GetEnvironmentVariable(\"Path\",\"Machine\"); $np=($p -split \";\" | Where-Object { $_ -ne \"$INSTDIR\" }) -join \";\"; [Environment]::SetEnvironmentVariable(\"Path\", $np, \"Machine\")"'

    ; Remove ficheiros
    Delete "$INSTDIR\sentinela.exe"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\install.ps1"
    Delete "$INSTDIR\install.bat"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove atalhos
    Delete "$SMPROGRAMS\Sentinela\Sentinela.lnk"
    Delete "$SMPROGRAMS\Sentinela\Desinstalar Sentinela.lnk"
    RMDir "$SMPROGRAMS\Sentinela"
    Delete "$DESKTOP\Sentinela HIDS.lnk"

    ; Remove chaves de registo
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela"
    DeleteRegKey HKLM "Software\Sentinela"
SectionEnd
