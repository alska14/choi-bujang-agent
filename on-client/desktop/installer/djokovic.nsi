; Djokovic 보안 관제 설치 프로그램(비밀번호 암호화형).
; 프로그램 파일 전체를 설치 비밀번호로 암호화한 7z(AES-256, 파일 이름까지 암호화)로 넣는다.
; 설치 프로그램 안에는 비밀번호도 그 해시도 없다. 입력한 비밀번호로 실제로 풀려야만 설치된다.
; 만들기: desktop\build-installer.ps1 (이 파일을 직접 컴파일하지 않는다. 경로·버전을 /D 로 넘겨 준다)
Unicode true
!include MUI2.nsh
!include nsDialogs.nsh
!include LogicLib.nsh
!include FileFunc.nsh

!define APPNAME "Djokovic 보안 관제"
!define APPEXE "Djokovic SOC.exe"
!define APPID "kr.aleph.djokovic.soc"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}"
!ifndef VERSION
  !error "VERSION 을 /DVERSION= 으로 넘겨야 합니다"
!endif

Name "${APPNAME}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\djokovic-soc-desktop"
RequestExecutionLevel user
; 안에 넣는 것은 이미 압축·암호화된 덩어리라 다시 압축하지 않는다.
SetCompress off
BrandingText "${APPNAME} ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1042 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=1042 "FileDescription" "${APPNAME} 설치"
VIAddVersionKey /LANG=1042 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1042 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1042 "LegalCopyright" "alska14"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING

Var PwField
Var Password

Page custom PwCreate PwLeave
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APPEXE}"
!define MUI_FINISHPAGE_RUN_TEXT "지금 실행"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Korean"

; 암호화된 덩어리와 7-Zip 을 임시 폴더에 꺼낸다(한 번만).
Function PreparePayload
  InitPluginsDir
  ${IfNot} ${FileExists} "$PLUGINSDIR\payload.7z"
    File "/oname=$PLUGINSDIR\7za.exe" "${SEVENZIP}"
    File "/oname=$PLUGINSDIR\payload.7z" "${PAYLOAD}"
  ${EndIf}
FunctionEnd

; $Password 로 암호화된 목록을 열어 본다. 파일 이름까지 암호화돼 있어서 비밀번호가 틀리면 열리지 않는다. $0 = 0 이면 맞음.
Function TestPassword
  Call PreparePayload
  nsExec::ExecToStack '"$PLUGINSDIR\7za.exe" l -bso0 -bse0 "-p$Password" "$PLUGINSDIR\payload.7z"'
  Pop $0
  Pop $1
FunctionEnd

Function PwCreate
  !insertmacro MUI_HEADER_TEXT "설치 비밀번호" "프로그램 파일이 비밀번호로 암호화돼 있습니다."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 34u "설치 비밀번호를 입력하세요.$\r$\n프로그램 파일은 이 비밀번호로 암호화(AES-256)돼 있어서 비밀번호가 맞아야 풀립니다."
  Pop $0
  ${NSD_CreatePassword} 0 42u 70% 14u ""
  Pop $PwField
  ${NSD_SetFocus} $PwField
  nsDialogs::Show
FunctionEnd

Function PwLeave
  ${NSD_GetText} $PwField $Password
  ${If} $Password == ""
    MessageBox MB_ICONEXCLAMATION|MB_OK "비밀번호를 입력하세요."
    Abort
  ${EndIf}
  Call TestPassword
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "비밀번호가 맞지 않습니다."
    ${NSD_SetText} $PwField ""
    StrCpy $Password ""
    Abort
  ${EndIf}
FunctionEnd

; 조용한 설치: /S /PASSWORD=비밀번호. 없거나 틀리면 아무것도 바꾸지 않고 종료 코드 5.
Function .onInit
  ${If} ${Silent}
    ${GetParameters} $R0
    ClearErrors
    ${GetOptions} $R0 "/PASSWORD=" $Password
    ${If} ${Errors}
    ${OrIf} $Password == ""
      SetErrorLevel 5
      Quit
    ${EndIf}
    Call TestPassword
    ${If} $0 != 0
      SetErrorLevel 5
      Quit
    ${EndIf}
  ${EndIf}
FunctionEnd

Section "Install"
  ; 실행 중인 앱(과 앱이 켠 관제 서버)을 끈다. 사건 기록 등 데이터 폴더(%LOCALAPPDATA%\djokovic-soc)는 건드리지 않는다.
  nsExec::Exec 'taskkill /IM "${APPEXE}" /F'
  Sleep 1500
  ; 예전 방식(electron-builder)으로 설치된 것이 있으면 그 제거 프로그램으로 먼저 지운다.
  ${If} ${FileExists} "$INSTDIR\Uninstall Djokovic SOC.exe"
    ExecWait '"$INSTDIR\Uninstall Djokovic SOC.exe" /S _?=$INSTDIR'
    Delete "$INSTDIR\Uninstall Djokovic SOC.exe"
  ${EndIf}
  RMDir /r "$INSTDIR"
  CreateDirectory "$INSTDIR"
  DetailPrint "프로그램 파일 암호 풀기·설치 중…"
  nsExec::ExecToStack '"$PLUGINSDIR\7za.exe" x -y -bso0 -bsp0 "-p$Password" "-o$INSTDIR" "$PLUGINSDIR\payload.7z"'
  Pop $0
  Pop $1
  StrCpy $Password ""
  Delete "$PLUGINSDIR\payload.7z"
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "프로그램 파일을 풀지 못했습니다(코드 $0)."
    SetErrorLevel 2
    Abort
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${APPEXE}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\${APPEXE}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "alska14"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\${APPEXE}"
  WriteRegStr HKCU "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "${UNINSTKEY}" "EstimatedSize" $0
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /IM "${APPEXE}" /F'
  Sleep 1500
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  ; 앱이 등록한 로그인 자동 실행도 지운다. 사건 기록·설정 등 데이터 폴더는 남긴다.
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${APPID}"
  DeleteRegKey HKCU "${UNINSTKEY}"
  RMDir /r "$INSTDIR"
SectionEnd
