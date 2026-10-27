; Djokovic 보안 관제 설치 프로그램(비밀번호 암호화형).
; 프로그램 파일 전체를 설치 비밀번호로 암호화한 7z(AES-256, 파일 이름까지 암호화)로 넣는다.
; 설치 프로그램 안에는 비밀번호도 그 해시도 없다. 입력한 비밀번호로 실제로 풀려야만 설치된다.
; 만들기: desktop\build-installer.ps1 (이 파일을 직접 컴파일하지 않는다. 경로·버전을 /D 로 넘겨 준다)
Unicode true
!include MUI2.nsh
!include nsDialogs.nsh
!include LogicLib.nsh
!include FileFunc.nsh
!include WordFunc.nsh

!define APPNAME "Djokovic 보안 관제"
!define APPEXE "Djokovic SOC.exe"
!define APPID "kr.aleph.djokovic.soc"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}"
!define FEEDBACK_URL "https://github.com/alska14/choi-bujang-agent/issues/new?title=%5B%ED%94%BC%EB%93%9C%EB%B0%B1%5D%20"
!define DONATE_TEXT "IBK기업은행 97907030801012"
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
; 설치 방식: install(처음) / update(새 버전) / reinstall(같은 버전) / downgrade(이전 버전)
Var Mode
Var OldVersion
Var WasRunning
Var FinishTitle
Var FinishText
; 제거할 때 사건 기록·설정 데이터도 지울지(기본: 남김)
Var DelData
Var DelDataBox
Page custom PwCreate PwLeave
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "$FinishTitle"
!define MUI_FINISHPAGE_TEXT "$FinishText"
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APPEXE}"
!define MUI_FINISHPAGE_RUN_TEXT "지금 실행"
!insertmacro MUI_PAGE_FINISH
; 제거 마법사: 의견·후원 안내(+데이터 지우기 선택) → 확인 → 제거 → 마침(의견 남기기 링크)
UninstPage custom un.FbCreate un.FbLeave
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "제거를 마쳤습니다"
!define MUI_FINISHPAGE_TEXT "${APPNAME}을(를) 지웠습니다. 써 주셔서 고맙습니다."
!define MUI_FINISHPAGE_LINK "의견 남기기(GitHub)"
!define MUI_FINISHPAGE_LINK_LOCATION "${FEEDBACK_URL}"
!insertmacro MUI_UNPAGE_FINISH
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
  ${If} $Mode == "update"
    SendMessage $HWNDPARENT ${WM_SETTEXT} 0 "STR:${APPNAME} 업데이트"
    !insertmacro MUI_HEADER_TEXT "업데이트: $OldVersion → ${VERSION}" "설치된 버전을 새 버전으로 바꿉니다. 사건 기록과 설정은 그대로 남습니다."
    StrCpy $1 "새 버전으로 업데이트하려면 설치 비밀번호를 입력하세요."
  ${ElseIf} $Mode == "reinstall"
    !insertmacro MUI_HEADER_TEXT "다시 설치: ${VERSION}" "같은 버전을 다시 설치합니다. 사건 기록과 설정은 그대로 남습니다."
    StrCpy $1 "다시 설치하려면 설치 비밀번호를 입력하세요."
  ${ElseIf} $Mode == "downgrade"
    !insertmacro MUI_HEADER_TEXT "이전 버전으로: $OldVersion → ${VERSION}" "설치된 것보다 오래된 버전입니다. 사건 기록과 설정은 그대로 남습니다."
    StrCpy $1 "이전 버전으로 바꾸려면 설치 비밀번호를 입력하세요."
  ${Else}
    !insertmacro MUI_HEADER_TEXT "설치 비밀번호" "프로그램 파일이 비밀번호로 암호화돼 있습니다."
    StrCpy $1 "설치 비밀번호를 입력하세요."
  ${EndIf}
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 34u "$1$\r$\n프로그램 파일은 이 비밀번호로 암호화(AES-256)돼 있어서 비밀번호가 맞아야 풀립니다."
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
  ; 이미 설치돼 있으면 그 위치·버전을 읽어 업데이트로 진행한다.
  ReadRegStr $OldVersion HKCU "${UNINSTKEY}" "DisplayVersion"
  ReadRegStr $0 HKCU "${UNINSTKEY}" "InstallLocation"
  ${If} $0 != ""
    StrCpy $INSTDIR $0
  ${EndIf}
  ${If} $OldVersion == ""
  ${AndIf} ${FileExists} "$INSTDIR\Uninstall Djokovic SOC.exe"
    StrCpy $OldVersion "1.0.0" ; 예전 방식(electron-builder)으로 설치된 1.0.0
  ${EndIf}
  ${If} $OldVersion == ""
    StrCpy $Mode "install"
  ${Else}
    ${VersionCompare} "${VERSION}" "$OldVersion" $1
    ${If} $1 == 1
      StrCpy $Mode "update"
    ${ElseIf} $1 == 0
      StrCpy $Mode "reinstall"
    ${Else}
      StrCpy $Mode "downgrade"
    ${EndIf}
  ${EndIf}
  ${If} $Mode == "downgrade"
    ${If} ${Silent}
      ${GetParameters} $R0
      ClearErrors
      ${GetOptions} $R0 "/ALLOWDOWNGRADE" $R1
      ${If} ${Errors}
        SetErrorLevel 6 ; 조용한 설치에서는 /ALLOWDOWNGRADE 없이 이전 버전으로 바꾸지 않는다
        Quit
      ${EndIf}
    ${Else}
      MessageBox MB_ICONQUESTION|MB_YESNO "더 새 버전($OldVersion)이 이미 설치돼 있습니다.$\r$\n이전 버전(${VERSION})으로 바꿀까요?" IDYES +2
      Quit
    ${EndIf}
  ${EndIf}
  ${If} $Mode == "install"
    StrCpy $FinishTitle "설치를 마쳤습니다"
    StrCpy $FinishText "${APPNAME} ${VERSION}을(를) 설치했습니다."
  ${Else}
    StrCpy $FinishTitle "업데이트를 마쳤습니다"
    StrCpy $FinishText "${APPNAME}을(를) $OldVersion에서 ${VERSION}(으)로 바꿨습니다. 사건 기록과 설정은 그대로입니다."
  ${EndIf}
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
  ${If} $Mode == "install"
    DetailPrint "새로 설치: ${VERSION}"
  ${Else}
    DetailPrint "업데이트: $OldVersion → ${VERSION}"
  ${EndIf}
  ; 실행 중이었는지 기억해 두었다가(조용한 업데이트면 끝나고 다시 켬), 앱과 앱이 켠 관제 서버를 끈다.
  ; 사건 기록 등 데이터 폴더(%LOCALAPPDATA%\djokovic-soc)는 건드리지 않는다.
  StrCpy $WasRunning 0
  nsExec::ExecToStack 'cmd.exe /c tasklist /FI "IMAGENAME eq ${APPEXE}" /NH'
  Pop $0
  Pop $1
  ${WordFind} "$1" "${APPEXE}" "E+1{" $2
  ${IfNot} ${Errors}
    StrCpy $WasRunning 1
  ${EndIf}
  nsExec::Exec 'taskkill /IM "${APPEXE}" /F'
  Sleep 1500
  ; 예전 방식(electron-builder)으로 설치된 것이 있으면 그 제거 프로그램으로 먼저 지운다.
  ${If} ${FileExists} "$INSTDIR\Uninstall Djokovic SOC.exe"
    ExecWait '"$INSTDIR\Uninstall Djokovic SOC.exe" /S _?=$INSTDIR'
    Delete "$INSTDIR\Uninstall Djokovic SOC.exe"
  ${EndIf}
  ; 새 버전은 옆 폴더(.new)에 먼저 풀고, 다 풀린 뒤에만 기존 폴더와 바꾼다. 중간에 실패하면 기존 버전이 그대로 남는다.
  DetailPrint "프로그램 파일 암호 풀기 중…"
  RMDir /r "$INSTDIR.new"
  CreateDirectory "$INSTDIR.new"
  nsExec::ExecToStack '"$PLUGINSDIR\7za.exe" x -y -bso0 -bsp0 "-p$Password" "-o$INSTDIR.new" "$PLUGINSDIR\payload.7z"'
  Pop $0
  Pop $1
  StrCpy $Password ""
  Delete "$PLUGINSDIR\payload.7z"
  ${If} $0 != 0
    RMDir /r "$INSTDIR.new"
    MessageBox MB_ICONSTOP|MB_OK "프로그램 파일을 풀지 못했습니다(코드 $0). 기존에 설치된 것은 그대로입니다." /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
  DetailPrint "기존 파일과 바꾸는 중…"
  RMDir /r "$INSTDIR.old"
  ${If} ${FileExists} "$INSTDIR\*.*"
    ; 앱이 끝나도 앱이 시작한 점검 작업(PowerShell)이 몇 초~수십 초 더 폴더를 쥐고 있을 수 있어, 최대 약 40초 동안 다시 시도한다.
    StrCpy $3 0
    ${Do}
      ClearErrors
      Rename "$INSTDIR" "$INSTDIR.old"
      ${IfNot} ${Errors}
        ${Break}
      ${EndIf}
      IntOp $3 $3 + 1
      ${If} $3 >= 20
        ${Break}
      ${EndIf}
      DetailPrint "기존 파일이 아직 사용 중이라 기다리는 중… ($3/20)"
      Sleep 2000
    ${Loop}
    ${If} ${Errors}
      RMDir /r "$INSTDIR.new"
      ${If} $WasRunning == 1
        Exec '"$INSTDIR\${APPEXE}"' ; 바꾸지 못했으면 원래 앱을 다시 켜 둔다
      ${EndIf}
      MessageBox MB_ICONSTOP|MB_OK "기존 프로그램 파일이 사용 중이라 바꾸지 못했습니다. 앱을 완전히 끝낸 뒤 다시 실행하세요. 기존에 설치된 것은 그대로입니다." /SD IDOK
      SetErrorLevel 3
      Abort
    ${EndIf}
  ${EndIf}
  Rename "$INSTDIR.new" "$INSTDIR"
  RMDir /r "$INSTDIR.old"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ; 바탕화면 바로가기는 처음 설치할 때만 만든다(업데이트 때 사용자가 지운 바로가기를 되살리지 않음). 있으면 새 경로로 고친다.
  ${If} $Mode == "install"
  ${OrIf} ${FileExists} "$DESKTOP\${APPNAME}.lnk"
    CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${APPEXE}"
  ${EndIf}
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
  ; 조용한 업데이트(자동 업데이트 등)에서 앱이 켜져 있었으면 다시 켠다. 창이 있는 설치는 마침 화면의 「지금 실행」으로 켠다.
  ${If} ${Silent}
  ${AndIf} $WasRunning == 1
    Exec '"$INSTDIR\${APPEXE}"'
  ${EndIf}
SectionEnd

; ---------- 제거 마법사 ----------
Function un.FbCreate
  !insertmacro MUI_HEADER_TEXT "떠나시기 전에" "의견을 남겨 주시면 다음 버전에 반영하겠습니다."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 24u "불편했던 점이나 바라는 기능을 알려 주세요. 아래 버튼을 누르면 의견 남기는 페이지(GitHub)가 브라우저로 열립니다."
  Pop $0
  ${NSD_CreateButton} 0 26u 45% 14u "의견 남기기(GitHub)"
  Pop $0
  ${NSD_OnClick} $0 un.OnFeedback
  ${NSD_CreateLabel} 0 50u 100% 20u "이 프로그램이 도움이 되셨다면 후원해 주시면 큰 힘이 됩니다(선택 사항입니다)."
  Pop $0
  ${NSD_CreateText} 0 70u 60% 13u "${DONATE_TEXT}"
  Pop $0
  SendMessage $0 ${EM_SETREADONLY} 1 0
  ${NSD_CreateCheckbox} 0 96u 100% 12u "사건 기록·점검 기록·설정도 함께 지우기(체크하지 않으면 다시 설치할 때 그대로 이어집니다)"
  Pop $DelDataBox
  nsDialogs::Show
FunctionEnd

Function un.OnFeedback
  Pop $0
  ExecShell "open" "${FEEDBACK_URL}"
FunctionEnd

Function un.FbLeave
  ${NSD_GetState} $DelDataBox $DelData
FunctionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /IM "${APPEXE}" /F'
  Sleep 1500
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  ; 앱이 등록한 로그인 자동 실행도 지운다. 사건 기록·설정 등 데이터 폴더는 남긴다.
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${APPID}"
  DeleteRegKey HKCU "${UNINSTKEY}"
  RMDir /r "$INSTDIR"
  ; 데이터도 지우기를 고른 경우에만 지운다. Codex 감사 훅 복사본(hooks 폴더)은 Codex 설정이 가리키고 있어 남긴다.
  ${If} $DelData == ${BST_CHECKED}
    Delete "$LOCALAPPDATA\djokovic-soc\events.json"
    Delete "$LOCALAPPDATA\djokovic-soc\inventory-baseline.json"
    Delete "$LOCALAPPDATA\djokovic-soc\remediation-log.json"
    Delete "$LOCALAPPDATA\djokovic-soc\ioc-store.json"
    Delete "$LOCALAPPDATA\djokovic-soc\agent-audit.jsonl"
    Delete "$LOCALAPPDATA\djokovic-soc\agent-audit.jsonl.1"
    Delete "$LOCALAPPDATA\djokovic-soc\app-server.log"
    Delete "$LOCALAPPDATA\djokovic-soc\app-server.log.1"
    Delete "$LOCALAPPDATA\djokovic-soc\autostart.log"
    RMDir /r "$APPDATA\Djokovic SOC"
  ${EndIf}
SectionEnd
