# 데이터 보존·백업·복원 계획 (Djoković 보안 Agent)

이 문서는 이 프로젝트가 어떤 데이터를 만들고 어디에 두는지, 어떻게 백업하고 복원하는지, 그리고 그 한계를 정리합니다. 아래 "코드 확인"은 파일을 읽고 `grep`으로 검색해 확인했다는 뜻이며, 실행해 본 것은 별도로 적었습니다.

## 1. 이 프로젝트가 다루는 데이터

| 데이터 | 저장 위치 | 보존 여부 | 근거 |
|---|---|---|---|
| 소스 코드·문서(`student/extension.mjs`, `docs/*`, `README.md` 등) | Git 저장소 | 보존합니다. 이것이 이 프로젝트의 유일한 보존 대상입니다. | `git ls-files` |
| 기본 실행(`start-alekov.ps1`, `npm start`, `npm run demo`)에서 앱이 만드는 데이터 | 만들지 않습니다. 서버·학생 코드·화면 코드에서 파일 쓰기(`writeFile`, `appendFile`, `createWriteStream`, `mkdir`), `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`를 검색했으나 없었습니다. | 보존할 것이 없습니다. | 코드 확인 |
| 화면에 보이는 사용자·기기·세션·보안 기록·AI 설명·조치 상태 | 브라우저 화면과 서버 메모리에만 있습니다. 서버나 브라우저를 닫으면 사라집니다. | 보존하지 않습니다. 필요하면 원래 시스템(접근 제어·XDR)에서 다시 조회합니다. | 코드 확인 |
| 내 PC 상태 측정 기록(`/pc-status`, 최근 20회의 CPU·메모리·디스크 값과 잰 시각) | 서버 메모리에만 있습니다. `src/pc-status/history.mjs`는 파일을 쓰지 않습니다. 서버를 끄면 사라집니다. | 보존하지 않습니다. 필요하면 다시 측정합니다. | `src/pc-status/*`, 코드 확인 |
| 방화벽·네트워크·Windows 기록 조회 결과(`/api/pc-security`) | 저장하지 않습니다. 요청 때마다 읽어 화면에 보내고 끝납니다. 읽기 위해 `powershell.exe`를 고정 명령으로 실행하며 어떤 설정도 바꾸지 않습니다. | 보존하지 않습니다. | `src/pc-status/security-reader.mjs`, 코드 확인 |
| 확인 티켓(조치 확인 번호) | 제공 화면 메모리에만 있습니다. 학생 함수에는 전달되지 않습니다. | 보존하지 않습니다. | `public/app.js`, 코드 확인 |
| `.env` 값(비밀 포함 가능) | 각자의 PC. Git에서 제외합니다(`.gitignore`: `.env`, `.env.*`, 단 `.env.example`만 포함). 서버는 `.env` 파일을 읽지 않고 환경 변수만 읽습니다. | 저장소에 보존하지 않습니다. | 코드 확인 |
| 조치 기록(`alekov_action_intents`, `alekov_action_state`, `alekov_action_audit` 표) | 조치를 켤 때(`--alekov-actions`와 `--alekov-actions-config`를 함께 지정) 운영자가 정한 기존 SQLite 파일에만 기록합니다. 기본 실행에서는 켜지지 않습니다. | 이 저장소의 보존 대상이 아닙니다. 운영자가 관리합니다. | `src/actions/store.mjs`, `src/server.mjs`, 코드 확인 |
| 계정 연결·AI 앱 열쇠 보관 폴더(`registry`, `vault`) | `tools\prepare-native-host.ps1`이 프로젝트 폴더 밖에 만들며 접근 권한을 제한합니다. 담당자 안내에 따라 쓸 때만 생깁니다. | 저장소에 넣지 않고 복사·백업하지 않습니다. 열쇠이므로 필요하면 담당자에게 재발급을 요청합니다. | `tools/prepare-native-host.ps1`, `src/connection/native-context.mjs`, 코드 확인 |

이 PC에서 기본 실행으로 서버를 켜고 화면을 확인했을 때 `on-client` 안에 새 파일이 생기지 않았습니다. 이는 재현 기록(`docs/REPRODUCTION_RECORD.md`)의 새 폴더 점검에서 `git status`로 확인한 결과입니다.

## 2. 백업

1. 변경한 파일을 커밋합니다(`git add 파일`, `git commit`). 비밀이 들어간 파일(`.env` 등)은 `git status`로 포함되지 않았는지 확인합니다.
2. GitHub 원격 저장소로 올립니다(`git push origin 브랜치이름`). 이 저장소의 원격 주소는 `https://github.com/alska14/choi-bujang-agent`입니다.
3. 제출·재현에 쓴 커밋은 40자리 해시와 브랜치 이름을 `docs/REPRODUCTION_RECORD.md`에 적어 둡니다. 브랜치는 이후에 움직일 수 있으므로 복원 기준은 커밋 해시입니다.
4. 원래 작업 폴더는 지우거나 덮어쓰지 않습니다. 단계별 브랜치(`step-18` ~ `step-22`)와 제출용 브랜치(`submit-17` ~ `submit-21`)를 삭제하지 않고 보존합니다.

## 3. 복원

새 PC나 새 폴더에서 다음을 순서대로 합니다.

1. 빈 폴더에서 `git clone https://github.com/alska14/choi-bujang-agent.git <새 폴더>`를 실행합니다.
2. `git checkout <40자리 커밋 해시>`로 기록해 둔 커밋을 받습니다. 실행용 전체본은 `step-22` 계열 브랜치이며, `submit-*` 브랜치는 판정용으로 파일을 줄여 두어 실행할 수 없습니다.
3. `docs/STUDENT_RUNBOOK.md`의 실행 절차(Node.js 확인, 실행, 브라우저 확인, 종료, 재실행)를 따릅니다. 외부 npm 의존성이 없어 `npm install`은 필요 없습니다.
4. 이전 PC의 `.env`, 인증·설정 파일, `vault`·`registry` 폴더를 복사하지 않습니다. 필요한 설정은 `.env.example`을 보고 환경 변수로 다시 지정하고, 열쇠는 담당자에게 다시 받습니다.

## 4. 제한

- 이 저장소에는 보존할 업무 데이터가 없습니다. 접속 기록·보안 경보·조치 결과의 원본은 접근 제어·XDR 시스템과 운영자 쪽 저장소에 있고, 이 프로젝트는 백업하거나 복원하지 않습니다.
- Git에 올라간 내용은 되돌려도 기록이 남습니다. 비밀값을 실수로 커밋했다면 즉시 담당자에게 알리고 열쇠 교체를 요청합니다. 커밋에서 지우는 것만으로 해결되지 않습니다.
- 복원 절차는 "새 폴더에서 같은 커밋을 받아 서버가 켜지고 기본 화면이 뜨는 것"까지만 이 PC에서 확인했습니다. 실제 시스템 연결, AI 연결, 조치 기록 복원은 해 보지 않았습니다.
- GitHub 저장소가 삭제되거나 접근할 수 없게 되면 원격 백업이 사라집니다. 별도의 오프라인 백업은 만들지 않았습니다.
