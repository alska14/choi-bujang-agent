# ALEPH 방어전: 1~22단계, XDR 보너스, 최종 앱 한눈에 보기

ALEPH BYTE BACK 4차 방어전에서 한 일을 순서대로 정리한 안내 페이지입니다. 코드는 두 저장소에 나뉘어 있어서, 어디에 뭐가 있는지부터 적습니다.

| 무엇 | 어디서 보나 |
|---|---|
| **1~12단계**(일부러 뚫린 가상 자료실을 막기) | 저장소 [choi-bujang-secret-vault](https://github.com/alska14/choi-bujang-secret-vault) |
| **XDR 보너스 6개** | 같은 저장소의 [`xdr/`](https://github.com/alska14/choi-bujang-secret-vault/tree/main/xdr) 폴더 |
| **13~22단계**(보안 Agent 「Djoković」 만들기) | 이 저장소. 단계별 브랜치는 아래 표 |
| **최종 앱**(마지막 총공세) | 이 저장소의 [`final-app`](https://github.com/alska14/choi-bujang-agent/tree/final-app) 브랜치 |
| **설치형 앱** | 이 저장소의 [Releases](https://github.com/alska14/choi-bujang-agent/releases/latest) |

> 이 페이지(`main` 브랜치)는 안내용입니다. 코드는 아래 표의 브랜치에 있습니다.

---

## 1~12단계: 가상 자료실 막기

저장소: [choi-bujang-secret-vault](https://github.com/alska14/choi-bujang-secret-vault). 단계별 풀이는 [`docs/steps/`](https://github.com/alska14/choi-bujang-secret-vault/tree/main/docs/steps), 한 장 요약은 [`docs/DEFENSE_STEPS.md`](https://github.com/alska14/choi-bujang-secret-vault/blob/main/docs/DEFENSE_STEPS.md)에 있습니다.

| 단계 | 한 일 |
|---|---|
| 1 | 출발점. 뚫린 자료실을 배포하고 저장소를 공개 |
| 2 | 자료를 코드 밖(Supabase)으로 옮김 |
| 3 | 진짜 로그인과 토큰 검사 |
| 4 | 소유자 비교. 남의 메모는 404 |
| 5 | 요청을 서버 한곳으로 모으고, DB 직접 접근 권한 회수 |
| 6 | 등록된 기기만 접근 허용 |
| 7 | 위험 신호가 둘 이상 겹치면 추가 확인(step_up) |
| 8 | 자원 구역(내 메모, 수업 공지)을 나눔 |
| 9 | 조회 폭주 탐지(10분에 120건 초과) |
| 10 | 정책 사본 복원, 메모 한 건 복원 |
| 11 | 설치형 자료실 화면, 서버가 정하는 기기 승인 |
| 12 | 판정·탐지·회수·복구 결과를 한 화면과 표로 |

## XDR 보너스 6개

같은 저장소의 [`xdr/`](https://github.com/alska14/choi-bujang-secret-vault/tree/main/xdr)에 있습니다.

| 모듈 | 보는 것 |
|---|---|
| brute-force | 짧은 시간에 몰린 로그인 실패 |
| web-injection | 웹 요청에 섞인 주입 공격 |
| known-cve | 공개된 취약점 악용 |
| persistence | 서비스·예약 작업 심기 |
| privilege | 권한 상승 |
| exfiltration | 큰 전송으로 자료 빼돌리기 |

## 13~22단계: 보안 Agent 「Djoković」

수업에서 받은 시작 틀(`on-client`)의 `student/extension.mjs`를 단계마다 채워 갔습니다.

| 단계 | 만든 것 | 코드 보기 |
|---|---|---|
| 13 | 로그인 사용자·기기·세션 화면(`renderIdentity`) | [`main`](https://github.com/alska14/choi-bujang-agent/tree/main/on-client) |
| 14 | 업무 앱 접근 판정과 이유(`renderDecision`) | `main` |
| 15 | 접속 기록·XDR 경보 목록과 필터, 상세(`renderEvents`) | `main` |
| 16 | 알림·기기·세션·오류·재시도·진단(`renderStatus`) | `main` |
| 17 | AI 연결 상태와 사건 설명 기본(`renderAiConnection`, `renderExplanation`) | `main` |
| 18 | 설명에 근거·규칙·확인 불가 상태 붙이기 | [`step-18`](https://github.com/alska14/choi-bujang-agent/tree/step-18) |
| 19 | 제안·사람 확인·실행 결과 관측을 구분(`renderAction`) | [`step-19`](https://github.com/alska14/choi-bujang-agent/tree/step-19) |
| 20 | 설치 버전과 OSV 취약점 결과(`renderVulnerabilities`) | [`step-20`](https://github.com/alska14/choi-bujang-agent/tree/step-20) |
| 21 | 학생용 실행 설명서와 구성도 | [`step-21`](https://github.com/alska14/choi-bujang-agent/tree/step-21) |
| 22 | 새 폴더에서 다시 실행한 재현 기록, 데이터 보존 계획 | [`step-22`](https://github.com/alska14/choi-bujang-agent/tree/step-22) |

18~22단계는 단계별 완성본(`step-NN`)과 제출용(`submit-NN`) 브랜치로 나눠 올렸습니다. 제출용은 심사에 필요한 파일만 남긴 것입니다.

## 최종 앱: 마지막 총공세

[`final-app`](https://github.com/alska14/choi-bujang-agent/tree/final-app) 브랜치입니다. 22단계 결과 위에 케셰브 앱을 완성했고, 안내 문서는 `on-client/docs/`에 있습니다.

**수업 시간에 한 것**
- 내 PC 상태: CPU·메모리·디스크 실측과 추이
- 네트워크·방화벽·Windows 기록 읽기 전용 조회, 기존 서버(SDP) 미연결 표시
- 처음 보는 사람용 빠른 실행 안내, 시연·정리 문서([`FINAL_REPORT.md`](https://github.com/alska14/choi-bujang-agent/blob/final-app/on-client/docs/FINAL_REPORT.md))

**그 위에 덧붙인 보안 관제**
- 네트워크·엔드포인트·계정 3개 영역 점검과 실시간 알림, 위협 인텔리전스(IOC·ATT&CK)
- KISA PC 점검(PC-01~18)과 승인·되돌리기가 있는 조치
- AI 에이전트(Claude Code·Codex)의 파일 접근 감시
- 데스크톱 앱(알림 영역 아이콘, 막대 없는 미니 창), 암호화한 설치 파일, 자동 업데이트
- 자세한 사용법은 [`SOC_GUIDE.md`](https://github.com/alska14/choi-bujang-agent/blob/final-app/on-client/docs/SOC_GUIDE.md), 그림 설명서는 [`SOC_MANUAL.md`](https://github.com/alska14/choi-bujang-agent/blob/final-app/on-client/docs/SOC_MANUAL.md)

제공된 서버(`src/server.mjs`), 화면(`public/`), 학생 코드(`student/`)는 이 덧붙임 과정에서 바꾸지 않았습니다.

## 설치형 앱 받기

[Releases](https://github.com/alska14/choi-bujang-agent/releases/latest)에서 `Djokovic-SOC-Setup-*.exe`를 받습니다. 프로그램 파일이 설치 비밀번호로 암호화돼 있어 비밀번호를 입력해야 설치됩니다(비밀번호는 저장소에 없습니다). 서명이 없는 프로그램이라 다른 PC에서 받으면 Windows 보안 경고가 한 번 뜰 수 있습니다.

## 직접 실행해 보기

Node.js 22~24가 필요합니다. `final-app` 브랜치를 받아 `on-client` 폴더에서 실행합니다.

```
git clone -b final-app https://github.com/alska14/choi-bujang-agent.git
cd choi-bujang-agent/on-client
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-final.ps1
```

실행하면 `http://127.0.0.1:5189`(케셰브 앱)와 `http://127.0.0.1:5189/pc-status`(보안 관제)가 열립니다.
