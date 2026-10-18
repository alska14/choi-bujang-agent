// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.

const DEVICE_LABEL = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
const SESSION_LABEL = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
const MODE_LABEL = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };

// 알 수 없는 값은 정상으로 바꾸지 않고 확인 불가로 둔다.
// 한글 설명 옆에 서버가 준 원래 상태 코드를 괄호로 함께 보여 준다. 값이 없으면 코드는 unknown 으로 적는다.
const raw = (status) => (typeof status === 'string' && status ? status : 'unknown');
const deviceText = (status) => `${DEVICE_LABEL[status] ?? DEVICE_LABEL.unknown} (${raw(status)})`;
const sessionText = (status) => `${SESSION_LABEL[status] ?? SESSION_LABEL.unknown} (${raw(status)})`;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}

// 정상이 아닌 상태는 색이 아니라 글자로 구분한다.
function row(name, value, abnormal) {
  const item = node('li', null, abnormal ? 'identity-row identity-warning' : 'identity-row');
  item.append(node('strong', `${name}: `), node('span', value));
  return item;
}

function modeNotice(mode) {
  return MODE_LABEL[mode] ? node('p', MODE_LABEL[mode], 'identity-mode') : null;
}

function renderIdentity({ me, devices, sessions } = {}) {
  const root = node('div', null, 'student-identity');
  const notice = modeNotice(me?.mode);
  if (notice) root.append(notice);

  if (!me || me.status === 'loading') {
    root.append(node('p', '불러오는 중', 'identity-loading'));
    return root;
  }
  if (me.status === 'error') {
    // 이전 사용자 값은 남기지 않고 실패만 보여 준다.
    const message = me.error && me.error.message ? me.error.message : '확인 불가';
    root.append(node('p', `연결 실패: ${message}`, 'identity-error'));
    return root;
  }
  if (me.status !== 'ok' || !me.data) {
    root.append(node('p', '확인 불가', 'identity-error'));
    return root;
  }

  const { user, device, session } = me.data;
  const list = node('ul', null, 'identity-list');
  list.append(
    row('사용자', (user && (user.label || user.id)) || '확인 불가', false),
    row('현재 기기', `${(device && (device.label || device.id)) || '확인 불가'} · ${deviceText(device && device.status)}`, !device || device.status !== 'compliant'),
    row('로그인 세션', `${(session && session.id) || '확인 불가'} · ${sessionText(session && session.status)}`, !session || session.status !== 'active'),
  );
  root.append(list);

  root.append(listSection('내 기기', devices, (d) => `${d.label || d.id} · ${deviceText(d.status)}`));
  root.append(listSection('내 세션', sessions, (s) => `${s.id} · ${sessionText(s.status)}`));
  return root;
}

// 기기·세션 목록은 자기 상태를 따로 가진다. 한쪽 실패가 다른 쪽이나 사용자 표시를 지우지 않는다.
function listSection(title, resource, describe) {
  const section = node('div', null, 'identity-section');
  section.append(node('h4', title));
  if (!resource || resource.status === 'loading') {
    section.append(node('p', '불러오는 중'));
  } else if (resource.status === 'error') {
    section.append(node('p', `연결 실패: ${(resource.error && resource.error.message) || '확인 불가'}`, 'identity-error'));
  } else if (resource.status !== 'ok' || !Array.isArray(resource.data)) {
    section.append(node('p', '확인 불가'));
  } else if (resource.data.length === 0) {
    section.append(node('p', '표시할 항목이 없습니다.'));
  } else {
    const list = node('ul', null, 'identity-list');
    for (const item of resource.data) list.append(node('li', describe(item)));
    section.append(list);
  }
  const notice = modeNotice(resource && resource.mode);
  if (notice) section.append(notice);
  return section;
}

// ---------- 14단계: 업무 앱 접근 요청 결과 ----------
const DECISION_LABEL = {
  allow: '접근 허용',
  deny: '접근 거부',
  challenge: '추가 인증 또는 확인 필요',
  unknown: '판정 확인 불가',
};
const DECISION_NOTE = {
  allow: '정책상 접근 허용이라는 뜻이며 실제 앱 접속 성공을 보장하지 않습니다.',
  deny: '정책에 따라 접근이 거부되었습니다.',
  challenge: '추가 확인이 필요합니다. 이 앱은 추가 인증을 대신 수행하지 않습니다.',
  unknown: '판정을 확인할 수 없습니다. 접근이 허용되지 않은 것으로 다룹니다.',
};

function formatChecked(value) {
  if (typeof value !== 'string' || !value) return '시각 정보 없음';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : `${date.toLocaleString('ko-KR')} (${value})`;
}

// 알 수 없는 decision 은 허용으로 보이지 않게 unknown 으로 처리한다. 원래 값은 그대로 함께 적는다.
function renderDecision({ status, mode, data, error, appId } = {}) {
  const root = node('div', null, 'student-decision');
  if (MODE_LABEL[mode]) root.append(node('p', MODE_LABEL[mode], 'decision-mode'));

  if (status === 'idle' || status == null) {
    root.append(node('p', '앱을 골라 접속을 요청하세요', 'decision-idle'));
    return root;
  }
  if (status === 'loading') {
    root.append(node('p', '판정 확인 중', 'decision-loading'));
    return root;
  }
  if (status === 'error') {
    // 요청 실패는 접근 판정이 아니다. 이전 판정 값은 남기지 않는다.
    const message = error && error.message ? error.message : '확인 불가';
    root.append(
      node('p', `요청 실패: ${message}`, 'decision-error'),
      node('p', '요청이 실패한 것이며 접근 거부 판정이 아닙니다. 접근이 허용되었다는 뜻도 아닙니다.', 'decision-note'),
    );
    return root;
  }
  if (status !== 'ok' || !data) {
    root.append(node('p', '판정 확인 불가(unknown). 접근이 허용되지 않은 것으로 다룹니다.', 'decision-unknown'));
    return root;
  }

  const known = Object.prototype.hasOwnProperty.call(DECISION_LABEL, data.decision);
  const code = known ? data.decision : 'unknown';
  const list = node('ul', null, 'decision-list');
  list.append(
    row('대상 앱', data.appId || appId || '확인 불가', false),
    row('판정', `${DECISION_LABEL[code]} (${known ? data.decision : 'unknown'})`, code !== 'allow'),
    row('이유', typeof data.reason === 'string' && data.reason ? data.reason : '이유 정보 없음', false),
    row('판정 시각', formatChecked(data.checkedAt), false),
  );
  root.append(list, node('p', DECISION_NOTE[code], 'decision-note'));
  return root;
}

// ---------- 15단계: 접속 기록·XDR 경보 목록과 상세 ----------
const KIND_NAME = { access: '접속', xdr: 'XDR 경보' };
const ACCESS_STATE = { allowed: '허용됨', denied: '거부됨', unknown: '확인 불가' };
const ALL = 'all';

// 필터·상세 선택은 같은 파일 안에서만 둔다. 새 자료가 오면 모두 지운다.
const eventsUi = { signature: null, kind: ALL, app: ALL, access: ALL, selected: null };

const kindText = (kind) => `${KIND_NAME[kind] ?? '확인 불가'} (${raw(kind)})`;
const accessText = (value) => `${ACCESS_STATE[value] ?? '확인 불가'} (${raw(value)})`;
const appText = (appId) => (typeof appId === 'string' && appId ? appId : '앱 확인 불가 (appId 없음)');

function timeText(at) {
  if (typeof at !== 'string' || !at) return '시각 정보 없음';
  const date = new Date(at);
  return Number.isNaN(date.getTime()) ? at : `${date.toLocaleString('ko-KR')} (${at})`;
}

// 원본 배열은 고치지 않고 복사해 at 기준 최신순으로 정렬한다.
function newestFirst(data) {
  const time = (event) => { const value = Date.parse(event && event.at); return Number.isNaN(value) ? -Infinity : value; };
  return [...data].sort((a, b) => time(b) - time(a));
}

function filterSelect(id, label, options, current, onPick) {
  const wrap = node('div', null, 'events-filter');
  const labelNode = node('label', label);
  labelNode.htmlFor = id;
  const select = document.createElement('select');
  select.id = id;
  for (const [value, text] of options) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = text;
    select.append(option);
  }
  select.value = current;
  select.addEventListener('change', () => onPick(select.value, id));
  wrap.append(labelNode, select);
  return wrap;
}

function listBlock(title, items, emptyText) {
  const block = node('div', null, 'events-detail-block');
  block.append(node('h5', title));
  if (!Array.isArray(items) || items.length === 0) {
    block.append(node('p', emptyText));
    return block;
  }
  const list = node('ul');
  for (const item of items) list.append(node('li', `${raw(item && item.id)}: ${(item && item.text) || '내용 없음'}`));
  block.append(list);
  return block;
}

function detailView(event) {
  const detail = node('div', null, 'events-detail');
  detail.dataset.studentEventDetail = event.id;
  const state = event.state || {};
  detail.append(
    node('h4', `${event.id} 상세`),
    node('p', `사건 ID: ${event.id}`),
    node('p', `업무 앱: ${appText(event.appId)}`),
    listBlock('근거(evidence)', event.evidence, '근거 정보 없음'),
    listBlock('규칙(rules)', event.rules, '규칙 정보 없음'),
  );
  const states = node('div', null, 'events-detail-block');
  states.append(node('h5', '상태'));
  const list = node('ul');
  list.append(
    node('li', `접속 상태(access): ${accessText(state.access)}`),
    node('li', `세션 상태(session): ${sessionText(state.session)}`),
    node('li', `기기 상태(device): ${deviceText(state.device)}`),
  );
  states.append(list);
  detail.append(states);
  const actions = Array.isArray(event.supportedActions) ? event.supportedActions.filter((a) => typeof a === 'string' && a) : [];
  if (actions.length > 0) {
    const block = node('div', null, 'events-detail-block');
    block.append(node('h5', '조치'));
    for (const action of actions) {
      // 조치 연결이 없으므로 요청을 보내지 않는 비활성 버튼만 둔다.
      const button = node('button', `${action} 미지원`);
      button.type = 'button';
      button.disabled = true;
      button.setAttribute('aria-label', `${action} 미지원`);
      block.append(button, node('p', '조치 실행 연결은 준비 중입니다. 이 앱은 조치 요청을 보내지 않습니다.', 'events-action-note'));
    }
    detail.append(block);
  }
  return detail;
}

function drawEvents(root, events, focusId) {
  const uniq = (pick) => [...new Set(events.map(pick))];
  const sorted = newestFirst(events);
  const shown = sorted.filter((event) =>
    (eventsUi.kind === ALL || event.kind === eventsUi.kind)
    && (eventsUi.app === ALL || (event.appId ?? '') === eventsUi.app)
    && (eventsUi.access === ALL || (event.state && event.state.access) === eventsUi.access));
  if (eventsUi.selected && !shown.some((event) => event.id === eventsUi.selected)) eventsUi.selected = null;

  const redraw = (key) => (value, id) => { eventsUi[key] = value; drawEvents(root, events, id); };
  const filters = node('div', null, 'events-filters');
  filters.append(
    filterSelect('student-filter-kind', '기록 종류', [[ALL, '전체'], ...uniq((e) => e.kind).map((v) => [v, kindText(v)])], eventsUi.kind, redraw('kind')),
    filterSelect('student-filter-app', '업무 앱', [[ALL, '전체'], ...uniq((e) => e.appId ?? '').map((v) => [v, appText(v)])], eventsUi.app, redraw('app')),
    filterSelect('student-filter-access', '접속 상태', [[ALL, '전체'], ...uniq((e) => e.state && e.state.access).map((v) => [v, accessText(v)])], eventsUi.access, redraw('access')),
  );

  const list = node('ul', null, 'events-list');
  for (const event of shown) {
    const item = node('li', null, 'events-row');
    item.dataset.studentEventId = event.id;
    item.append(node('span', `${event.id} · ${timeText(event.at)} · ${kindText(event.kind)} · ${appText(event.appId)} · ${event.summary ?? ''}`));
    const button = node('button', `${event.id} 상세`);
    button.type = 'button';
    button.setAttribute('aria-label', `${event.id} 상세`);
    button.setAttribute('aria-expanded', String(eventsUi.selected === event.id));
    button.dataset.focusKey = `detail-${event.id}`;
    button.addEventListener('click', () => {
      eventsUi.selected = eventsUi.selected === event.id ? null : event.id;
      drawEvents(root, events, `detail-${event.id}`);
    });
    item.append(button);
    list.append(item);
  }

  const children = [
    node('p', `전체 ${events.length}건 중 ${shown.length}건 표시 (본인의 최근 기록 범위이며 전체 직원 이력이 아닙니다)`, 'events-count'),
    filters,
    shown.length ? list : node('p', '선택한 조건에 맞는 기록이 없습니다.', 'events-none'),
  ];
  const selected = shown.find((event) => event.id === eventsUi.selected);
  if (selected) children.push(detailView(selected));
  root.replaceChildren(...children);
  if (focusId) {
    const target = [...root.querySelectorAll('select, button')].find((el) => el.id === focusId || el.dataset.focusKey === focusId);
    if (target) target.focus();
  }
}

function renderEvents({ status, mode, data, error } = {}) {
  const root = node('div', null, 'student-events');
  // 새 자료(다시 불러오기 포함)가 오면 이전 필터와 상세 선택을 지운다.
  const signature = JSON.stringify({ status, data: data ?? null, error: error ?? null });
  if (signature !== eventsUi.signature) {
    Object.assign(eventsUi, { signature, kind: ALL, app: ALL, access: ALL, selected: null });
  }
  if (MODE_LABEL[mode]) root.append(node('p', MODE_LABEL[mode], 'events-mode'));

  if (status === 'loading' || status == null) {
    root.append(node('p', '불러오는 중', 'events-loading'));
    return root;
  }
  if (status === 'error') {
    const message = error && error.message ? error.message : '확인 불가';
    root.append(node('p', error && error.code === 'CONTRACT_MISMATCH'
      ? `기록 확인 불가(CONTRACT_MISMATCH): ${message}`
      : `기록을 불러오지 못했습니다: ${message}`, 'events-error'));
    return root;
  }
  if (status !== 'ok' || !Array.isArray(data)) {
    root.append(node('p', '기록 확인 불가: 응답 형식을 확인할 수 없습니다.', 'events-error'));
    return root;
  }
  if (data.length === 0) {
    root.append(node('p', '표시할 기록이 없습니다.', 'events-empty'));
    return root;
  }
  const holder = node('div', null, 'events-body');
  drawEvents(holder, data, null);
  root.append(holder);
  return root;
}

// ---------- 16단계: 알림·빈 상태·오류·진단 정보 ----------
const RETRY_HINT = '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요. 이 앱은 자동으로 다시 요청하지 않습니다.';
const RESOURCE_NAME = { devices: '기기 목록', sessions: '세션', diagnostics: '진단 정보', events: '접속·XDR 기록' };

function isTimeout(error) {
  const text = `${(error && error.code) || ''} ${(error && error.message) || ''}`;
  return /timeout|timed out|시간 초과/i.test(text);
}

function failureBlock(name, error) {
  const message = error && error.message ? error.message : '확인 불가';
  const box = node('div', null, 'status-error');
  box.append(
    node('p', `${name}을(를) 불러오지 못했습니다: ${message}`),
    node('p', isTimeout(error) ? `시간 초과로 응답을 받지 못했습니다. ${RETRY_HINT}` : RETRY_HINT),
  );
  return box;
}

// 기기·세션·진단 각각 loading / ok / error 와 빈 목록을 서로 다른 문장으로 보여 준다.
function resourceSection(title, resource, { emptyText, describe, listLabel }) {
  const section = node('div', null, 'status-section');
  section.append(node('h4', title));
  if (!resource || resource.status === 'loading' || resource.status === 'idle') {
    section.append(node('p', '불러오는 중', 'status-loading'));
  } else if (resource.status === 'error') {
    section.append(failureBlock(title, resource.error));
  } else if (resource.status !== 'ok' || !Array.isArray(resource.data)) {
    section.append(node('p', `${title} 확인 불가: 응답 형식을 확인할 수 없습니다. ${RETRY_HINT}`, 'status-error'));
  } else if (resource.data.length === 0) {
    section.append(node('p', emptyText, 'status-empty'));
  } else {
    const list = node('ul');
    for (const item of resource.data) list.append(node('li', describe(item)));
    section.append(list);
    if (listLabel) section.append(node('p', listLabel, 'status-scope'));
  }
  if (resource && MODE_LABEL[resource.mode]) section.append(node('p', MODE_LABEL[resource.mode], 'status-mode'));
  return section;
}

// 진단 정보는 제공 화면이 전달한 값에서 정해진 6개만 문자열로 꺼낸다. 그 밖의 값(인증·설정 등)은 보여 주거나 복사하지 않는다.
function safeDiagnostics(resource) {
  if (!resource || resource.status !== 'ok' || !resource.data || typeof resource.data !== 'object') return null;
  const data = resource.data;
  const text = (value) => (typeof value === 'string' || typeof value === 'number' ? String(value) : '확인 불가');
  const engine = data.engine && typeof data.engine === 'object' ? data.engine : {};
  return [
    ['requestId', text(data.requestId)],
    ['component', text(data.component)],
    ['version', text(data.version)],
    ['checkedAt', text(data.checkedAt)],
    ['engine.mode', text(engine.mode)],
    ['engine.code', text(engine.code)],
  ];
}

function helpCopyButton(rows, resultNode) {
  const button = node('button', '도움정보 복사');
  button.type = 'button';
  button.setAttribute('aria-label', '도움정보 복사');
  button.addEventListener('click', async () => {
    // 사용자가 누를 때만 복사한다. 복사에 성공했을 때만 성공 문구를 쓴다.
    const body = rows.map(([name, value]) => `${name}: ${value}`).join('\n');
    try {
      await navigator.clipboard.writeText(body);
      resultNode.textContent = '도움 요청에 쓸 점검 정보를 복사했습니다. 비밀번호·토큰·API 키는 포함하지 않습니다.';
    } catch {
      resultNode.textContent = '복사하지 못했습니다. 아래 점검 정보를 직접 선택해 복사하세요.';
    }
  });
  return button;
}

function renderStatus({ devices, sessions, notifications, diagnostics, mode } = {}) {
  const root = node('div', null, 'student-status');
  if (MODE_LABEL[mode]) root.append(node('p', MODE_LABEL[mode], 'status-mode'));

  root.append(resourceSection('등록 기기', devices, {
    emptyText: '등록된 기기가 없습니다.',
    describe: (d) => `${(d && (d.label || d.id)) || '이름 없음'} · ${deviceText(d && d.status)}`,
  }));
  root.append(resourceSection('현재 세션', sessions, {
    emptyText: '현재 연결이 없습니다.',
    describe: (s) => `${(s && s.id) || '확인 불가'} · ${sessionText(s && s.status)}`,
    listLabel: '세션은 지금 검증된 연결 한 개만 보여 주며 지난 세션 목록이 아닙니다.',
  }));

  const noticeSection = node('div', null, 'status-section');
  noticeSection.append(node('h4', '알림'));
  if (!Array.isArray(notifications) || notifications.length === 0) {
    noticeSection.append(node('p', '주의할 알림이 없습니다.', 'status-empty'));
  } else {
    const list = node('ul');
    for (const note of notifications) {
      const resource = RESOURCE_NAME[note && note.resource] ?? raw(note && note.resource);
      list.append(node('li', `${resource} (${raw(note && note.resource)}) · ${raw(note && note.code)}: ${(note && note.message) || '내용 없음'}`));
    }
    noticeSection.append(list);
  }
  root.append(noticeSection);

  const diagSection = node('div', null, 'status-section');
  diagSection.append(node('h4', '진단 정보'));
  const rows = safeDiagnostics(diagnostics);
  const copyResult = node('p', null, 'status-copy-result');
  copyResult.setAttribute('role', 'status');
  if (!diagnostics || diagnostics.status === 'loading' || diagnostics.status === 'idle') {
    diagSection.append(node('p', '진단 정보는 도움정보 영역에서 불러온 뒤에 표시됩니다.', 'status-loading'));
  } else if (diagnostics.status === 'error') {
    diagSection.append(failureBlock('진단 정보', diagnostics.error));
  } else if (!rows) {
    diagSection.append(node('p', `진단 정보 확인 불가: 응답 형식을 확인할 수 없습니다. ${RETRY_HINT}`, 'status-error'));
  } else {
    const list = node('ul');
    for (const [name, value] of rows) list.append(node('li', `${name}: ${value}`));
    diagSection.append(list);
  }
  // 버튼은 진단 정보를 아직 받지 못했을 때도 있다. 그때는 확인 불가 값만 복사한다.
  diagSection.append(helpCopyButton(rows || [['diagnostics', '확인 불가']], copyResult), copyResult);
  root.append(diagSection);
  return root;
}

// ---------- 17단계: 앱 내부 AI 연결 상태 ----------
const AUTHORIZATION_LABEL = { test: '시험 연결 점검(test)', verified: '앱 권한 확인 후 점검(verified)' };
const AI_RETRY = '다시 점검은 사용자가 점검 버튼을 직접 눌러야 합니다. 이 앱은 자동으로 다시 점검하지 않습니다.';

// 안전한 error.code 로 원인을 나눈다. 열쇠나 원문 오류는 쓰지 않고, 모르는 코드는 확인 불가로 둔다.
function classifyAiError(code) {
  const c = String(code ?? '').toUpperCase();
  if (/CANCEL/.test(c)) return ['취소', '점검이 취소되었습니다. 이전 결과는 현재 결과가 아닙니다. 필요하면 직접 다시 점검하세요.'];
  if (/MODEL_LIST_EMPTY|MODEL_NOT_CONFIGURED|NO_MODEL/.test(c)) return ['쓸 수 있는 모델 없음', '현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정 확인을 요청하세요.'];
  if (/PROVISIONING_PENDING|TRANSPORT_PENDING|PENDING|UNVERIFIED/.test(c)) return ['권한 준비 중', '계정 연결과 앱 권한 준비가 끝나지 않았습니다. 학생 잘못이 아닙니다. 담당자에게 계정 연결과 앱 권한 확인을 요청하세요.'];
  if (/AUTH_REQUIRED|INVALID_TOKEN|AUTHENTICATION|UNAUTHORIZED/.test(c)) return ['인증 실패', '인증을 확인하지 못했습니다. 계정 연결을 다시 확인하고, 계속되면 담당자에게 알리세요.'];
  if (/ACCESS_BLOCKED|AUTHORIZATION_CHANGED|FORBIDDEN/.test(c)) return ['접근 제한', 'AI 이용 접근이 제한되었습니다. 계정 연결을 다시 확인하고 담당자에게 현재 권한을 확인하세요.'];
  if (/BUDGET|LIMIT_REACHED|QUOTA/.test(c)) return ['사용량·이용 한도', '반 사용량이나 이용 한도에 도달했습니다. 담당자에게 확인하세요.'];
  if (/SESSION_CLOSED|OUT_OF_HOURS/.test(c)) return ['이용 시간 아님', '지금은 AI 이용 시간이 아닙니다. 이용 시간을 확인하세요.'];
  if (/RATE_LIMITED/.test(c)) return ['요청 제한', 'AI 요청이 잠시 제한되었습니다. 잠시 뒤 직접 다시 점검하세요.'];
  if (/TIMEOUT/.test(c)) return ['시간 초과', 'AI 요청이 시간 안에 끝나지 않았습니다. 잠시 뒤 직접 다시 점검하세요.'];
  if (/NETWORK|SERVER_UNAVAILABLE|UNAVAILABLE/.test(c)) return ['네트워크·서버 연결', 'AI 서버에 연결하지 못했습니다. 잠시 뒤 직접 다시 점검하세요.'];
  return ['확인 불가', '원인을 확인할 수 없습니다. 연결 완료로 보지 않습니다. 담당자에게 위 코드와 함께 문의하세요.'];
}

function renderAiConnection({ status, mode, data, error, checkedAt } = {}) {
  const root = node('div', null, 'student-ai-connection');
  if (MODE_LABEL[mode]) root.append(node('p', MODE_LABEL[mode], 'ai-mode'));

  if (status === 'idle' || status == null) {
    // 점검 전이거나 계정 연결을 다시 해 결과가 비워진 경우다. 이전 결과·오류는 남기지 않는다.
    root.append(node('p', 'AI 연결 점검 전', 'ai-idle'), node('p', '연결 시작과 현재 API 연결 점검은 사용자가 버튼을 직접 눌러 진행합니다.'));
    return root;
  }
  if (status === 'loading') {
    root.append(node('p', 'AI 연결 점검 중', 'ai-loading'));
    return root;
  }
  if (status === 'error') {
    const code = raw(error && error.code);
    const message = error && error.message ? error.message : '확인 불가';
    const [category, guide] = classifyAiError(error && error.code);
    root.append(
      node('p', `AI 연결 점검 실패: ${category}`, 'ai-error'),
      node('p', `오류 코드: ${code}`),
      node('p', `메시지: ${message}`),
      node('p', guide),
      node('p', AI_RETRY),
      node('p', '사건 설명은 실행되지 않았습니다.'),
    );
    return root;
  }
  if (status !== 'ok' || !data || typeof data !== 'object') {
    root.append(node('p', 'AI 연결 확인 불가: 응답 형식을 확인할 수 없습니다. 연결 완료로 보지 않습니다.', 'ai-error'), node('p', AI_RETRY));
    return root;
  }

  const authorization = Object.prototype.hasOwnProperty.call(AUTHORIZATION_LABEL, data.audienceAuthorization)
    ? AUTHORIZATION_LABEL[data.audienceAuthorization]
    : `확인 불가(${raw(data.audienceAuthorization)})`;
  const list = node('ul', null, 'ai-result');
  list.append(
    node('li', `연결 점검: ${data.transportChecked === true ? '완료' : '확인 불가'}`),
    node('li', `점검 종류: ${authorization}`),
    node('li', `확인된 모델 수: ${Number.isFinite(data.modelCount) ? data.modelCount : '확인 불가'}`),
    node('li', `점검 시각: ${timeText(checkedAt)}`),
  );
  root.append(
    node('p', 'AI 연결 점검 결과', 'ai-ok'),
    list,
    node('p', '연결만 점검했고 사건 설명은 아직 실행하지 않았습니다. 모델 목록 응답은 사건 설명이 된 것이 아닙니다.', 'ai-not-explained'),
    node('p', AI_RETRY),
  );
  return root;
}

// 18단계에서 넓힌다. 지금은 선택한 사건의 설명 결과와 실패만 구분한다.
function renderExplanation({ event, explanation } = {}) {
  const root = node('div', null, 'student-explanation');
  if (!event || typeof event.id !== 'string' || !event.id) {
    root.append(node('p', '설명을 볼 사건을 선택하세요.', 'explanation-idle'));
    return root;
  }
  const result = explanation || {};
  if (result.status === 'loading') {
    root.append(node('p', 'AI 설명을 불러오는 중', 'explanation-loading'));
    return root;
  }
  if (result.status === 'error') {
    const message = result.error && result.error.message ? result.error.message : '확인 불가';
    // 연결 점검(모델 목록)이 성공해도 사건 설명 호출은 따로 실패할 수 있다. 원인을 연결 점검과 같은 기준으로 나눠 안내한다.
    const [category, guide] = classifyAiError(result.error && result.error.code);
    root.append(
      node('p', `AI 설명을 받지 못했습니다: ${category}`, 'explanation-error'),
      node('p', `오류 코드: ${raw(result.error && result.error.code)} · 메시지: ${message}`),
      node('p', guide),
      node('p', '사건 설명 호출은 연결 점검과 별개입니다. 연결 점검이 성공했더라도 이 사건의 설명이 성공한 것은 아닙니다.'),
      node('p', '사건 기록은 그대로입니다. 설명 실패는 접속 판정이나 기록을 바꾸지 않습니다. 다시 요청은 사용자가 직접 누릅니다.'),
    );
    return root;
  }
  if (result.status === 'ok' && result.data && typeof result.data.summary === 'string') {
    root.dataset.studentExplanationEvent = event.id;
    root.append(
      node('p', `사건 ID: ${event.id}`),
      node('p', `설명 요약: ${result.data.summary}`),
      node('p', '이 설명은 이 사건에 대한 사건 설명 요청의 응답입니다. 연결 점검(모델 목록)의 결과와 별개입니다.'),
    );
    return root;
  }
  root.append(node('p', 'AI 설명 요청 전이거나 결과를 확인할 수 없습니다. 기록은 그대로입니다.', 'explanation-idle'));
  return root;
}

export function createStudentView() {
  return {
    renderIdentity,
    renderDecision,
    renderEvents,
    renderStatus,
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection,
    renderExplanation,
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
