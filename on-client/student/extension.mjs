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

// ---------- 18단계: 근거에 연결된 AI 사건 설명 ----------
const STATE_NAME = { access: '접속', session: '세션', device: '기기' };
const STATE_KNOWN = {
  access: ['allowed', 'denied'],
  session: ['active', 'expired', 'revoked'],
  device: ['compliant', 'noncompliant'],
};

// 설명 실패 원인. 근거 부족은 따로 구분하고 나머지는 연결 점검과 같은 기준을 쓴다.
function explanationFailure(error) {
  if (/INSUFFICIENT|EVIDENCE/i.test(String((error && error.code) ?? ''))) {
    return ['근거 부족', '이 사건의 근거가 부족하거나 맞지 않아 설명을 만들지 않았습니다. 없는 근거를 지어내 맞추지 않습니다.'];
  }
  return classifyAiError(error && error.code);
}

// 설명을 쓸 수 없을 때의 화면. 성공 표식(data-student-explanation-event)은 붙이지 않는다.
function explanationUnusable(root, title, reason) {
  root.append(
    node('p', title, 'explanation-error'),
    node('p', reason),
    node('p', '사건 기록은 그대로입니다. 이 설명은 화면에 쓰지 않습니다.'),
  );
  return root;
}

function idTextList(title, items, emptyText) {
  const block = node('div', null, 'explanation-block');
  block.append(node('h5', title));
  if (items.length === 0) {
    block.append(node('p', emptyText));
    return block;
  }
  const list = node('ul');
  for (const [id, text] of items) list.append(node('li', `${id} — ${text}`));
  block.append(list);
  return block;
}

function renderExplanation({ event, explanation } = {}) {
  const root = node('div', null, 'student-explanation');
  const result = explanation || {};

  if (result.status === 'error') {
    // event 가 없어도 실패 이유는 먼저 보여 준다.
    const message = result.error && result.error.message ? result.error.message : '확인 불가';
    const [category, guide] = explanationFailure(result.error);
    root.append(
      node('p', `AI 설명 실패: ${category}`, 'explanation-error'),
      node('p', `오류 코드: ${raw(result.error && result.error.code)} · 메시지: ${message}`),
      node('p', guide),
    );
    if (/EXECUT/i.test(String((result.error && result.error.code) ?? ''))) {
      root.append(node('p', 'AI가 조치를 이미 실행했다고 답한 설명은 쓸 수 없습니다.'));
    }
    root.append(
      node('p', '사건 설명 호출은 연결 점검과 별개입니다. 연결 점검이 성공했더라도 이 사건의 설명이 성공한 것은 아닙니다.'),
      node('p', '기록은 그대로입니다. 설명 실패는 접속 판정이나 보안 기록을 바꾸지 않으며 과제 실패도 아닙니다. 다시 요청은 사용자가 직접 누릅니다.'),
    );
    return root;
  }
  if (!event || typeof event.id !== 'string' || !event.id) {
    root.append(node('p', '보안 기록에서 기록을 먼저 고르세요', 'explanation-idle'));
    return root;
  }
  if (result.status === 'loading') {
    root.append(node('p', `${event.id}: AI 설명 요청 중`, 'explanation-loading'));
    return root;
  }
  const data = result.data;
  if (result.status !== 'ok' || !data || typeof data !== 'object') {
    root.append(node('p', `${event.id}: AI 설명 요청 전이거나 결과를 확인할 수 없습니다. 기록은 그대로입니다.`, 'explanation-idle'));
    return root;
  }

  if (data.executed === true) {
    return explanationUnusable(root, 'AI 설명을 쓸 수 없음: 실행 완료로 보고됨', 'AI가 조치를 이미 실행했다고 답한 설명은 쓸 수 없습니다. 이 앱의 설명·제안은 조치를 실행하지 않습니다.');
  }
  if (typeof data.summary !== 'string' || !Array.isArray(data.evidenceIds) || !Array.isArray(data.proposals)
    || data.requiresHumanConfirmation !== true || data.executed !== false) {
    return explanationUnusable(root, 'AI 설명을 쓸 수 없음: 응답 형식 불일치', '설명 응답이 공식 입력 계약(summary, evidenceIds, proposals, requiresHumanConfirmation:true, executed:false)과 맞지 않습니다.');
  }

  // 근거 ID 는 현재 사건의 evidence 와 대조한다. 없는 ID 를 만들어 맞추지 않는다.
  const evidenceById = new Map();
  for (const item of Array.isArray(event.evidence) ? event.evidence : []) {
    if (item && typeof item.id === 'string') evidenceById.set(item.id, typeof item.text === 'string' ? item.text : '내용 없음');
  }
  const cited = (ids) => Array.isArray(ids) && ids.length > 0 && ids.every((id) => typeof id === 'string' && evidenceById.has(id));
  if (!cited(data.evidenceIds)) {
    return explanationUnusable(
      root,
      `AI 설명을 쓸 수 없음: 근거가 맞지 않음 (${event.id})`,
      '설명이 인용한 근거 ID 가 이 사건의 근거 목록에 없거나 인용한 근거가 없습니다. 다른 사건의 설명이거나 근거가 부족한 설명일 수 있어 내용을 표시하지 않습니다.',
    );
  }
  if (data.proposals.some((proposal) => !proposal || !cited(proposal.evidenceIds))) {
    return explanationUnusable(
      root,
      `AI 설명을 쓸 수 없음: 제안의 근거가 맞지 않음 (${event.id})`,
      '제안이 인용한 근거 ID 가 이 사건의 근거 목록에 없습니다. 내용을 표시하지 않습니다.',
    );
  }

  root.dataset.studentExplanationEvent = event.id;
  root.append(
    node('p', `사건 ID: ${event.id}`),
    node('h4', 'AI 설명(참고용)'),
    node('p', data.summary),
    node('p', 'AI 설명은 해석입니다. 사실은 아래 근거 글과 연동 시스템이 알려 준 상태로 판단하세요.'),
    idTextList('인용한 근거', data.evidenceIds.map((id) => [id, evidenceById.get(id)]), '인용한 근거 없음'),
    idTextList(
      '규칙',
      (Array.isArray(event.rules) ? event.rules : []).filter((rule) => rule && typeof rule === 'object').map((rule) => [raw(rule.id), typeof rule.text === 'string' && rule.text ? rule.text : '내용 없음']),
      '규칙 정보 없음',
    ),
  );

  const state = event.state && typeof event.state === 'object' ? event.state : {};
  const unknownRows = Object.keys(STATE_NAME)
    .filter((key) => !STATE_KNOWN[key].includes(state[key]))
    .map((key) => `${STATE_NAME[key]}: 확인 불가(${raw(state[key])})`);
  const stateBlock = node('div', null, 'explanation-block');
  stateBlock.append(node('h5', '확인 불가 상태'));
  if (unknownRows.length === 0) {
    stateBlock.append(node('p', '없음'));
  } else {
    const list = node('ul');
    for (const text of unknownRows) list.append(node('li', text));
    stateBlock.append(list, node('p', '확인 불가는 안전이나 정상이라는 뜻이 아닙니다.'));
  }
  root.append(stateBlock);

  const proposalBlock = node('div', null, 'explanation-block');
  proposalBlock.append(node('h5', '제안'));
  if (data.proposals.length === 0) {
    const supported = Array.isArray(event.supportedActions) ? event.supportedActions.filter((a) => typeof a === 'string' && a) : [];
    proposalBlock.append(node('p', supported.length === 0
      ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상)'
      : 'AI가 제안한 조치가 없습니다.'));
  } else {
    const list = node('ul');
    for (const proposal of data.proposals) {
      list.append(node('li', `조치: ${raw(proposal.action)} · 이유: ${typeof proposal.reason === 'string' && proposal.reason ? proposal.reason : '이유 없음'} · 근거: ${proposal.evidenceIds.join(', ')}`));
    }
    proposalBlock.append(list, node('p', '사람 확인이 필요하며 실행되지 않았습니다'));
  }
  root.append(proposalBlock);
  return root;
}

// ---------- 19단계: 보안 조치 요청 상태와 실제 결과 구분 ----------
// 제안·사람 확인·서버 접수(ACK)·연동 시스템의 효과 관측을 서로 다른 문장으로 보여 준다. 버튼·요청·확인 번호는 다루지 않는다.
const ACTION_STATUS = {
  idle: '아직 미실행(idle)',
  loading: '조치 준비 또는 연동 시스템 결과 조회 중(loading) · 결과가 아직 확인되지 않았습니다',
  prepared: '준비됨·미실행(prepared) · 사람 확인 전이며 아직 실행되지 않았습니다',
  executing: '서버에 전달 중(executing) · 결과가 아직 확인되지 않았습니다',
  pending: '서버 접수·처리 중(pending) · 서버가 받았다는 응답(ACK)은 효과 확인이 아닙니다',
  denied: '연동 시스템 거절(denied)',
  failed: '연동 시스템 실패(failed)',
  unknown: '결과 불명(unknown) · 효과 없음으로도 성공으로도 판단하지 않습니다',
  expired: '확인 기한 지남(expired) · 이번 준비로는 집행할 수 없습니다',
  error: '요청 처리 안 됨(error)',
};
const REQUERY_HINT = '「연동 시스템 결과만 재조회」를 직접 눌러 결과만 다시 조회하세요. 이 앱은 자동으로 다시 조회하지 않습니다.';

function renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error } = {}) {
  const root = node('div', null, 'student-action');
  const code = status == null ? 'idle' : status;
  const eventId = event && typeof event.id === 'string' && event.id ? event.id : null;
  const safeReceipt = receipt && typeof receipt === 'object' ? receipt : null;

  // 현재 사건·조치와 다른 영수증은 다른 요청의 결과이므로 표시하지 않는다.
  if (safeReceipt && ((typeof safeReceipt.eventId === 'string' && safeReceipt.eventId !== eventId)
    || (typeof safeReceipt.actionId === 'string' && typeof actionId === 'string' && safeReceipt.actionId !== actionId))) {
    root.append(
      node('p', `조치 결과 표시 불가: 현재 사건·조치와 맞지 않는 결과입니다(상태 원래 값: ${raw(status)})`, 'action-error'),
      node('p', '다른 사건이나 다른 조치의 결과로 보여 주지 않습니다. 조치 화면은 현재 사건 기준으로 다시 준비해야 합니다.'),
    );
    return root;
  }

  const confirmed = code === 'succeeded' && !!observation && typeof observation === 'object' && observation.effectApplied === true;
  const unconfirmedSucceeded = code === 'succeeded' && !confirmed;
  const known = Object.prototype.hasOwnProperty.call(ACTION_STATUS, code);

  let headline;
  if (confirmed) headline = '효과 확인(succeeded) · 연동 시스템이 관측한 결과입니다';
  else if (unconfirmedSucceeded) headline = '결과 불명(unknown) · 상태는 succeeded 이지만 연동 시스템의 효과 관측(effectApplied: true)이 확인되지 않았습니다';
  else if (known) headline = ACTION_STATUS[code];
  else headline = `조치 상태 확인 불가(${raw(status)}) · 성공으로 다루지 않습니다`;
  root.append(node('p', headline, confirmed ? 'action-observed' : 'action-status'));

  if (code === 'idle') {
    root.append(
      node('p', typeof message === 'string' && message ? message : '조치 제안은 아직 실행되지 않았습니다.'),
      node('p', '이 기록에 연동 시스템이 지원하는 조치(supportedActions)가 없으면 조치 준비 버튼이 나오지 않는 것이 정상입니다.'),
    );
    return root;
  }
  if (code === 'prepared') root.append(node('p', '실행은 제공 화면의 「대상과 조치를 확인했으며 집행합니다」로 사람이 직접 합니다. 이 화면에는 실행 버튼이 없습니다.'));
  if (code === 'pending' || code === 'executing') root.append(node('p', REQUERY_HINT));
  if (code === 'unknown' || unconfirmedSucceeded) root.append(node('p', REQUERY_HINT));
  if (code === 'expired') root.append(node('p', '조치를 다시 준비하세요. 이전 준비의 확인 기한은 지났습니다.'));
  if (code === 'denied' || code === 'failed') {
    const text = typeof message === 'string' && message ? message : (error && error.message) || '메시지 없음';
    root.append(node('p', `메시지: ${text}`));
  }
  if (code === 'error' || (error && (code === 'expired' || code === 'unknown'))) {
    root.append(node('p', `오류 코드: ${raw(error && error.code)} · 메시지: ${(error && error.message) || '확인 불가'}`));
  }

  const rows = [];
  if (eventId) rows.push(['사건 ID', eventId]);
  const evidenceIds = event && Array.isArray(event.evidence) ? event.evidence.map((item) => item && item.id).filter((id) => typeof id === 'string' && id) : [];
  if (evidenceIds.length > 0) rows.push(['근거 ID', evidenceIds.join(', ')]);
  if (typeof actionId === 'string' && actionId) rows.push(['조치(actionId)', actionId]);
  if (target && typeof target === 'object' && typeof target.id === 'string') rows.push(['실제 대상(target.id)', target.id]);
  if (target && typeof target === 'object' && Number.isFinite(target.generation)) rows.push(['대상 세대(generation)', String(target.generation)]);
  if (safeReceipt) {
    if (typeof safeReceipt.requestId === 'string') rows.push(['요청(requestId)', safeReceipt.requestId]);
    if (typeof safeReceipt.receiptId === 'string') rows.push(['영수증(receiptId)', safeReceipt.receiptId]);
    if (Number.isFinite(safeReceipt.version)) rows.push(['버전(version)', String(safeReceipt.version)]);
    if (typeof safeReceipt.replayed === 'boolean') rows.push(['기존 요청 재응답(replayed)', String(safeReceipt.replayed)]);
  }
  if ((code === 'prepared' || code === 'expired') && typeof confirmationExpiresAt === 'string' && confirmationExpiresAt) {
    rows.push(['사람 확인 기한', timeText(confirmationExpiresAt)]);
  }
  if (observation && typeof observation === 'object') {
    rows.push(['연동 시스템 관측 시각(observedAt)', timeText(observation.observedAt)]);
    rows.push(['실제 효과(effectApplied)', `effectApplied: ${raw(String(observation.effectApplied))}`]);
  }
  if (rows.length > 0) {
    const list = node('ul', null, 'action-list');
    for (const [name, value] of rows) list.append(node('li', `${name}: ${value}`));
    root.append(list);
  }
  if (safeReceipt && safeReceipt.superseded === true) root.append(node('p', '이전 조회는 최신 결과를 대신하지 않습니다(superseded).'));

  // 사건과 요청에 묶인 정상 표시에만 붙인다. 진행 전·오류·결과 불명 표시에는 붙이지 않는다.
  const bound = ['prepared', 'executing', 'pending', 'denied', 'failed', 'expired'].includes(code) || confirmed;
  if (bound && eventId && safeReceipt && typeof safeReceipt.requestId === 'string' && safeReceipt.requestId) {
    root.dataset.studentActionEvent = eventId;
    root.dataset.studentActionRequest = safeReceipt.requestId;
  }
  return root;
}

// ---------- 20단계: 설치 패키지 버전과 알려진 취약점 조회 결과 ----------
// 조회 실패·미조회는 취약점 없음이 아니다. 범위(^1.2.0 등)는 설치 버전으로 표시하지 않는다.
const SCAN_STATUS = {
  complete: ['모두 조회(complete)', null],
  partial: ['일부 조회 실패(partial)', '일부 패키지를 끝까지 조회하지 못했습니다. 이미 받은 취약점 ID는 그대로 보여 줍니다.'],
  not_checked: ['아직 조회 안 함(not_checked)', '승인된 공개 조회 대상 패키지가 없어 조회하지 않았습니다. 취약점 없음이 아닙니다.'],
  not_configured: ['조회 준비 미완료(not_configured)', '조회 대상 프로젝트 설정이 필요합니다. 대상 경로와 허용 패키지는 운영자가 준비합니다. 취약점 없음이 아닙니다.'],
  unverifiable: ['lock 파일 확인 불가(unverifiable)', 'package-lock.json을 확인하지 못해 조회하지 않았습니다. 취약점 없음이 아닙니다.'],
};
const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function packageStatusText(pkg, findings) {
  if (pkg.status === 'unverifiable') {
    return findings.length > 0 ? '일부 확인·전체 조회 확인 불가(unverifiable)' : '조회 확인 불가(unverifiable)';
  }
  if (pkg.status === 'known_vulnerabilities') return '알려진 항목 있음(known_vulnerabilities)';
  if (pkg.status === 'none_found') {
    return findings.length > 0
      ? '확인 불가(none_found 이지만 취약점 항목이 함께 전달됨)'
      : '알려진 항목 없음(none_found) · 조회 범위·시점 기준이며 안전을 보장하지 않습니다';
  }
  return `확인 불가(${raw(pkg.status)})`;
}

function packageRow(pkg) {
  const row = node('li', null, 'vulnerabilities-package');
  const info = pkg && typeof pkg === 'object' ? pkg : {};
  const name = typeof info.name === 'string' && info.name ? info.name : null;
  const exact = typeof info.version === 'string' && EXACT_VERSION.test(info.version);
  if (name && exact) {
    row.dataset.studentPackageName = name;
    row.dataset.studentPackageVersion = info.version;
  }
  const findings = Array.isArray(info.vulnerabilities)
    ? info.vulnerabilities.filter((item) => item && typeof item.id === 'string' && item.id)
    : [];
  const lines = node('ul');
  lines.append(
    node('li', `설치 버전: ${exact ? info.version : '확인 불가(정확한 설치 버전이 아니어서 표시하지 않습니다)'}`),
    node('li', `조회 결과: ${packageStatusText(info, findings)}`),
    node('li', `출처: ${typeof info.source === 'string' && info.source ? info.source : '확인 불가'}`),
    node('li', `조회 시각: ${timeText(info.checkedAt)}`),
  );
  row.append(node('strong', name || '이름 확인 불가'), lines);
  if (findings.length > 0) {
    const list = node('ul', null, 'vulnerabilities-findings');
    for (const item of findings) list.append(node('li', `${item.id} · 수정 시각(modified): ${timeText(item.modified)}`));
    row.append(node('p', info.status === 'unverifiable' ? '이미 받은 취약점 ID (전체 조회는 확인 불가):' : '취약점 ID:'), list);
  }
  return row;
}

function renderVulnerabilities({ status, mode, data, error } = {}) {
  const root = node('div', null, 'student-vulnerabilities');
  if (MODE_LABEL[mode]) root.append(node('p', MODE_LABEL[mode], 'vulnerabilities-mode'));

  if (status === 'idle' || status == null) {
    root.append(node('p', '조회 전', 'vulnerabilities-idle'), node('p', '설치 패키지 조회는 사용자가 버튼을 직접 눌러 시작합니다.'));
    return root;
  }
  if (status === 'loading') {
    root.append(node('p', '조회 중', 'vulnerabilities-loading'));
    return root;
  }
  if (status === 'error') {
    root.append(
      node('p', `조회 실패: ${(error && error.message) || '확인 불가'}`, 'vulnerabilities-error'),
      node('p', `오류 코드: ${raw(error && error.code)}`),
      node('p', '조회 실패는 취약점 없음이 아닙니다. 이전 결과는 현재 확인 결과가 아닙니다. 다시 조회는 사용자가 직접 누릅니다.'),
    );
    return root;
  }
  if (status !== 'ok' || !data || typeof data !== 'object' || !Object.prototype.hasOwnProperty.call(SCAN_STATUS, data.status)) {
    root.append(
      node('p', '조회 결과 확인 불가: 응답 형식을 확인할 수 없습니다.', 'vulnerabilities-error'),
      node('p', '취약점 없음으로 보지 않습니다. 다시 조회는 사용자가 직접 누릅니다.'),
    );
    return root;
  }

  const packages = Array.isArray(data.packages) ? data.packages : [];
  const [label, note] = SCAN_STATUS[data.status];
  root.append(node('p', `전체 조회 상태: ${label}`, 'vulnerabilities-status'));
  if (note) root.append(node('p', note));
  if (data.status === 'complete' && packages.some((pkg) => !pkg || pkg.status === 'unverifiable')) {
    root.append(node('p', '일부 패키지가 조회 확인 불가입니다. 모두 조회된 것으로 보지 않습니다.', 'vulnerabilities-error'));
  }

  const meta = node('ul', null, 'vulnerabilities-meta');
  if (data.lockfileVersion != null) meta.append(node('li', `lockfileVersion: ${raw(String(data.lockfileVersion))}`));
  if (typeof data.lockfileHash === 'string' && data.lockfileHash) meta.append(node('li', `lockfileHash: ${data.lockfileHash}`));
  if (typeof data.checkedAt === 'string' && data.checkedAt) meta.append(node('li', `checkedAt: ${timeText(data.checkedAt)}`));
  if (meta.children.length > 0) root.append(meta);

  if (packages.length === 0) {
    root.append(node('p', data.status === 'complete'
      ? '조회한 패키지가 없습니다.'
      : '패키지별 결과가 없습니다. 조회하지 않았거나 확인하지 못한 것이며 취약점 없음이 아닙니다.', 'vulnerabilities-empty'));
  } else {
    const count = (value) => packages.filter((pkg) => pkg && pkg.status === value).length;
    root.append(node('p', `패키지 ${packages.length}개: 알려진 항목 있음 ${count('known_vulnerabilities')} · 알려진 항목 없음 ${count('none_found')} · 조회 확인 불가 ${count('unverifiable')}`));
    const list = node('ul', null, 'vulnerabilities-list');
    for (const pkg of packages) list.append(packageRow(pkg));
    root.append(list);
  }
  root.append(node('p', 'package-lock.json과 설치된 node_modules 메타데이터를 대조한 값입니다. OSV는 알려진 취약점 데이터베이스이며, 조회 결과가 없다는 사실만으로 패키지나 앱 전체가 안전하다고 보장할 수 없습니다.', 'vulnerabilities-scope'));
  return root;
}

export function createStudentView() {
  return {
    renderIdentity,
    renderDecision,
    renderEvents,
    renderStatus,
    renderVulnerabilities,
    renderAiConnection,
    renderExplanation,
    renderAction,
  };
}
