// 긴급 사건이 처음 생겼을 때 화면 맨 위에 뜨는 Windows 팝업을 띄운다(브라우저가 최소화돼 있어도 보인다).
// 메시지는 환경 변수로 넘기며 스크립트에 문자열을 끼워 넣지 않는다. 같은 사건은 한 번만, 팝업 사이에는 최소 간격을 둔다.
import { spawn } from 'node:child_process';

const POPUP_SCRIPT = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { [System.Media.SystemSounds]::Hand.Play() } catch {}
$form = New-Object System.Windows.Forms.Form
$form.Text = $env:SOC_ALERT_TITLE
$form.TopMost = $true
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(620, 300)
$form.BackColor = [System.Drawing.Color]::FromArgb(158, 18, 32)
$form.ForeColor = [System.Drawing.Color]::White
$form.FormBorderStyle = 'FixedDialog'
$form.MinimizeBox = $false
$form.MaximizeBox = $false
$label = New-Object System.Windows.Forms.Label
$label.Text = $env:SOC_ALERT_TEXT
$label.Font = New-Object System.Drawing.Font('Malgun Gothic', 13, [System.Drawing.FontStyle]::Bold)
$label.Dock = 'Top'
$label.Height = 230
$label.Padding = New-Object System.Windows.Forms.Padding(16)
$button = New-Object System.Windows.Forms.Button
$button.Text = '확인했음'
$button.Dock = 'Bottom'
$button.Height = 46
$button.BackColor = [System.Drawing.Color]::White
$button.ForeColor = [System.Drawing.Color]::Black
$button.DialogResult = 'OK'
$form.Controls.Add($label)
$form.Controls.Add($button)
$form.AcceptButton = $button
$form.Add_Shown({ $form.Activate(); $form.BringToFront() })
[void]$form.ShowDialog()`;

const clean = (value, max) => String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max);

export const POPUP_TITLE_PREFIX = '긴급 보안 경보';

function defaultLaunch(env) {
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-STA', '-WindowStyle', 'Hidden', '-Command', POPUP_SCRIPT], { env: { ...process.env, ...env }, detached: true, stdio: 'ignore' });
  child.on('error', () => {});
  child.unref();
  return child.pid;
}

export function createNativeAlerter({ enabled = true, cooldownMs = 30000, launch = defaultLaunch, now = () => Date.now(), platform = process.platform } = {}) {
  let lastAt = -Infinity;
  const status = { enabled: Boolean(enabled) && platform === 'win32', launched: 0, suppressed: 0, lastError: null };
  return Object.freeze({
    status: () => ({ ...status }),
    // 긴급(critical) 사건만 팝업을 띄운다. 반환값: 'launched' | 'disabled' | 'not-critical' | 'cooldown' | 'failed'
    alert(event) {
      if (!status.enabled) return 'disabled';
      if (!event || event.severity !== 'critical') return 'not-critical';
      const t = now();
      if (t - lastAt < cooldownMs) { status.suppressed += 1; return 'cooldown'; }
      try {
        launch({
          SOC_ALERT_TITLE: `${POPUP_TITLE_PREFIX}${event.test ? ' (시험)' : ''}`,
          SOC_ALERT_TEXT: `${event.test ? '[시험 경보: 실제 사건 아님]\n' : ''}${clean(event.title, 120)}\n\n${clean(event.detail, 200)}\n\n관제 화면: http://127.0.0.1:5189/pc-status`,
        });
        lastAt = t;
        status.launched += 1;
        return 'launched';
      } catch (error) {
        status.lastError = clean(error && error.code, 40) || 'LAUNCH_FAILED';
        return 'failed';
      }
    },
  });
}
