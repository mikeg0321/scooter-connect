const ble = new ScooterBLE();

// DOM elements
const connectScreen   = document.getElementById('connect-screen');
const dashboardScreen = document.getElementById('dashboard-screen');
const btnConnect      = document.getElementById('btn-connect');
const btnDisconnect   = document.getElementById('btn-disconnect');
const connectError    = document.getElementById('connect-error');
const btUnsupported   = document.getElementById('bt-unsupported');
const deviceNameEl    = document.getElementById('device-name');
const statBattery     = document.getElementById('stat-battery');
const statSpeed       = document.getElementById('stat-speed');
const statDistance     = document.getElementById('stat-distance');
const speedSlider     = document.getElementById('speed-slider');
const sliderValue     = document.getElementById('slider-value');
const btnApplySpeed   = document.getElementById('btn-apply-speed');
const modeBtns        = document.querySelectorAll('.mode-btn');
const toggleCruise    = document.getElementById('toggle-cruise');
const toggleTaillight = document.getElementById('toggle-taillight');
const btnLock         = document.getElementById('btn-lock');
const persistCheck    = document.getElementById('persist-speed');
const logArea         = document.getElementById('log');

let locked = false;
let pollInterval = null;

// ── Persistent Settings (localStorage) ──

const STORAGE_KEY = 'scooterlink_settings';

function loadSettings() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
  } catch { return {}; }
}

function saveSettings(updates) {
  const settings = { ...loadSettings(), ...updates };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

function restoreUI() {
  const s = loadSettings();
  if (s.speedLimit != null) {
    speedSlider.value = s.speedLimit;
    sliderValue.textContent = s.speedLimit + ' km/h';
  }
  if (s.speedMode != null) {
    modeBtns.forEach(b => {
      b.classList.toggle('active', parseInt(b.dataset.mode) === s.speedMode);
    });
  }
  if (s.cruise != null) toggleCruise.checked = s.cruise;
  if (s.taillight != null) toggleTaillight.checked = s.taillight;
  if (s.persist != null) persistCheck.checked = s.persist;
}

/** Auto-apply all saved settings to the scooter on connect */
async function applyPersistedSettings() {
  const s = loadSettings();
  if (!s.persist && s.persist !== undefined) return;

  log('Applying saved settings...', 'warn');

  try {
    if (s.speedMode != null) {
      await ble.setSpeedMode(s.speedMode);
      log(`Restored speed mode: ${s.speedMode}`, 'success');
    }
    if (s.speedLimit != null) {
      await ble.setSpeedLimit(s.speedLimit);
      log(`Restored speed limit: ${s.speedLimit} km/h`, 'success');
    }
    if (s.cruise != null) {
      await ble.setCruiseControl(s.cruise);
    }
    if (s.taillight != null) {
      await ble.setTailLight(s.taillight);
    }
    log('All settings applied!', 'success');
  } catch (e) {
    log(`Auto-apply error: ${e.message}`, 'error');
  }
}

// ── Init ──

if (!ScooterBLE.isSupported()) {
  btUnsupported.classList.remove('hidden');
  btnConnect.disabled = true;
}

restoreUI();

// ── Logging ──

function log(msg, level = '') {
  const time = new Date().toLocaleTimeString();
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `<span class="log-time">${time}</span><span class="log-${level}">${msg}</span>`;
  logArea.prepend(entry);
  while (logArea.children.length > 200) logArea.lastChild.remove();
}

// ── Connection ──

btnConnect.addEventListener('click', async () => {
  connectError.classList.add('hidden');
  btnConnect.disabled = true;
  btnConnect.textContent = 'Scanning...';

  try {
    // Wire BLE debug logging to activity log
    ble._debugLog = (msg) => log(msg, 'warn');
    btnConnect.textContent = 'Connecting...';
    const name = await ble.connect();

    showDashboard(name);
  } catch (e) {
    if (e.name !== 'NotFoundError' && e.message !== 'User cancelled the requestDevice() chooser.') {
      connectError.textContent = e.message;
      connectError.classList.remove('hidden');
    }
  } finally {
    btnConnect.disabled = false;
    btnConnect.textContent = 'Scan for Scooters';
  }
});

btnDisconnect.addEventListener('click', () => {
  ble.disconnect();
  showConnectScreen();
  log('Disconnected by user', 'warn');
});

ble.onDisconnect = () => {
  showConnectScreen();
  log('Connection lost', 'error');
};

// Handle telemetry data from scooter
ble.onData = (pkt) => {
  const parsed = ScooterBLE.parseResponse(pkt);
  if (!parsed) return;

  switch (parsed.type) {
    case 'battery':
      statBattery.textContent = parsed.value + '%';
      break;
    case 'speed':
      statSpeed.textContent = parsed.value;
      break;
    case 'distance':
      statDistance.textContent = parsed.value;
      break;
    case 'mode':
      modeBtns.forEach(b => {
        b.classList.toggle('active', parseInt(b.dataset.mode) === parsed.value);
      });
      break;
    default:
      log(`Data: reg=0x${(parsed.register || 0).toString(16)} [${parsed.data || ''}]`);
  }
};

async function showDashboard(name) {
  connectScreen.classList.add('hidden');
  dashboardScreen.classList.remove('hidden');
  deviceNameEl.textContent = name;
  log(`Connected to ${name}`, 'success');

  await applyPersistedSettings();

  // Start polling for telemetry
  pollScooterData();
  pollInterval = setInterval(pollScooterData, 5000);
}

function showConnectScreen() {
  dashboardScreen.classList.add('hidden');
  connectScreen.classList.remove('hidden');
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

async function pollScooterData() {
  if (!ble.isConnected) return;
  try {
    const battery = await ble.requestBattery();
    if (battery !== null) statBattery.textContent = battery + '%';
  } catch {}
  try { await ble.requestSpeed(); } catch {}
  try { await ble.requestMileage(); } catch {}
}

// ── Speed Modes (Eco=1, Drive/Normal=0, Sport=2) ──

modeBtns.forEach(btn => {
  btn.addEventListener('click', async () => {
    const mode = parseInt(btn.dataset.mode);
    const speed = parseInt(btn.dataset.speed);

    modeBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    speedSlider.value = speed;
    sliderValue.textContent = speed + ' km/h';

    saveSettings({ speedMode: mode, speedLimit: speed });

    try {
      await ble.setSpeedMode(mode);
      await ble.setSpeedLimit(speed);
      log(`Mode: ${btn.querySelector('.mode-name').textContent} (${speed} km/h)`, 'success');
    } catch (e) {
      log(`Failed to set mode: ${e.message}`, 'error');
    }
  });
});

// ── Custom Speed Slider ──

speedSlider.addEventListener('input', () => {
  sliderValue.textContent = speedSlider.value + ' km/h';
  modeBtns.forEach(b => b.classList.remove('active'));
});

btnApplySpeed.addEventListener('click', async () => {
  const speed = parseInt(speedSlider.value);
  btnApplySpeed.disabled = true;
  btnApplySpeed.textContent = 'Applying...';

  saveSettings({ speedLimit: speed, speedMode: null });

  try {
    await ble.setSpeedLimit(speed);
    log(`Speed limit: ${speed} km/h`, 'success');
  } catch (e) {
    log(`Failed to set speed: ${e.message}`, 'error');
  } finally {
    btnApplySpeed.disabled = false;
    btnApplySpeed.textContent = 'Apply Speed Limit';
  }
});

// ── Persist toggle ──

persistCheck.addEventListener('change', () => {
  saveSettings({ persist: persistCheck.checked });
  log(`Auto-apply on connect: ${persistCheck.checked ? 'ON' : 'OFF'}`, 'success');
});

// ── Settings Toggles ──

toggleCruise.addEventListener('change', async () => {
  saveSettings({ cruise: toggleCruise.checked });
  try {
    await ble.setCruiseControl(toggleCruise.checked);
    log(`Cruise control ${toggleCruise.checked ? 'ON' : 'OFF'}`, 'success');
  } catch (e) {
    log(`Cruise control failed: ${e.message}`, 'error');
    toggleCruise.checked = !toggleCruise.checked;
    saveSettings({ cruise: toggleCruise.checked });
  }
});

toggleTaillight.addEventListener('change', async () => {
  saveSettings({ taillight: toggleTaillight.checked });
  try {
    await ble.setTailLight(toggleTaillight.checked);
    log(`Tail light ${toggleTaillight.checked ? 'ON' : 'OFF'}`, 'success');
  } catch (e) {
    log(`Tail light failed: ${e.message}`, 'error');
    toggleTaillight.checked = !toggleTaillight.checked;
    saveSettings({ taillight: toggleTaillight.checked });
  }
});

btnLock.addEventListener('click', async () => {
  locked = !locked;
  try {
    await ble.setLock(locked);
    btnLock.textContent = locked ? 'Unlock' : 'Lock';
    btnLock.className = locked ? 'btn-small btn-primary' : 'btn-small btn-danger';
    log(`Scooter ${locked ? 'LOCKED' : 'UNLOCKED'}`, locked ? 'warn' : 'success');
  } catch (e) {
    locked = !locked;
    log(`Lock failed: ${e.message}`, 'error');
  }
});
