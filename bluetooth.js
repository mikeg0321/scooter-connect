/**
 * NinebotCrypto — AES-CCM encryption for Segway-Ninebot scooters.
 * Ported from scooterhacking/NinebotCrypto C++/C# reference.
 */
class NinebotCrypto {
  static FW = new Uint8Array([0x97,0xCF,0xB8,0x02,0x84,0x41,0x43,0xDE,0x56,0x00,0x2B,0x3B,0x34,0x78,0x0A,0x5D]);

  constructor() {
    this.name = new Uint8Array(16);
    this.ble = new Uint8Array(16);
    this.app = new Uint8Array(16);
    this.key = null;
    this.it = 0;
  }

  async init(deviceName) {
    this.name.fill(0);
    const b = new TextEncoder().encode(deviceName || '');
    this.name.set(b.slice(0, 16));
    await this._sha(this.name, NinebotCrypto.FW);
  }

  async _sha(d1, d2) {
    const c = new Uint8Array(32);
    c.set(d1.slice(0, 16), 0);
    c.set(d2.slice(0, 16), 16);
    this.key = new Uint8Array(await crypto.subtle.digest('SHA-1', c)).slice(0, 16);
  }

  async _aes(plain, key) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
    const r = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, k, plain);
    return new Uint8Array(r).slice(0, 16);
  }

  async _first(src) {
    const k = await this._aes(NinebotCrypto.FW, this.key);
    const dst = new Uint8Array(src.length);
    for (let i = 0; i < src.length; i++) dst[i] = src[i] ^ k[i % 16];
    return dst;
  }

  async _next(src, it) {
    const dst = new Uint8Array(src.length);
    const n = new Uint8Array(16);
    n[0] = 1;
    n[1] = (it >>> 24) & 0xFF; n[2] = (it >>> 16) & 0xFF;
    n[3] = (it >>> 8) & 0xFF;  n[4] = it & 0xFF;
    n.set(this.ble.slice(0, 8), 5);
    let idx = 0, rem = src.length;
    while (rem > 0) {
      n[15]++;
      const k = await this._aes(n, this.key);
      const cl = Math.min(rem, 16);
      for (let i = 0; i < cl; i++) dst[idx + i] = src[idx + i] ^ k[i];
      rem -= cl; idx += cl;
    }
    return dst;
  }

  _crcFirst(p) {
    let s = 0; for (let i = 0; i < p.length; i++) s += p[i];
    const c = (~s) & 0xFFFF;
    return [c & 0xFF, (c >> 8) & 0xFF];
  }

  async _crcNext(data, it) {
    const pLen = data.length - 3;
    const b0 = new Uint8Array(16);
    b0[0] = 0x59;
    b0[1] = (it >>> 24) & 0xFF; b0[2] = (it >>> 16) & 0xFF;
    b0[3] = (it >>> 8) & 0xFF;  b0[4] = it & 0xFF;
    b0.set(this.ble.slice(0, 8), 5);
    b0[15] = pLen & 0xFF;
    let x = await this._aes(b0, this.key);
    const hb = new Uint8Array(16); hb.set(data.slice(0, 3));
    const xh = new Uint8Array(16);
    for (let i = 0; i < 16; i++) xh[i] = hb[i] ^ x[i];
    x = await this._aes(xh, this.key);
    let bi = 3, rem = pLen;
    while (rem > 0) {
      const cl = Math.min(rem, 16);
      const blk = new Uint8Array(16); blk.set(data.slice(bi, bi + cl));
      const xb = new Uint8Array(16);
      for (let i = 0; i < 16; i++) xb[i] = blk[i] ^ x[i];
      x = await this._aes(xb, this.key);
      rem -= cl; bi += cl;
    }
    const a0 = new Uint8Array(16);
    a0[0] = 1;
    a0[1] = (it >>> 24) & 0xFF; a0[2] = (it >>> 16) & 0xFF;
    a0[3] = (it >>> 8) & 0xFF;  a0[4] = it & 0xFF;
    a0.set(this.ble.slice(0, 8), 5);
    const s0 = await this._aes(a0, this.key);
    return [x[0]^s0[0], x[1]^s0[1], x[2]^s0[2], x[3]^s0[3]];
  }

  async encrypt(data) {
    const hdr = data.slice(0, 3);
    const body = data.slice(3);
    const pLen = body.length;
    const out = new Uint8Array(data.length + 6);
    out.set(hdr);
    if (this.it === 0) {
      const crc = this._crcFirst(body);
      const enc = await this._first(body);
      out.set(enc, 3);
      out[pLen+5] = crc[0]; out[pLen+6] = crc[1];
      this.it++;
      if (data[5] === 0x5C && data[6] === 0x00 && data.length >= 23)
        this.app.set(data.slice(7, 23));
    } else {
      this.it++;
      const crc = await this._crcNext(data, this.it);
      const enc = await this._next(body, this.it);
      out.set(enc, 3);
      out[pLen+3] = crc[0]; out[pLen+4] = crc[1]; out[pLen+5] = crc[2]; out[pLen+6] = crc[3];
      out[pLen+7] = (this.it >>> 8) & 0xFF; out[pLen+8] = this.it & 0xFF;
      if (data[5] === 0x5C && data[6] === 0x00 && data.length >= 23)
        this.app.set(data.slice(7, 23));
    }
    return out;
  }

  async decrypt(data) {
    const hdr = data.slice(0, 3);
    const enc = data.slice(3, data.length - 6);
    let mi = this.it;
    if ((mi & 0x8000) > 0 && (data[data.length - 2] >> 7) === 0) mi += 0x10000;
    mi = (mi & 0xFFFF0000) + (data[data.length - 2] << 8) + data[data.length - 1];
    const out = new Uint8Array(hdr.length + enc.length);
    out.set(hdr);
    if (mi === 0) {
      out.set(await this._first(enc), 3);
      if (out[3] === 0x21 && out[4] === 0x3E && out[5] === 0x5B) {
        this.ble.set(out.slice(7, 23));
        await this._sha(this.name, this.ble);
      }
    } else {
      out.set(await this._next(enc, mi), 3);
      if (out[5] === 0x5C && out[6] === 0x01)
        await this._sha(this.app, this.ble);
      this.it = mi;
    }
    return out;
  }
}

/**
 * ScooterBLE — Segway-Ninebot E2 Pro BLE controller with NinebotCrypto.
 */
class ScooterBLE {
  static SVC = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
  static TX  = '6e400002-b5a3-f393-e0a9-e50e24dcca9e';
  static RX  = '6e400003-b5a3-f393-e0a9-e50e24dcca9e';

  static REG_BATTERY = 0x22; static REG_SPEED = 0x26; static REG_MILEAGE = 0x29;
  static REG_LOCK = 0x70; static REG_UNLOCK = 0x71;
  static REG_NORMAL_LIMIT = 0x73; static REG_SPEED_MODE = 0x75;
  static REG_CRUISE = 0x7C; static REG_TAILLIGHT = 0x7D;

  constructor() {
    this.device = null; this.server = null;
    this.txChar = null; this.rxChar = null;
    this.crypto = null;
    this.onData = null; this.onDisconnect = null;
    this.authenticated = false;
    this._debugLog = null;
    this._rxBuf = null; this._rxExpected = 0;
    this._pendingResolve = null; this._pendingTimeout = null;
    this._pendingCmd = null;
    this._rxQueue = [];
  }

  static isSupported() { return !!navigator.bluetooth; }
  get isConnected() { return this.device && this.device.gatt.connected; }

  _log(msg) { console.log('[BLE]', msg); if (this._debugLog) this._debugLog(msg); }

  static _delay(ms) { return new Promise(r => setTimeout(r, ms)); }

  static packet(src, dst, cmd, idx, seg = []) {
    return new Uint8Array([0x5A, 0xA5, seg.length, src, dst, cmd, idx, ...seg]);
  }

  async connect() {
    this.device = await navigator.bluetooth.requestDevice({
      acceptAllDevices: true,
      optionalServices: [ScooterBLE.SVC, '0000ffe0-0000-1000-8000-00805f9b34fb', 'battery_service'],
    });
    this.device.addEventListener('gattserverdisconnected', () => {
      this.authenticated = false;
      if (this.onDisconnect) this.onDisconnect();
    });
    this.server = await this.device.gatt.connect();
    this._log(`GATT connected to ${this.device.name}`);

    // Find Nordic UART service
    try {
      const svc = await this.server.getPrimaryService(ScooterBLE.SVC);
      this._log('Nordic UART: FOUND');
      const chars = await svc.getCharacteristics();
      for (const ch of chars) {
        const p = ch.properties;
        const id = ch.uuid.slice(4, 8);
        const flags = [p.read?'R':'', p.write?'W':'', p.writeWithoutResponse?'Wn':'', p.notify?'N':'', p.indicate?'I':''].filter(Boolean).join(',');
        this._log(`  ${id}: ${flags} [${ch.uuid}]`);

        const uuid = ch.uuid.toLowerCase();
        if (uuid === ScooterBLE.TX || uuid.includes('6e400002')) { this.txChar = ch; this._log('  -> TX assigned'); }
        if (uuid === ScooterBLE.RX || uuid.includes('6e400003')) { this.rxChar = ch; this._log('  -> RX assigned'); }
      }
    } catch (e) {
      this._log(`Nordic UART: NOT FOUND (${e.message})`);
    }

    // Fallback: try FFE0
    if (!this.txChar) {
      try {
        const svc = await this.server.getPrimaryService('0000ffe0-0000-1000-8000-00805f9b34fb');
        this._log('FFE0: FOUND');
        const chars = await svc.getCharacteristics();
        for (const ch of chars) {
          const p = ch.properties;
          this._log(`  ${ch.uuid.slice(4,8)}: ${[p.read?'R':'',p.write?'W':'',p.writeWithoutResponse?'Wn':'',p.notify?'N':''].filter(Boolean).join(',')}`);
          if (p.writeWithoutResponse || p.write) { this.txChar = ch; this._log('  -> TX assigned'); }
          if (p.notify) { this.rxChar = ch; this._log('  -> RX assigned'); }
        }
      } catch { this._log('FFE0: not found'); }
    }

    // Last resort: match by properties if UUID matching failed
    if (!this.txChar || !this.rxChar) {
      this._log('Trying property-based char matching...');
      try {
        const svc = await this.server.getPrimaryService(ScooterBLE.SVC);
        const chars = await svc.getCharacteristics();
        for (const ch of chars) {
          const p = ch.properties;
          if (!this.txChar && (p.write || p.writeWithoutResponse)) {
            this.txChar = ch;
            this._log(`  -> TX (by props): ${ch.uuid}`);
          }
          if (!this.rxChar && p.notify) {
            this.rxChar = ch;
            this._log(`  -> RX (by props): ${ch.uuid}`);
          }
        }
      } catch {}
    }

    if (!this.txChar) { this._log('!! NO TX CHAR !!'); }
    if (!this.rxChar) { this._log('!! NO RX CHAR !!'); }

    // Subscribe to RX notifications
    if (this.rxChar) {
      try {
        await this.rxChar.startNotifications();
        this.rxChar.addEventListener('characteristicvaluechanged', (e) => {
          this._onRx(new Uint8Array(e.target.value.buffer));
        });
        this._log('RX notifications: subscribed');
      } catch (e) {
        this._log(`RX subscribe FAILED: ${e.message}`);
      }
    }

    // Init crypto and authenticate
    this.crypto = new NinebotCrypto();
    await this.crypto.init(this.device.name);
    this._log(`Crypto init: name="${this.device.name}" key=${Array.from(this.crypto.key.slice(0,4)).map(b=>b.toString(16).padStart(2,'0')).join('')}...`);

    await this._auth();
    return this.device.name || 'Unknown Scooter';
  }

  disconnect() {
    if (this.device && this.device.gatt.connected) this.device.gatt.disconnect();
    this.device = null; this.server = null;
    this.txChar = null; this.rxChar = null;
    this.authenticated = false; this.crypto = null;
  }

  // Send encrypted packet
  async _send(rawPacket) {
    if (!this.txChar) throw new Error('No TX characteristic');
    const enc = await this.crypto.encrypt(rawPacket);
    const hex = Array.from(enc).map(b => b.toString(16).padStart(2, '0')).join(' ');
    this._log(`TX ${enc.length}b: ${hex}`);
    const useResp = this.txChar.properties.write && !this.txChar.properties.writeWithoutResponse;
    for (let i = 0; i < enc.length; i += 20) {
      const chunk = enc.slice(i, i + 20);
      if (useResp) await this.txChar.writeValueWithResponse(chunk);
      else await this.txChar.writeValueWithoutResponse(chunk);
    }
  }

  _onRx(chunk) {
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    this._log(`RX ${chunk.length}b: ${hex}`);

    // Accumulate encrypted packet
    if (chunk.length >= 2 && chunk[0] === 0x5A && chunk[1] === 0xA5) {
      this._rxBuf = new Uint8Array(chunk);
      this._rxExpected = chunk.length >= 3 ? chunk[2] + 13 : 999;
      this._log(`RX expect ${this._rxExpected}b (bLen=${chunk[2]})`);
    } else if (this._rxBuf) {
      const m = new Uint8Array(this._rxBuf.length + chunk.length);
      m.set(this._rxBuf); m.set(chunk, this._rxBuf.length);
      this._rxBuf = m;
      this._log(`RX accum ${this._rxBuf.length}/${this._rxExpected}b`);
    } else {
      if (this._pendingResolve) {
        clearTimeout(this._pendingTimeout);
        this._pendingResolve({ raw: chunk });
        this._pendingResolve = null;
      }
      return;
    }

    if (this._rxBuf && this._rxBuf.length >= this._rxExpected) {
      const pktData = this._rxBuf.slice(0, this._rxExpected);
      this._rxBuf = null;
      this._processPacket(pktData);
    }
  }

  async _processPacket(encrypted) {
    try {
      const dec = await this.crypto.decrypt(encrypted);
      const hex = Array.from(dec).map(b => b.toString(16).padStart(2, '0')).join(' ');
      this._log(`DEC: ${hex}`);
      const pkt = { src: dec[3], dst: dec[4], cmd: dec[5], idx: dec[6], data: dec.slice(7) };

      // Only resolve pending if this matches what we're waiting for, or is an auth response
      const isAuthResp = (pkt.cmd === 0x5B || pkt.cmd === 0x5C || pkt.cmd === 0x5D);
      const isExpected = !this._pendingCmd || isAuthResp ||
        pkt.cmd === 0x04 || pkt.cmd === 0x05;

      if (this._pendingResolve && isExpected) {
        clearTimeout(this._pendingTimeout);
        this._pendingResolve(pkt);
        this._pendingResolve = null;
        this._pendingCmd = null;
      }
      if ((pkt.cmd === 0x04 || pkt.cmd === 0x05) && this.onData) this.onData(pkt);
    } catch (e) {
      this._log(`Decrypt err: ${e.message}`);
      if (this._pendingResolve) {
        clearTimeout(this._pendingTimeout);
        this._pendingResolve({ error: e.message, raw: encrypted });
        this._pendingResolve = null;
        this._pendingCmd = null;
      }
    }
  }

  _waitResp(ms = 5000, cmd = null) {
    return new Promise((resolve, reject) => {
      this._pendingCmd = cmd;
      this._pendingTimeout = setTimeout(() => {
        this._pendingResolve = null;
        this._pendingCmd = null;
        reject(new Error('Timeout'));
      }, ms);
      this._pendingResolve = resolve;
    });
  }

  async _auth() {
    if (!this.txChar || !this.rxChar) {
      this._log('Cannot auth: missing TX or RX');
      return;
    }

    // Retry auth up to 3 times
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        this._log(`Auth retry ${attempt}/2...`);
        this.crypto = new NinebotCrypto();
        await this.crypto.init(this.device.name);
        await ScooterBLE._delay(1000);
      }

      try {
        // Step 1: INIT
        this._log('Auth: sending INIT...');
        const initPkt = ScooterBLE.packet(0x3E, 0x21, 0x5B, 0x00);
        const w1 = this._waitResp(8000, 0x5B);
        await this._send(initPkt);
        const r1 = await w1;
        if (r1.error) { this._log(`INIT decrypt failed: ${r1.error}`); continue; }
        if (r1.raw) { this._log('INIT: got raw (non-5AA5) response'); continue; }
        this._log(`INIT resp: cmd=0x${r1.cmd.toString(16)} idx=${r1.idx} data=${r1.data.length}b`);

        if (r1.data.length >= 16) {
          const bleHex = Array.from(r1.data.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
          this._log(`INIT bleData: ${bleHex}`);
          this._log(`INIT rekey: ${Array.from(this.crypto.key.slice(0,4)).map(b=>b.toString(16).padStart(2,'0')).join('')}...`);
        }

        // Small delay to let Bluefy + scooter settle after INIT
        await ScooterBLE._delay(300);

        // Step 2: PING
        const appKey = new Uint8Array(16);
        crypto.getRandomValues(appKey);
        this._log(`Auth: sending PING (appKey=${Array.from(appKey.slice(0,4)).map(b=>b.toString(16).padStart(2,'0')).join('')}...)...`);
        const pingPkt = ScooterBLE.packet(0x3E, 0x21, 0x5C, 0x00, Array.from(appKey));
        const w2 = this._waitResp(8000, 0x5C);
        await this._send(pingPkt);
        const r2 = await w2;
        if (r2.error) { this._log(`PING decrypt failed: ${r2.error}`); continue; }
        if (r2.raw) { this._log('PING: got raw response'); continue; }
        this._log(`PING resp: cmd=0x${r2.cmd.toString(16)} idx=${r2.idx}`);

        // Step 3: PAIR if needed (idx=0 means not yet paired, need button press)
        if (r2.idx === 0 && r1.data.length >= 16) {
          const serial = r1.data.slice(16);
          const serialStr = new TextDecoder().decode(serial);
          this._log(`PAIR needed — press scooter POWER BUTTON now! Serial: ${serialStr}`);
          for (let i = 0; i < 10; i++) {
            await ScooterBLE._delay(500);
            const pairPkt = ScooterBLE.packet(0x3E, 0x21, 0x5D, 0x00, Array.from(serial));
            const w3 = this._waitResp(3000, 0x5C);
            await this._send(pairPkt);
            try {
              const r3 = await w3;
              this._log(`PAIR ${i}: cmd=0x${(r3.cmd||0).toString(16)} idx=${r3.idx}`);
              if (r3.cmd === 0x5C && r3.idx === 1) {
                this._log('PAIR accepted!');
                break;
              }
            } catch { this._log(`PAIR ${i}: timeout (press power button!)`); }
          }
        }

        this.authenticated = true;
        this._log('AUTH SUCCESS');
        return;
      } catch (e) {
        this._log(`AUTH attempt ${attempt} FAILED: ${e.message}`);
      }
    }

    this._log('AUTH FAILED after 3 attempts — falling back to unencrypted');
    this.authenticated = false;
    this.crypto = { encrypt: async (d) => d, decrypt: async (d) => d };
  }

  // Commands (encrypted)
  async writeRegister(reg, value) {
    const pkt = ScooterBLE.packet(0x3E, 0x20, 0x02, reg, [value & 0xFF, (value >> 8) & 0xFF]);
    await this._send(pkt);
  }

  async readRegister(reg, numRegs = 2) {
    const pkt = ScooterBLE.packet(0x3E, 0x20, 0x01, reg, [numRegs]);
    const w = this._waitResp(3000);
    await this._send(pkt);
    try { return await w; } catch { return null; }
  }

  async setSpeedMode(mode) { await this.writeRegister(ScooterBLE.REG_SPEED_MODE, mode); }
  async setSpeedLimit(kmh) {
    await this.writeRegister(ScooterBLE.REG_NORMAL_LIMIT, Math.max(50, Math.min(650, Math.round(kmh * 10))));
  }
  async setCruiseControl(on) { await this.writeRegister(ScooterBLE.REG_CRUISE, on ? 1 : 0); }
  async setTailLight(on) { await this.writeRegister(ScooterBLE.REG_TAILLIGHT, on ? 1 : 0); }
  async setLock(lock) { await this.writeRegister(lock ? ScooterBLE.REG_LOCK : ScooterBLE.REG_UNLOCK, 1); }

  async requestBattery() {
    try {
      const svc = await this.server.getPrimaryService('battery_service');
      const ch = await svc.getCharacteristic('battery_level');
      return (await ch.readValue()).getUint8(0);
    } catch {}
    await this.readRegister(ScooterBLE.REG_BATTERY, 2);
    return null;
  }
  async requestSpeed() { await this.readRegister(ScooterBLE.REG_SPEED, 2); }
  async requestMileage() { await this.readRegister(ScooterBLE.REG_MILEAGE, 4); }

  static parseResponse(pkt) {
    if (!pkt || !pkt.data || pkt.data.length === 0) return null;
    const d = pkt.data;
    const u16 = (i) => (d[i]||0) | ((d[i+1]||0) << 8);
    const u32 = (i) => u16(i) | (u16(i+2) << 16);
    switch (pkt.idx) {
      case 0x22: return { type: 'battery', value: u16(0) };
      case 0x26: return { type: 'speed', value: Math.round(u16(0)/10*10)/10 };
      case 0x29: return { type: 'distance', value: Math.round(u32(0)/100)/10 };
      default: return { type: 'register', register: pkt.idx, data: Array.from(d) };
    }
  }
}
