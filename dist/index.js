var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: (newValue) => all[name] = () => newValue
    });
};
var __esm = (fn, res) => () => (fn && (res = fn(fn = 0)), res);

// node_modules/@noble/hashes/esm/_assert.js
function isBytes(a) {
  return a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
}
var number, bytes, hash, exists, output;
var init__assert = __esm(() => {
  number = function(n) {
    if (!Number.isSafeInteger(n) || n < 0)
      throw new Error(`positive integer expected, not ${n}`);
  };
  bytes = function(b, ...lengths) {
    if (!isBytes(b))
      throw new Error("Uint8Array expected");
    if (lengths.length > 0 && !lengths.includes(b.length))
      throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
  };
  hash = function(h) {
    if (typeof h !== "function" || typeof h.create !== "function")
      throw new Error("Hash should be wrapped by utils.wrapConstructor");
    number(h.outputLen);
    number(h.blockLen);
  };
  exists = function(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished)
      throw new Error("Hash#digest() has already been called");
  };
  output = function(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
  };
});

// node_modules/@noble/hashes/esm/crypto.js
var crypto;
var init_crypto = __esm(() => {
  crypto = typeof globalThis === "object" && ("crypto" in globalThis) ? globalThis.crypto : undefined;
});

// node_modules/@noble/hashes/esm/utils.js
function byteSwap32(arr) {
  for (let i = 0;i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  bytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    bytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function wrapXOFConstructorWithOpts(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto && typeof crypto.getRandomValues === "function") {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto && typeof crypto.randomBytes === "function") {
    return crypto.randomBytes(bytesLength);
  }
  throw new Error("crypto.getRandomValues must be defined");
}

class Hash {
  clone() {
    return this._cloneInto();
  }
}
var u32, createView, rotr, isLE, byteSwap, toStr;
var init_utils = __esm(() => {
  init_crypto();
  init__assert();
  /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  rotr = (word, shift) => word << 32 - shift | word >>> shift;
  isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
  byteSwap = (word) => word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  toStr = {}.toString;
});

// node_modules/@noble/hashes/esm/hmac.js
class HMAC extends Hash {
  constructor(hash2, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    hash(hash2);
    const key = toBytes(_key);
    this.iHash = hash2.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash2.create().update(key).digest() : key);
    for (let i = 0;i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash2.create();
    for (let i = 0;i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf) {
    exists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    exists(this);
    bytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
}
var hmac;
var init_hmac = __esm(() => {
  init__assert();
  init_utils();
  hmac = (hash2, key, message) => new HMAC(hash2, key).update(message).digest();
  hmac.create = (hash2, key) => new HMAC(hash2, key);
});

// node_modules/@noble/hashes/esm/_md.js
class HashMD extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    exists(this);
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0;pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (;blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    exists(this);
    output(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos;i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0;i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor);
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
}
var setBigUint64, Chi, Maj;
var init__md = __esm(() => {
  init__assert();
  init_utils();
  setBigUint64 = function(view, byteOffset, value, isLE2) {
    if (typeof view.setBigUint64 === "function")
      return view.setBigUint64(byteOffset, value, isLE2);
    const _32n = BigInt(32);
    const _u32_max = BigInt(4294967295);
    const wh = Number(value >> _32n & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE2 ? 4 : 0;
    const l = isLE2 ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE2);
    view.setUint32(byteOffset + l, wl, isLE2);
  };
  Chi = (a, b, c) => a & b ^ ~a & c;
  Maj = (a, b, c) => a & b ^ a & c ^ b & c;
});

// node_modules/@noble/hashes/esm/sha256.js
class SHA256 extends HashMD {
  constructor() {
    super(64, 32, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0;i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16;i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0;i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    SHA256_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
}
var SHA256_K, SHA256_IV, SHA256_W, sha256;
var init_sha256 = __esm(() => {
  init__md();
  init_utils();
  SHA256_K = new Uint32Array([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  SHA256_IV = new Uint32Array([
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
  ]);
  SHA256_W = new Uint32Array(64);
  sha256 = wrapConstructor(() => new SHA256);
});

// node_modules/@noble/hashes/esm/_u64.js
var fromBig, split, U32_MASK64, _32n, rotlSH, rotlSL, rotlBH, rotlBL;
var init__u64 = __esm(() => {
  fromBig = function(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  };
  split = function(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0;i < lst.length; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  };
  U32_MASK64 = BigInt(2 ** 32 - 1);
  _32n = BigInt(32);
  rotlSH = (h, l, s) => h << s | l >>> 32 - s;
  rotlSL = (h, l, s) => l << s | h >>> 32 - s;
  rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
  rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
});

// node_modules/@noble/curves/esm/abstract/utils.js
var exports_utils = {};
__export(exports_utils, {
  validateObject: () => {
    {
      return validateObject;
    }
  },
  utf8ToBytes: () => {
    {
      return utf8ToBytes2;
    }
  },
  numberToVarBytesBE: () => {
    {
      return numberToVarBytesBE;
    }
  },
  numberToHexUnpadded: () => {
    {
      return numberToHexUnpadded;
    }
  },
  numberToBytesLE: () => {
    {
      return numberToBytesLE;
    }
  },
  numberToBytesBE: () => {
    {
      return numberToBytesBE;
    }
  },
  notImplemented: () => {
    {
      return notImplemented;
    }
  },
  memoized: () => {
    {
      return memoized;
    }
  },
  isBytes: () => {
    {
      return isBytes2;
    }
  },
  inRange: () => {
    {
      return inRange;
    }
  },
  hexToNumber: () => {
    {
      return hexToNumber;
    }
  },
  hexToBytes: () => {
    {
      return hexToBytes;
    }
  },
  equalBytes: () => {
    {
      return equalBytes;
    }
  },
  ensureBytes: () => {
    {
      return ensureBytes;
    }
  },
  createHmacDrbg: () => {
    {
      return createHmacDrbg;
    }
  },
  concatBytes: () => {
    {
      return concatBytes2;
    }
  },
  bytesToNumberLE: () => {
    {
      return bytesToNumberLE;
    }
  },
  bytesToNumberBE: () => {
    {
      return bytesToNumberBE;
    }
  },
  bytesToHex: () => {
    {
      return bytesToHex;
    }
  },
  bitSet: () => {
    {
      return bitSet;
    }
  },
  bitMask: () => {
    {
      return bitMask;
    }
  },
  bitLen: () => {
    {
      return bitLen;
    }
  },
  bitGet: () => {
    {
      return bitGet;
    }
  },
  abytes: () => {
    {
      return abytes;
    }
  },
  abool: () => {
    {
      return abool;
    }
  },
  aInRange: () => {
    {
      return aInRange;
    }
  }
});
function isBytes2(a) {
  return a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
}
function abytes(item) {
  if (!isBytes2(item))
    throw new Error("Uint8Array expected");
}
function abool(title, value) {
  if (typeof value !== "boolean")
    throw new Error(`${title} must be valid boolean, got "${value}".`);
}
function bytesToHex(bytes2) {
  abytes(bytes2);
  let hex = "";
  for (let i = 0;i < bytes2.length; i++) {
    hex += hexes[bytes2[i]];
  }
  return hex;
}
function numberToHexUnpadded(num) {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return BigInt(hex === "" ? "0" : `0x${hex}`);
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("padded hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0;ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function bytesToNumberBE(bytes2) {
  return hexToNumber(bytesToHex(bytes2));
}
function bytesToNumberLE(bytes2) {
  abytes(bytes2);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes2).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function numberToVarBytesBE(n) {
  return hexToBytes(numberToHexUnpadded(n));
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(`${title} must be valid hex string, got "${hex}". Cause: ${e}`);
    }
  } else if (isBytes2(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(`${title} must be hex string or Uint8Array`);
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(`${title} expected ${expectedLength} bytes, got ${len}`);
  return res;
}
function concatBytes2(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0;i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function utf8ToBytes2(str) {
  if (typeof str !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str));
}
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error(`expected valid ${title}: ${min} <= n < ${max}, got ${typeof n} ${n}`);
}
function bitLen(n) {
  let len;
  for (len = 0;n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
function bitGet(n, pos) {
  return n >> BigInt(pos) & _1n;
}
function bitSet(n, pos, value) {
  return n | (value ? _1n : _0n) << BigInt(pos);
}
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  if (typeof hashLen !== "number" || hashLen < 2)
    throw new Error("hashLen must be a number");
  if (typeof qByteLen !== "number" || qByteLen < 2)
    throw new Error("qByteLen must be a number");
  if (typeof hmacFn !== "function")
    throw new Error("hmacFn must be a function");
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b) => hmacFn(k, v, ...b);
  const reseed = (seed = u8n()) => {
    k = h(u8fr([0]), seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(u8fr([1]), seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= 1000)
      throw new Error("drbg: tried 1000 values");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = undefined;
    while (!(res = pred(gen())))
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
function validateObject(object, validators, optValidators = {}) {
  const checkField = (fieldName, type, isOptional) => {
    const checkVal = validatorFns[type];
    if (typeof checkVal !== "function")
      throw new Error(`Invalid validator "${type}", expected function`);
    const val = object[fieldName];
    if (isOptional && val === undefined)
      return;
    if (!checkVal(val, object)) {
      throw new Error(`Invalid param ${String(fieldName)}=${val} (${typeof val}), expected ${type}`);
    }
  };
  for (const [fieldName, type] of Object.entries(validators))
    checkField(fieldName, type, false);
  for (const [fieldName, type] of Object.entries(optValidators))
    checkField(fieldName, type, true);
  return object;
}
function memoized(fn) {
  const map = new WeakMap;
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== undefined)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}
var asciiToBase16, _0n, _1n, _2n, hexes, asciis, isPosBig, bitMask, u8n, u8fr, validatorFns, notImplemented;
var init_utils2 = __esm(() => {
  asciiToBase16 = function(char) {
    if (char >= asciis._0 && char <= asciis._9)
      return char - asciis._0;
    if (char >= asciis._A && char <= asciis._F)
      return char - (asciis._A - 10);
    if (char >= asciis._a && char <= asciis._f)
      return char - (asciis._a - 10);
    return;
  };
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  _0n = BigInt(0);
  _1n = BigInt(1);
  _2n = BigInt(2);
  hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
  asciis = { _0: 48, _9: 57, _A: 65, _F: 70, _a: 97, _f: 102 };
  isPosBig = (n) => typeof n === "bigint" && _0n <= n;
  bitMask = (n) => (_2n << BigInt(n - 1)) - _1n;
  u8n = (data) => new Uint8Array(data);
  u8fr = (arr) => Uint8Array.from(arr);
  validatorFns = {
    bigint: (val) => typeof val === "bigint",
    function: (val) => typeof val === "function",
    boolean: (val) => typeof val === "boolean",
    string: (val) => typeof val === "string",
    stringOrUint8Array: (val) => typeof val === "string" || isBytes2(val),
    isSafeInteger: (val) => Number.isSafeInteger(val),
    array: (val) => Array.isArray(val),
    field: (val, object) => object.Fp.isValid(val),
    hash: (val) => typeof val === "function" && Number.isSafeInteger(val.outputLen)
  };
  notImplemented = () => {
    throw new Error("not implemented");
  };
});

// node_modules/@noble/curves/esm/abstract/modular.js
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow(num, power, modulo) {
  if (modulo <= _0n2 || power < _0n2)
    throw new Error("Expected power/modulo > 0");
  if (modulo === _1n2)
    return _0n2;
  let res = _1n2;
  while (power > _0n2) {
    if (power & _1n2)
      res = res * num % modulo;
    num = num * num % modulo;
    power >>= _1n2;
  }
  return res;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number2, modulo) {
  if (number2 === _0n2 || modulo <= _0n2) {
    throw new Error(`invert: expected positive integers, got n=${number2} mod=${modulo}`);
  }
  let a = mod(number2, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function tonelliShanks(P) {
  const legendreC = (P - _1n2) / _2n2;
  let Q, S, Z;
  for (Q = P - _1n2, S = 0;Q % _2n2 === _0n2; Q /= _2n2, S++)
    ;
  for (Z = _2n2;Z < P && pow(Z, legendreC, P) !== P - _1n2; Z++)
    ;
  if (S === 1) {
    const p1div4 = (P + _1n2) / _4n;
    return function tonelliFast(Fp, n) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
      return root;
    };
  }
  const Q1div2 = (Q + _1n2) / _2n2;
  return function tonelliSlow(Fp, n) {
    if (Fp.pow(n, legendreC) === Fp.neg(Fp.ONE))
      throw new Error("Cannot find square root");
    let r = S;
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q);
    let x = Fp.pow(n, Q1div2);
    let b = Fp.pow(n, Q);
    while (!Fp.eql(b, Fp.ONE)) {
      if (Fp.eql(b, Fp.ZERO))
        return Fp.ZERO;
      let m = 1;
      for (let t2 = Fp.sqr(b);m < r; m++) {
        if (Fp.eql(t2, Fp.ONE))
          break;
        t2 = Fp.sqr(t2);
      }
      const ge = Fp.pow(g, _1n2 << BigInt(r - m - 1));
      g = Fp.sqr(ge);
      x = Fp.mul(x, ge);
      b = Fp.mul(b, g);
      r = m;
    }
    return x;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n) {
    const p1div4 = (P + _1n2) / _4n;
    return function sqrt3mod4(Fp, n) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
      return root;
    };
  }
  if (P % _8n === _5n) {
    const c1 = (P - _5n) / _8n;
    return function sqrt5mod8(Fp, n) {
      const n2 = Fp.mul(n, _2n2);
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n2), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.eql(Fp.sqr(root), n))
        throw new Error("Cannot find square root");
      return root;
    };
  }
  if (P % _16n === _9n) {
  }
  return tonelliShanks(P);
}
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "isSafeInteger",
    BITS: "isSafeInteger"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  return validateObject(field, opts);
}
function FpPow(f, num, power) {
  if (power < _0n2)
    throw new Error("Expected power > 0");
  if (power === _0n2)
    return f.ONE;
  if (power === _1n2)
    return num;
  let p = f.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = f.mul(p, d);
    d = f.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(f, nums) {
  const tmp = new Array(nums.length);
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (f.is0(num))
      return acc;
    tmp[i] = acc;
    return f.mul(acc, num);
  }, f.ONE);
  const inverted = f.inv(lastMultiplied);
  nums.reduceRight((acc, num, i) => {
    if (f.is0(num))
      return acc;
    tmp[i] = f.mul(acc, tmp[i]);
    return f.mul(acc, num);
  }, inverted);
  return tmp;
}
function nLength(n, nBitLength) {
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLen2, isLE2 = false, redef = {}) {
  if (ORDER <= _0n2)
    throw new Error(`Expected Field ORDER > 0, got ${ORDER}`);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen2);
  if (BYTES > 2048)
    throw new Error("Field lengths over 2048 bytes are not supported");
  const sqrtP = FpSqrt(ORDER);
  const f = Object.freeze({
    ORDER,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error(`Invalid field element: expected bigint, got ${typeof num}`);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || ((n) => sqrtP(f, n)),
    invertBatch: (lst) => FpInvertBatch(f, lst),
    cmov: (a, b, c) => c ? b : a,
    toBytes: (num) => isLE2 ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes2) => {
      if (bytes2.length !== BYTES)
        throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes2.length}`);
      return isLE2 ? bytesToNumberLE(bytes2) : bytesToNumberBE(bytes2);
    }
  });
  return Object.freeze(f);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE2 = false) {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error(`expected ${minLen}-1024 bytes of input, got ${len}`);
  const num = isLE2 ? bytesToNumberBE(key) : bytesToNumberLE(key);
  const reduced = mod(num, fieldOrder - _1n2) + _1n2;
  return isLE2 ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}
var _0n2, _1n2, _2n2, _3n, _4n, _5n, _8n, _9n, _16n, FIELD_FIELDS;
var init_modular = __esm(() => {
  init_utils2();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  _0n2 = BigInt(0);
  _1n2 = BigInt(1);
  _2n2 = BigInt(2);
  _3n = BigInt(3);
  _4n = BigInt(4);
  _5n = BigInt(5);
  _8n = BigInt(8);
  _9n = BigInt(9);
  _16n = BigInt(16);
  FIELD_FIELDS = [
    "create",
    "isValid",
    "is0",
    "neg",
    "inv",
    "sqrt",
    "sqr",
    "eql",
    "add",
    "sub",
    "mul",
    "pow",
    "div",
    "addN",
    "subN",
    "mulN",
    "sqrN"
  ];
});

// node_modules/@noble/curves/esm/abstract/curve.js
function wNAF(c, bits) {
  const constTimeNegate = (condition, item) => {
    const neg = item.negate();
    return condition ? neg : item;
  };
  const validateW = (W) => {
    if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
      throw new Error(`Wrong window size=${W}, should be [1..${bits}]`);
  };
  const opts = (W) => {
    validateW(W);
    const windows = Math.ceil(bits / W) + 1;
    const windowSize = 2 ** (W - 1);
    return { windows, windowSize };
  };
  return {
    constTimeNegate,
    unsafeLadder(elm, n) {
      let p = c.ZERO;
      let d = elm;
      while (n > _0n3) {
        if (n & _1n3)
          p = p.add(d);
        d = d.double();
        n >>= _1n3;
      }
      return p;
    },
    precomputeWindow(elm, W) {
      const { windows, windowSize } = opts(W);
      const points = [];
      let p = elm;
      let base = p;
      for (let window = 0;window < windows; window++) {
        base = p;
        points.push(base);
        for (let i = 1;i < windowSize; i++) {
          base = base.add(p);
          points.push(base);
        }
        p = base.double();
      }
      return points;
    },
    wNAF(W, precomputes, n) {
      const { windows, windowSize } = opts(W);
      let p = c.ZERO;
      let f = c.BASE;
      const mask = BigInt(2 ** W - 1);
      const maxNumber = 2 ** W;
      const shiftBy = BigInt(W);
      for (let window = 0;window < windows; window++) {
        const offset = window * windowSize;
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > windowSize) {
          wbits -= maxNumber;
          n += _1n3;
        }
        const offset1 = offset;
        const offset2 = offset + Math.abs(wbits) - 1;
        const cond1 = window % 2 !== 0;
        const cond2 = wbits < 0;
        if (wbits === 0) {
          f = f.add(constTimeNegate(cond1, precomputes[offset1]));
        } else {
          p = p.add(constTimeNegate(cond2, precomputes[offset2]));
        }
      }
      return { p, f };
    },
    wNAFCached(P, n, transform) {
      const W = pointWindowSizes.get(P) || 1;
      let comp = pointPrecomputes.get(P);
      if (!comp) {
        comp = this.precomputeWindow(P, W);
        if (W !== 1)
          pointPrecomputes.set(P, transform(comp));
      }
      return this.wNAF(W, comp, n);
    },
    setWindowSize(P, W) {
      validateW(W);
      pointWindowSizes.set(P, W);
      pointPrecomputes.delete(P);
    }
  };
}
function pippenger(c, field, points, scalars) {
  if (!Array.isArray(points) || !Array.isArray(scalars) || scalars.length !== points.length)
    throw new Error("arrays of points and scalars must have equal length");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error(`wrong scalar at index ${i}`);
  });
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error(`wrong point at index ${i}`);
  });
  const wbits = bitLen(BigInt(points.length));
  const windowSize = wbits > 12 ? wbits - 3 : wbits > 4 ? wbits - 2 : wbits ? 2 : 1;
  const MASK = (1 << windowSize) - 1;
  const buckets = new Array(MASK + 1).fill(c.ZERO);
  const lastBits = Math.floor((field.BITS - 1) / windowSize) * windowSize;
  let sum = c.ZERO;
  for (let i = lastBits;i >= 0; i -= windowSize) {
    buckets.fill(c.ZERO);
    for (let j = 0;j < scalars.length; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i) & BigInt(MASK));
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = c.ZERO;
    for (let j = buckets.length - 1, sumI = c.ZERO;j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0;j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function validateBasic(curve) {
  validateField(curve.Fp);
  validateObject(curve, {
    n: "bigint",
    h: "bigint",
    Gx: "field",
    Gy: "field"
  }, {
    nBitLength: "isSafeInteger",
    nByteLength: "isSafeInteger"
  });
  return Object.freeze({
    ...nLength(curve.n, curve.nBitLength),
    ...curve,
    ...{ p: curve.Fp.ORDER }
  });
}
var _0n3, _1n3, pointPrecomputes, pointWindowSizes;
var init_curve = __esm(() => {
  init_modular();
  init_utils2();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  _0n3 = BigInt(0);
  _1n3 = BigInt(1);
  pointPrecomputes = new WeakMap;
  pointWindowSizes = new WeakMap;
});

// node_modules/@noble/curves/esm/abstract/weierstrass.js
function weierstrassPoints(opts) {
  const CURVE = validatePointOpts(opts);
  const { Fp } = CURVE;
  const Fn = Field(CURVE.n, CURVE.nBitLength);
  const toBytes2 = CURVE.toBytes || ((_c, point, _isCompressed) => {
    const a = point.toAffine();
    return concatBytes2(Uint8Array.from([4]), Fp.toBytes(a.x), Fp.toBytes(a.y));
  });
  const fromBytes = CURVE.fromBytes || ((bytes2) => {
    const tail = bytes2.subarray(1);
    const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
    const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
    return { x, y };
  });
  function weierstrassEquation(x) {
    const { a, b } = CURVE;
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, a)), b);
  }
  if (!Fp.eql(Fp.sqr(CURVE.Gy), weierstrassEquation(CURVE.Gx)))
    throw new Error("bad generator point: equation left != right");
  function isWithinCurveOrder(num) {
    return inRange(num, _1n4, CURVE.n);
  }
  function normPrivateKeyToScalar(key) {
    const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n: N } = CURVE;
    if (lengths && typeof key !== "bigint") {
      if (isBytes2(key))
        key = bytesToHex(key);
      if (typeof key !== "string" || !lengths.includes(key.length))
        throw new Error("Invalid key");
      key = key.padStart(nByteLength * 2, "0");
    }
    let num;
    try {
      num = typeof key === "bigint" ? key : bytesToNumberBE(ensureBytes("private key", key, nByteLength));
    } catch (error) {
      throw new Error(`private key must be ${nByteLength} bytes, hex or bigint, not ${typeof key}`);
    }
    if (wrapPrivateKey)
      num = mod(num, N);
    aInRange("private key", num, _1n4, N);
    return num;
  }
  function assertPrjPoint(other) {
    if (!(other instanceof Point))
      throw new Error("ProjectivePoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { px: x, py: y, pz: z } = p;
    if (Fp.eql(z, Fp.ONE))
      return { x, y };
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? Fp.ONE : Fp.inv(z);
    const ax = Fp.mul(x, iz);
    const ay = Fp.mul(y, iz);
    const zz = Fp.mul(z, iz);
    if (is0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (!Fp.eql(zz, Fp.ONE))
      throw new Error("invZ was invalid");
    return { x: ax, y: ay };
  });
  const assertValidMemo = memoized((p) => {
    if (p.is0()) {
      if (CURVE.allowInfinityPoint && !Fp.is0(p.py))
        return;
      throw new Error("bad point: ZERO");
    }
    const { x, y } = p.toAffine();
    if (!Fp.isValid(x) || !Fp.isValid(y))
      throw new Error("bad point: x or y not FE");
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    if (!Fp.eql(left, right))
      throw new Error("bad point: equation left != right");
    if (!p.isTorsionFree())
      throw new Error("bad point: not in prime-order subgroup");
    return true;
  });

  class Point {
    constructor(px, py, pz) {
      this.px = px;
      this.py = py;
      this.pz = pz;
      if (px == null || !Fp.isValid(px))
        throw new Error("x required");
      if (py == null || !Fp.isValid(py))
        throw new Error("y required");
      if (pz == null || !Fp.isValid(pz))
        throw new Error("z required");
      Object.freeze(this);
    }
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      const is0 = (i) => Fp.eql(i, Fp.ZERO);
      if (is0(x) && is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    static normalizeZ(points) {
      const toInv = Fp.invertBatch(points.map((p) => p.pz));
      return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
    }
    static fromHex(hex) {
      const P = Point.fromAffine(fromBytes(ensureBytes("pointHex", hex)));
      P.assertValidity();
      return P;
    }
    static fromPrivateKey(privateKey) {
      return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn, points, scalars);
    }
    _setWindowSize(windowSize) {
      wnaf.setWindowSize(this, windowSize);
    }
    assertValidity() {
      assertValidMemo(this);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (Fp.isOdd)
        return !Fp.isOdd(y);
      throw new Error("Field doesn't support isOdd");
    }
    equals(other) {
      assertPrjPoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    negate() {
      return new Point(this.px, Fp.neg(this.py), this.pz);
    }
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n2);
      const { px: X1, py: Y1, pz: Z1 } = this;
      let { ZERO: X3, ZERO: Y3, ZERO: Z3 } = Fp;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    add(other) {
      assertPrjPoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      let { ZERO: X3, ZERO: Y3, ZERO: Z3 } = Fp;
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n2);
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    wNAF(n) {
      return wnaf.wNAFCached(this, n, Point.normalizeZ);
    }
    multiplyUnsafe(sc) {
      aInRange("scalar", sc, _0n4, CURVE.n);
      const I = Point.ZERO;
      if (sc === _0n4)
        return I;
      if (sc === _1n4)
        return this;
      const { endo } = CURVE;
      if (!endo)
        return wnaf.unsafeLadder(this, sc);
      let { k1neg, k1, k2neg, k2 } = endo.splitScalar(sc);
      let k1p = I;
      let k2p = I;
      let d = this;
      while (k1 > _0n4 || k2 > _0n4) {
        if (k1 & _1n4)
          k1p = k1p.add(d);
        if (k2 & _1n4)
          k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n4;
        k2 >>= _1n4;
      }
      if (k1neg)
        k1p = k1p.negate();
      if (k2neg)
        k2p = k2p.negate();
      k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
      return k1p.add(k2p);
    }
    multiply(scalar) {
      const { endo, n: N } = CURVE;
      aInRange("scalar", scalar, _1n4, N);
      let point, fake;
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = endo.splitScalar(scalar);
        let { p: k1p, f: f1p } = this.wNAF(k1);
        let { p: k2p, f: f2p } = this.wNAF(k2);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(scalar);
        point = p;
        fake = f;
      }
      return Point.normalizeZ([point, fake])[0];
    }
    multiplyAndAddUnsafe(Q, a, b) {
      const G = Point.BASE;
      const mul = (P, a2) => a2 === _0n4 || a2 === _1n4 || !P.equals(G) ? P.multiplyUnsafe(a2) : P.multiply(a2);
      const sum = mul(this, a).add(mul(Q, b));
      return sum.is0() ? undefined : sum;
    }
    toAffine(iz) {
      return toAffineMemo(this, iz);
    }
    isTorsionFree() {
      const { h: cofactor, isTorsionFree } = CURVE;
      if (cofactor === _1n4)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      throw new Error("isTorsionFree() has not been declared for the elliptic curve");
    }
    clearCofactor() {
      const { h: cofactor, clearCofactor } = CURVE;
      if (cofactor === _1n4)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(CURVE.h);
    }
    toRawBytes(isCompressed = true) {
      abool("isCompressed", isCompressed);
      this.assertValidity();
      return toBytes2(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      abool("isCompressed", isCompressed);
      return bytesToHex(this.toRawBytes(isCompressed));
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
  Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
  const _bits = CURVE.nBitLength;
  const wnaf = wNAF(Point, CURVE.endo ? Math.ceil(_bits / 2) : _bits);
  return {
    CURVE,
    ProjectivePoint: Point,
    normPrivateKeyToScalar,
    weierstrassEquation,
    isWithinCurveOrder
  };
}
function weierstrass(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { Fp, n: CURVE_ORDER } = CURVE;
  const compressedLen = Fp.BYTES + 1;
  const uncompressedLen = 2 * Fp.BYTES + 1;
  function modN(a) {
    return mod(a, CURVE_ORDER);
  }
  function invN(a) {
    return invert(a, CURVE_ORDER);
  }
  const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder } = weierstrassPoints({
    ...CURVE,
    toBytes(_c, point, isCompressed) {
      const a = point.toAffine();
      const x = Fp.toBytes(a.x);
      const cat = concatBytes2;
      abool("isCompressed", isCompressed);
      if (isCompressed) {
        return cat(Uint8Array.from([point.hasEvenY() ? 2 : 3]), x);
      } else {
        return cat(Uint8Array.from([4]), x, Fp.toBytes(a.y));
      }
    },
    fromBytes(bytes2) {
      const len = bytes2.length;
      const head = bytes2[0];
      const tail = bytes2.subarray(1);
      if (len === compressedLen && (head === 2 || head === 3)) {
        const x = bytesToNumberBE(tail);
        if (!inRange(x, _1n4, Fp.ORDER))
          throw new Error("Point is not on curve");
        const y2 = weierstrassEquation(x);
        let y;
        try {
          y = Fp.sqrt(y2);
        } catch (sqrtError) {
          const suffix = sqrtError instanceof Error ? ": " + sqrtError.message : "";
          throw new Error("Point is not on curve" + suffix);
        }
        const isYOdd = (y & _1n4) === _1n4;
        const isHeadOdd = (head & 1) === 1;
        if (isHeadOdd !== isYOdd)
          y = Fp.neg(y);
        return { x, y };
      } else if (len === uncompressedLen && head === 4) {
        const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
        const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
        return { x, y };
      } else {
        throw new Error(`Point of length ${len} was invalid. Expected ${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes`);
      }
    }
  });
  const numToNByteStr = (num) => bytesToHex(numberToBytesBE(num, CURVE.nByteLength));
  function isBiggerThanHalfOrder(number2) {
    const HALF = CURVE_ORDER >> _1n4;
    return number2 > HALF;
  }
  function normalizeS(s) {
    return isBiggerThanHalfOrder(s) ? modN(-s) : s;
  }
  const slcNum = (b, from, to) => bytesToNumberBE(b.slice(from, to));

  class Signature {
    constructor(r, s, recovery) {
      this.r = r;
      this.s = s;
      this.recovery = recovery;
      this.assertValidity();
    }
    static fromCompact(hex) {
      const l = CURVE.nByteLength;
      hex = ensureBytes("compactSignature", hex, l * 2);
      return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
    }
    static fromDER(hex) {
      const { r, s } = DER.toSig(ensureBytes("DER", hex));
      return new Signature(r, s);
    }
    assertValidity() {
      aInRange("r", this.r, _1n4, CURVE_ORDER);
      aInRange("s", this.s, _1n4, CURVE_ORDER);
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    recoverPublicKey(msgHash) {
      const { r, s, recovery: rec } = this;
      const h = bits2int_modN(ensureBytes("msgHash", msgHash));
      if (rec == null || ![0, 1, 2, 3].includes(rec))
        throw new Error("recovery id invalid");
      const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
      if (radj >= Fp.ORDER)
        throw new Error("recovery id 2 or 3 invalid");
      const prefix = (rec & 1) === 0 ? "02" : "03";
      const R = Point.fromHex(prefix + numToNByteStr(radj));
      const ir = invN(radj);
      const u1 = modN(-h * ir);
      const u2 = modN(s * ir);
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
      if (!Q)
        throw new Error("point at infinify");
      Q.assertValidity();
      return Q;
    }
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
    }
    toDERRawBytes() {
      return hexToBytes(this.toDERHex());
    }
    toDERHex() {
      return DER.hexFromSig({ r: this.r, s: this.s });
    }
    toCompactRawBytes() {
      return hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
      return numToNByteStr(this.r) + numToNByteStr(this.s);
    }
  }
  const utils7 = {
    isValidPrivateKey(privateKey) {
      try {
        normPrivateKeyToScalar(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    normPrivateKeyToScalar,
    randomPrivateKey: () => {
      const length = getMinHashLength(CURVE.n);
      return mapHashToField(CURVE.randomBytes(length), CURVE.n);
    },
    precompute(windowSize = 8, point = Point.BASE) {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    }
  };
  function getPublicKey(privateKey, isCompressed = true) {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
  }
  function isProbPub(item) {
    const arr = isBytes2(item);
    const str = typeof item === "string";
    const len = (arr || str) && item.length;
    if (arr)
      return len === compressedLen || len === uncompressedLen;
    if (str)
      return len === 2 * compressedLen || len === 2 * uncompressedLen;
    if (item instanceof Point)
      return true;
    return false;
  }
  function getSharedSecret(privateA, publicB, isCompressed = true) {
    if (isProbPub(privateA))
      throw new Error("first arg must be private key");
    if (!isProbPub(publicB))
      throw new Error("second arg must be public key");
    const b = Point.fromHex(publicB);
    return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
  }
  const bits2int = CURVE.bits2int || function(bytes2) {
    const num = bytesToNumberBE(bytes2);
    const delta = bytes2.length * 8 - CURVE.nBitLength;
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const bits2int_modN = CURVE.bits2int_modN || function(bytes2) {
    return modN(bits2int(bytes2));
  };
  const ORDER_MASK = bitMask(CURVE.nBitLength);
  function int2octets(num) {
    aInRange(`num < 2^${CURVE.nBitLength}`, num, _0n4, ORDER_MASK);
    return numberToBytesBE(num, CURVE.nByteLength);
  }
  function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
    if (["recovered", "canonical"].some((k) => (k in opts)))
      throw new Error("sign() legacy options not supported");
    const { hash: hash2, randomBytes: randomBytes2 } = CURVE;
    let { lowS, prehash, extraEntropy: ent } = opts;
    if (lowS == null)
      lowS = true;
    msgHash = ensureBytes("msgHash", msgHash);
    validateSigVerOpts(opts);
    if (prehash)
      msgHash = ensureBytes("prehashed msgHash", hash2(msgHash));
    const h1int = bits2int_modN(msgHash);
    const d = normPrivateKeyToScalar(privateKey);
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (ent != null && ent !== false) {
      const e = ent === true ? randomBytes2(Fp.BYTES) : ent;
      seedArgs.push(ensureBytes("extraEntropy", e));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!isWithinCurveOrder(k))
        return;
      const ik = invN(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = modN(q.x);
      if (r === _0n4)
        return;
      const s = modN(ik * modN(m + r * d));
      if (s === _0n4)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n4);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, recovery);
    }
    return { seed, k2sig };
  }
  const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
  const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
  function sign(msgHash, privKey, opts = defaultSigOpts) {
    const { seed, k2sig } = prepSig(msgHash, privKey, opts);
    const C = CURVE;
    const drbg = createHmacDrbg(C.hash.outputLen, C.nByteLength, C.hmac);
    return drbg(seed, k2sig);
  }
  Point.BASE._setWindowSize(8);
  function verify(signature, msgHash, publicKey, opts = defaultVerOpts) {
    const sg = signature;
    msgHash = ensureBytes("msgHash", msgHash);
    publicKey = ensureBytes("publicKey", publicKey);
    if ("strict" in opts)
      throw new Error("options.strict was renamed to lowS");
    validateSigVerOpts(opts);
    const { lowS, prehash } = opts;
    let _sig = undefined;
    let P;
    try {
      if (typeof sg === "string" || isBytes2(sg)) {
        try {
          _sig = Signature.fromDER(sg);
        } catch (derError) {
          if (!(derError instanceof DER.Err))
            throw derError;
          _sig = Signature.fromCompact(sg);
        }
      } else if (typeof sg === "object" && typeof sg.r === "bigint" && typeof sg.s === "bigint") {
        const { r: r2, s: s2 } = sg;
        _sig = new Signature(r2, s2);
      } else {
        throw new Error("PARSE");
      }
      P = Point.fromHex(publicKey);
    } catch (error) {
      if (error.message === "PARSE")
        throw new Error(`signature must be Signature instance, Uint8Array or hex string`);
      return false;
    }
    if (lowS && _sig.hasHighS())
      return false;
    if (prehash)
      msgHash = CURVE.hash(msgHash);
    const { r, s } = _sig;
    const h = bits2int_modN(msgHash);
    const is = invN(s);
    const u1 = modN(h * is);
    const u2 = modN(r * is);
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine();
    if (!R)
      return false;
    const v = modN(R.x);
    return v === r;
  }
  return {
    CURVE,
    getPublicKey,
    getSharedSecret,
    sign,
    verify,
    ProjectivePoint: Point,
    Signature,
    utils: utils7
  };
}
function SWUFpSqrtRatio(Fp, Z) {
  const q = Fp.ORDER;
  let l = _0n4;
  for (let o = q - _1n4;o % _2n3 === _0n4; o /= _2n3)
    l += _1n4;
  const c1 = l;
  const _2n_pow_c1_1 = _2n3 << c1 - _1n4 - _1n4;
  const _2n_pow_c1 = _2n_pow_c1_1 * _2n3;
  const c2 = (q - _1n4) / _2n_pow_c1;
  const c3 = (c2 - _1n4) / _2n3;
  const c4 = _2n_pow_c1 - _1n4;
  const c5 = _2n_pow_c1_1;
  const c6 = Fp.pow(Z, c2);
  const c7 = Fp.pow(Z, (c2 + _1n4) / _2n3);
  let sqrtRatio = (u, v) => {
    let tv1 = c6;
    let tv2 = Fp.pow(v, c4);
    let tv3 = Fp.sqr(tv2);
    tv3 = Fp.mul(tv3, v);
    let tv5 = Fp.mul(u, tv3);
    tv5 = Fp.pow(tv5, c3);
    tv5 = Fp.mul(tv5, tv2);
    tv2 = Fp.mul(tv5, v);
    tv3 = Fp.mul(tv5, u);
    let tv4 = Fp.mul(tv3, tv2);
    tv5 = Fp.pow(tv4, c5);
    let isQR = Fp.eql(tv5, Fp.ONE);
    tv2 = Fp.mul(tv3, c7);
    tv5 = Fp.mul(tv4, tv1);
    tv3 = Fp.cmov(tv2, tv3, isQR);
    tv4 = Fp.cmov(tv5, tv4, isQR);
    for (let i = c1;i > _1n4; i--) {
      let tv52 = i - _2n3;
      tv52 = _2n3 << tv52 - _1n4;
      let tvv5 = Fp.pow(tv4, tv52);
      const e1 = Fp.eql(tvv5, Fp.ONE);
      tv2 = Fp.mul(tv3, tv1);
      tv1 = Fp.mul(tv1, tv1);
      tvv5 = Fp.mul(tv4, tv1);
      tv3 = Fp.cmov(tv2, tv3, e1);
      tv4 = Fp.cmov(tvv5, tv4, e1);
    }
    return { isValid: isQR, value: tv3 };
  };
  if (Fp.ORDER % _4n2 === _3n2) {
    const c12 = (Fp.ORDER - _3n2) / _4n2;
    const c22 = Fp.sqrt(Fp.neg(Z));
    sqrtRatio = (u, v) => {
      let tv1 = Fp.sqr(v);
      const tv2 = Fp.mul(u, v);
      tv1 = Fp.mul(tv1, tv2);
      let y1 = Fp.pow(tv1, c12);
      y1 = Fp.mul(y1, tv2);
      const y2 = Fp.mul(y1, c22);
      const tv3 = Fp.mul(Fp.sqr(y1), v);
      const isQR = Fp.eql(tv3, u);
      let y = Fp.cmov(y2, y1, isQR);
      return { isValid: isQR, value: y };
    };
  }
  return sqrtRatio;
}
function mapToCurveSimpleSWU(Fp, opts) {
  validateField(Fp);
  if (!Fp.isValid(opts.A) || !Fp.isValid(opts.B) || !Fp.isValid(opts.Z))
    throw new Error("mapToCurveSimpleSWU: invalid opts");
  const sqrtRatio = SWUFpSqrtRatio(Fp, opts.Z);
  if (!Fp.isOdd)
    throw new Error("Fp.isOdd is not implemented!");
  return (u) => {
    let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
    tv1 = Fp.sqr(u);
    tv1 = Fp.mul(tv1, opts.Z);
    tv2 = Fp.sqr(tv1);
    tv2 = Fp.add(tv2, tv1);
    tv3 = Fp.add(tv2, Fp.ONE);
    tv3 = Fp.mul(tv3, opts.B);
    tv4 = Fp.cmov(opts.Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO));
    tv4 = Fp.mul(tv4, opts.A);
    tv2 = Fp.sqr(tv3);
    tv6 = Fp.sqr(tv4);
    tv5 = Fp.mul(tv6, opts.A);
    tv2 = Fp.add(tv2, tv5);
    tv2 = Fp.mul(tv2, tv3);
    tv6 = Fp.mul(tv6, tv4);
    tv5 = Fp.mul(tv6, opts.B);
    tv2 = Fp.add(tv2, tv5);
    x = Fp.mul(tv1, tv3);
    const { isValid, value } = sqrtRatio(tv2, tv6);
    y = Fp.mul(tv1, u);
    y = Fp.mul(y, value);
    x = Fp.cmov(x, tv3, isValid);
    y = Fp.cmov(y, value, isValid);
    const e1 = Fp.isOdd(u) === Fp.isOdd(y);
    y = Fp.cmov(Fp.neg(y), y, e1);
    x = Fp.div(x, tv4);
    return { x, y };
  };
}
var validateSigVerOpts, validatePointOpts, validateOpts, b2n, h2b, DER, _0n4, _1n4, _2n3, _3n2, _4n2;
var init_weierstrass = __esm(() => {
  init_curve();
  init_modular();
  init_utils2();
  init_utils2();
  validateSigVerOpts = function(opts) {
    if (opts.lowS !== undefined)
      abool("lowS", opts.lowS);
    if (opts.prehash !== undefined)
      abool("prehash", opts.prehash);
  };
  validatePointOpts = function(curve2) {
    const opts = validateBasic(curve2);
    validateObject(opts, {
      a: "field",
      b: "field"
    }, {
      allowedPrivateKeyLengths: "array",
      wrapPrivateKey: "boolean",
      isTorsionFree: "function",
      clearCofactor: "function",
      allowInfinityPoint: "boolean",
      fromBytes: "function",
      toBytes: "function"
    });
    const { endo, Fp, a } = opts;
    if (endo) {
      if (!Fp.eql(a, Fp.ZERO)) {
        throw new Error("Endomorphism can only be defined for Koblitz curves that have a=0");
      }
      if (typeof endo !== "object" || typeof endo.beta !== "bigint" || typeof endo.splitScalar !== "function") {
        throw new Error("Expected endomorphism with beta: bigint and splitScalar: function");
      }
    }
    return Object.freeze({ ...opts });
  };
  validateOpts = function(curve2) {
    const opts = validateBasic(curve2);
    validateObject(opts, {
      hash: "hash",
      hmac: "function",
      randomBytes: "function"
    }, {
      bits2int: "function",
      bits2int_modN: "function",
      lowS: "boolean"
    });
    return Object.freeze({ lowS: true, ...opts });
  };
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  ({ bytesToNumberBE: b2n, hexToBytes: h2b } = exports_utils);
  DER = {
    Err: class DERErr extends Error {
      constructor(m = "") {
        super(m);
      }
    },
    _tlv: {
      encode: (tag, data) => {
        const { Err: E } = DER;
        if (tag < 0 || tag > 256)
          throw new E("tlv.encode: wrong tag");
        if (data.length & 1)
          throw new E("tlv.encode: unpadded data");
        const dataLen = data.length / 2;
        const len = numberToHexUnpadded(dataLen);
        if (len.length / 2 & 128)
          throw new E("tlv.encode: long form length too big");
        const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
        return `${numberToHexUnpadded(tag)}${lenLen}${len}${data}`;
      },
      decode(tag, data) {
        const { Err: E } = DER;
        let pos = 0;
        if (tag < 0 || tag > 256)
          throw new E("tlv.encode: wrong tag");
        if (data.length < 2 || data[pos++] !== tag)
          throw new E("tlv.decode: wrong tlv");
        const first = data[pos++];
        const isLong = !!(first & 128);
        let length = 0;
        if (!isLong)
          length = first;
        else {
          const lenLen = first & 127;
          if (!lenLen)
            throw new E("tlv.decode(long): indefinite length not supported");
          if (lenLen > 4)
            throw new E("tlv.decode(long): byte length is too big");
          const lengthBytes = data.subarray(pos, pos + lenLen);
          if (lengthBytes.length !== lenLen)
            throw new E("tlv.decode: length bytes not complete");
          if (lengthBytes[0] === 0)
            throw new E("tlv.decode(long): zero leftmost byte");
          for (const b of lengthBytes)
            length = length << 8 | b;
          pos += lenLen;
          if (length < 128)
            throw new E("tlv.decode(long): not minimal encoding");
        }
        const v = data.subarray(pos, pos + length);
        if (v.length !== length)
          throw new E("tlv.decode: wrong value length");
        return { v, l: data.subarray(pos + length) };
      }
    },
    _int: {
      encode(num) {
        const { Err: E } = DER;
        if (num < _0n4)
          throw new E("integer: negative integers are not allowed");
        let hex = numberToHexUnpadded(num);
        if (Number.parseInt(hex[0], 16) & 8)
          hex = "00" + hex;
        if (hex.length & 1)
          throw new E("unexpected assertion");
        return hex;
      },
      decode(data) {
        const { Err: E } = DER;
        if (data[0] & 128)
          throw new E("Invalid signature integer: negative");
        if (data[0] === 0 && !(data[1] & 128))
          throw new E("Invalid signature integer: unnecessary leading zero");
        return b2n(data);
      }
    },
    toSig(hex) {
      const { Err: E, _int: int, _tlv: tlv } = DER;
      const data = typeof hex === "string" ? h2b(hex) : hex;
      abytes(data);
      const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
      if (seqLeftBytes.length)
        throw new E("Invalid signature: left bytes after parsing");
      const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
      const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
      if (sLeftBytes.length)
        throw new E("Invalid signature: left bytes after parsing");
      return { r: int.decode(rBytes), s: int.decode(sBytes) };
    },
    hexFromSig(sig) {
      const { _tlv: tlv, _int: int } = DER;
      const seq = `${tlv.encode(2, int.encode(sig.r))}${tlv.encode(2, int.encode(sig.s))}`;
      return tlv.encode(48, seq);
    }
  };
  _0n4 = BigInt(0);
  _1n4 = BigInt(1);
  _2n3 = BigInt(2);
  _3n2 = BigInt(3);
  _4n2 = BigInt(4);
});

// node_modules/@noble/curves/esm/_shortw_utils.js
function getHash(hash2) {
  return {
    hash: hash2,
    hmac: (key, ...msgs) => hmac(hash2, key, concatBytes(...msgs)),
    randomBytes
  };
}
function createCurve(curveDef, defHash) {
  const create = (hash2) => weierstrass({ ...curveDef, ...getHash(hash2) });
  return Object.freeze({ ...create(defHash), create });
}
var init__shortw_utils = __esm(() => {
  init_hmac();
  init_utils();
  init_weierstrass();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
});

// node_modules/@noble/curves/esm/abstract/hash-to-curve.js
function expand_message_xmd(msg, DST, lenInBytes, H) {
  abytes(msg);
  abytes(DST);
  anum(lenInBytes);
  if (DST.length > 255)
    DST = H(concatBytes2(utf8ToBytes2("H2C-OVERSIZE-DST-"), DST));
  const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
  const ell = Math.ceil(lenInBytes / b_in_bytes);
  if (lenInBytes > 65535 || ell > 255)
    throw new Error("expand_message_xmd: invalid lenInBytes");
  const DST_prime = concatBytes2(DST, i2osp(DST.length, 1));
  const Z_pad = i2osp(0, r_in_bytes);
  const l_i_b_str = i2osp(lenInBytes, 2);
  const b = new Array(ell);
  const b_0 = H(concatBytes2(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
  b[0] = H(concatBytes2(b_0, i2osp(1, 1), DST_prime));
  for (let i = 1;i <= ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
    b[i] = H(concatBytes2(...args));
  }
  const pseudo_random_bytes = concatBytes2(...b);
  return pseudo_random_bytes.slice(0, lenInBytes);
}
function expand_message_xof(msg, DST, lenInBytes, k, H) {
  abytes(msg);
  abytes(DST);
  anum(lenInBytes);
  if (DST.length > 255) {
    const dkLen = Math.ceil(2 * k / 8);
    DST = H.create({ dkLen }).update(utf8ToBytes2("H2C-OVERSIZE-DST-")).update(DST).digest();
  }
  if (lenInBytes > 65535 || DST.length > 255)
    throw new Error("expand_message_xof: invalid lenInBytes");
  return H.create({ dkLen: lenInBytes }).update(msg).update(i2osp(lenInBytes, 2)).update(DST).update(i2osp(DST.length, 1)).digest();
}
function hash_to_field(msg, count, options) {
  validateObject(options, {
    DST: "stringOrUint8Array",
    p: "bigint",
    m: "isSafeInteger",
    k: "isSafeInteger",
    hash: "hash"
  });
  const { p, k, m, hash: hash2, expand, DST: _DST } = options;
  abytes(msg);
  anum(count);
  const DST = typeof _DST === "string" ? utf8ToBytes2(_DST) : _DST;
  const log2p = p.toString(2).length;
  const L = Math.ceil((log2p + k) / 8);
  const len_in_bytes = count * m * L;
  let prb;
  if (expand === "xmd") {
    prb = expand_message_xmd(msg, DST, len_in_bytes, hash2);
  } else if (expand === "xof") {
    prb = expand_message_xof(msg, DST, len_in_bytes, k, hash2);
  } else if (expand === "_internal_pass") {
    prb = msg;
  } else {
    throw new Error('expand must be "xmd" or "xof"');
  }
  const u = new Array(count);
  for (let i = 0;i < count; i++) {
    const e = new Array(m);
    for (let j = 0;j < m; j++) {
      const elm_offset = L * (j + i * m);
      const tv = prb.subarray(elm_offset, elm_offset + L);
      e[j] = mod(os2ip(tv), p);
    }
    u[i] = e;
  }
  return u;
}
function isogenyMap(field, map) {
  const COEFF = map.map((i) => Array.from(i).reverse());
  return (x, y) => {
    const [xNum, xDen, yNum, yDen] = COEFF.map((val) => val.reduce((acc, i) => field.add(field.mul(acc, x), i)));
    x = field.div(xNum, xDen);
    y = field.mul(y, field.div(yNum, yDen));
    return { x, y };
  };
}
function createHasher(Point, mapToCurve, def) {
  if (typeof mapToCurve !== "function")
    throw new Error("mapToCurve() must be defined");
  return {
    hashToCurve(msg, options) {
      const u = hash_to_field(msg, 2, { ...def, DST: def.DST, ...options });
      const u0 = Point.fromAffine(mapToCurve(u[0]));
      const u1 = Point.fromAffine(mapToCurve(u[1]));
      const P = u0.add(u1).clearCofactor();
      P.assertValidity();
      return P;
    },
    encodeToCurve(msg, options) {
      const u = hash_to_field(msg, 1, { ...def, DST: def.encodeDST, ...options });
      const P = Point.fromAffine(mapToCurve(u[0])).clearCofactor();
      P.assertValidity();
      return P;
    },
    mapToCurve(scalars) {
      if (!Array.isArray(scalars))
        throw new Error("mapToCurve: expected array of bigints");
      for (const i of scalars)
        if (typeof i !== "bigint")
          throw new Error(`mapToCurve: expected array of bigints, got ${i} in array`);
      const P = Point.fromAffine(mapToCurve(scalars)).clearCofactor();
      P.assertValidity();
      return P;
    }
  };
}
var i2osp, strxor, anum, os2ip;
var init_hash_to_curve = __esm(() => {
  init_modular();
  init_utils2();
  i2osp = function(value, length) {
    anum(value);
    anum(length);
    if (value < 0 || value >= 1 << 8 * length) {
      throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1;i >= 0; i--) {
      res[i] = value & 255;
      value >>>= 8;
    }
    return new Uint8Array(res);
  };
  strxor = function(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0;i < a.length; i++) {
      arr[i] = a[i] ^ b[i];
    }
    return arr;
  };
  anum = function(item) {
    if (!Number.isSafeInteger(item))
      throw new Error("number expected");
  };
  os2ip = bytesToNumberBE;
});

// node_modules/@noble/curves/esm/secp256k1.js
var exports_secp256k1 = {};
__export(exports_secp256k1, {
  secp256k1: () => {
    {
      return secp256k1;
    }
  },
  schnorr: () => {
    {
      return schnorr;
    }
  },
  hashToCurve: () => {
    {
      return hashToCurve;
    }
  },
  encodeToCurve: () => {
    {
      return encodeToCurve;
    }
  }
});
var sqrtMod, taggedHash, schnorrGetExtPubKey, lift_x, challenge, schnorrGetPublicKey, schnorrSign, schnorrVerify, secp256k1P, secp256k1N, _1n5, _2n4, divNearest, Fp, secp256k1, _0n5, TAGGED_HASH_PREFIXES, pointToBytes, numTo32b, modP, modN, Point, GmulAdd, num, schnorr, isoMap, mapSWU, htf, hashToCurve, encodeToCurve;
var init_secp256k1 = __esm(() => {
  init_sha256();
  init_utils();
  init__shortw_utils();
  init_hash_to_curve();
  init_modular();
  init_utils2();
  init_weierstrass();
  sqrtMod = function(y) {
    const P = secp256k1P;
    const _3n3 = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
    const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
    const b2 = y * y * y % P;
    const b3 = b2 * b2 * y % P;
    const b6 = pow2(b3, _3n3, P) * b3 % P;
    const b9 = pow2(b6, _3n3, P) * b3 % P;
    const b11 = pow2(b9, _2n4, P) * b2 % P;
    const b22 = pow2(b11, _11n, P) * b11 % P;
    const b44 = pow2(b22, _22n, P) * b22 % P;
    const b88 = pow2(b44, _44n, P) * b44 % P;
    const b176 = pow2(b88, _88n, P) * b88 % P;
    const b220 = pow2(b176, _44n, P) * b44 % P;
    const b223 = pow2(b220, _3n3, P) * b3 % P;
    const t1 = pow2(b223, _23n, P) * b22 % P;
    const t2 = pow2(t1, _6n, P) * b2 % P;
    const root = pow2(t2, _2n4, P);
    if (!Fp.eql(Fp.sqr(root), y))
      throw new Error("Cannot find square root");
    return root;
  };
  taggedHash = function(tag, ...messages) {
    let tagP = TAGGED_HASH_PREFIXES[tag];
    if (tagP === undefined) {
      const tagH = sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
      tagP = concatBytes2(tagH, tagH);
      TAGGED_HASH_PREFIXES[tag] = tagP;
    }
    return sha256(concatBytes2(tagP, ...messages));
  };
  schnorrGetExtPubKey = function(priv) {
    let d_ = secp256k1.utils.normPrivateKeyToScalar(priv);
    let p = Point.fromPrivateKey(d_);
    const scalar = p.hasEvenY() ? d_ : modN(-d_);
    return { scalar, bytes: pointToBytes(p) };
  };
  lift_x = function(x) {
    aInRange("x", x, _1n5, secp256k1P);
    const xx = modP(x * x);
    const c = modP(xx * x + BigInt(7));
    let y = sqrtMod(c);
    if (y % _2n4 !== _0n5)
      y = modP(-y);
    const p = new Point(x, y, _1n5);
    p.assertValidity();
    return p;
  };
  challenge = function(...args) {
    return modN(num(taggedHash("BIP0340/challenge", ...args)));
  };
  schnorrGetPublicKey = function(privateKey) {
    return schnorrGetExtPubKey(privateKey).bytes;
  };
  schnorrSign = function(message, privateKey, auxRand = randomBytes(32)) {
    const m = ensureBytes("message", message);
    const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey);
    const a = ensureBytes("auxRand", auxRand, 32);
    const t = numTo32b(d ^ num(taggedHash("BIP0340/aux", a)));
    const rand = taggedHash("BIP0340/nonce", t, px, m);
    const k_ = modN(num(rand));
    if (k_ === _0n5)
      throw new Error("sign failed: k is zero");
    const { bytes: rx, scalar: k } = schnorrGetExtPubKey(k_);
    const e = challenge(rx, px, m);
    const sig = new Uint8Array(64);
    sig.set(rx, 0);
    sig.set(numTo32b(modN(k + e * d)), 32);
    if (!schnorrVerify(sig, m, px))
      throw new Error("sign: Invalid signature produced");
    return sig;
  };
  schnorrVerify = function(signature, message, publicKey) {
    const sig = ensureBytes("signature", signature, 64);
    const m = ensureBytes("message", message);
    const pub = ensureBytes("publicKey", publicKey, 32);
    try {
      const P = lift_x(num(pub));
      const r = num(sig.subarray(0, 32));
      if (!inRange(r, _1n5, secp256k1P))
        return false;
      const s = num(sig.subarray(32, 64));
      if (!inRange(s, _1n5, secp256k1N))
        return false;
      const e = challenge(numTo32b(r), pointToBytes(P), m);
      const R = GmulAdd(P, s, modN(-e));
      if (!R || !R.hasEvenY() || R.toAffine().x !== r)
        return false;
      return true;
    } catch (error) {
      return false;
    }
  };
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  secp256k1P = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
  secp256k1N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  _1n5 = BigInt(1);
  _2n4 = BigInt(2);
  divNearest = (a, b) => (a + b / _2n4) / b;
  Fp = Field(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
  secp256k1 = createCurve({
    a: BigInt(0),
    b: BigInt(7),
    Fp,
    n: secp256k1N,
    Gx: BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
    Gy: BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424"),
    h: BigInt(1),
    lowS: true,
    endo: {
      beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
      splitScalar: (k) => {
        const n = secp256k1N;
        const a1 = BigInt("0x3086d221a7d46bcde86c90e49284eb15");
        const b1 = -_1n5 * BigInt("0xe4437ed6010e88286f547fa90abfe4c3");
        const a2 = BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8");
        const b2 = a1;
        const POW_2_128 = BigInt("0x100000000000000000000000000000000");
        const c1 = divNearest(b2 * k, n);
        const c2 = divNearest(-b1 * k, n);
        let k1 = mod(k - c1 * a1 - c2 * a2, n);
        let k2 = mod(-c1 * b1 - c2 * b2, n);
        const k1neg = k1 > POW_2_128;
        const k2neg = k2 > POW_2_128;
        if (k1neg)
          k1 = n - k1;
        if (k2neg)
          k2 = n - k2;
        if (k1 > POW_2_128 || k2 > POW_2_128) {
          throw new Error("splitScalar: Endomorphism failed, k=" + k);
        }
        return { k1neg, k1, k2neg, k2 };
      }
    }
  }, sha256);
  _0n5 = BigInt(0);
  TAGGED_HASH_PREFIXES = {};
  pointToBytes = (point) => point.toRawBytes(true).slice(1);
  numTo32b = (n) => numberToBytesBE(n, 32);
  modP = (x) => mod(x, secp256k1P);
  modN = (x) => mod(x, secp256k1N);
  Point = secp256k1.ProjectivePoint;
  GmulAdd = (Q, a, b) => Point.BASE.multiplyAndAddUnsafe(Q, a, b);
  num = bytesToNumberBE;
  schnorr = (() => ({
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    utils: {
      randomPrivateKey: secp256k1.utils.randomPrivateKey,
      lift_x,
      pointToBytes,
      numberToBytesBE,
      bytesToNumberBE,
      taggedHash,
      mod
    }
  }))();
  isoMap = (() => isogenyMap(Fp, [
    [
      "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7",
      "0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581",
      "0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262",
      "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c"
    ],
    [
      "0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b",
      "0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14",
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    ],
    [
      "0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c",
      "0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3",
      "0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931",
      "0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84"
    ],
    [
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b",
      "0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573",
      "0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f",
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    ]
  ].map((i) => i.map((j) => BigInt(j)))))();
  mapSWU = (() => mapToCurveSimpleSWU(Fp, {
    A: BigInt("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533"),
    B: BigInt("1771"),
    Z: Fp.create(BigInt("-11"))
  }))();
  htf = (() => createHasher(secp256k1.ProjectivePoint, (scalars) => {
    const { x, y } = mapSWU(Fp.create(scalars[0]));
    return isoMap(x, y);
  }, {
    DST: "secp256k1_XMD:SHA-256_SSWU_RO_",
    encodeDST: "secp256k1_XMD:SHA-256_SSWU_NU_",
    p: Fp.ORDER,
    m: 1,
    k: 128,
    expand: "xmd",
    hash: sha256
  }))();
  hashToCurve = (() => htf.hashToCurve)();
  encodeToCurve = (() => htf.encodeToCurve)();
});

// node_modules/viem/_esm/errors/version.js
var version;
var init_version = __esm(() => {
  version = "2.21.45";
});

// node_modules/viem/_esm/errors/base.js
class BaseError extends Error {
  constructor(shortMessage, args = {}) {
    const details = (() => {
      if (args.cause instanceof BaseError)
        return args.cause.details;
      if (args.cause?.message)
        return args.cause.message;
      return args.details;
    })();
    const docsPath = (() => {
      if (args.cause instanceof BaseError)
        return args.cause.docsPath || args.docsPath;
      return args.docsPath;
    })();
    const docsUrl = errorConfig.getDocsUrl?.({ ...args, docsPath });
    const message = [
      shortMessage || "An error occurred.",
      "",
      ...args.metaMessages ? [...args.metaMessages, ""] : [],
      ...docsUrl ? [`Docs: ${docsUrl}`] : [],
      ...details ? [`Details: ${details}`] : [],
      ...errorConfig.version ? [`Version: ${errorConfig.version}`] : []
    ].join("\n");
    super(message, args.cause ? { cause: args.cause } : undefined);
    Object.defineProperty(this, "details", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "docsPath", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "metaMessages", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "shortMessage", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "version", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "BaseError"
    });
    this.details = details;
    this.docsPath = docsPath;
    this.metaMessages = args.metaMessages;
    this.name = args.name ?? this.name;
    this.shortMessage = shortMessage;
    this.version = version;
  }
  walk(fn) {
    return walk(this, fn);
  }
}
var walk, errorConfig;
var init_base = __esm(() => {
  init_version();
  walk = function(err, fn) {
    if (fn?.(err))
      return err;
    if (err && typeof err === "object" && ("cause" in err) && err.cause !== undefined)
      return walk(err.cause, fn);
    return fn ? null : err;
  };
  errorConfig = {
    getDocsUrl: ({ docsBaseUrl, docsPath = "", docsSlug }) => docsPath ? `${docsBaseUrl ?? "https://viem.sh"}${docsPath}${docsSlug ? `#${docsSlug}` : ""}` : undefined,
    version: `viem@${version}`
  };
});

// node_modules/viem/_esm/errors/encoding.js
class IntegerOutOfRangeError extends BaseError {
  constructor({ max, min, signed, size, value }) {
    super(`Number "${value}" is not in safe ${size ? `${size * 8}-bit ${signed ? "signed" : "unsigned"} ` : ""}integer range ${max ? `(${min} to ${max})` : `(above ${min})`}`, { name: "IntegerOutOfRangeError" });
  }
}

class InvalidBytesBooleanError extends BaseError {
  constructor(bytes2) {
    super(`Bytes value "${bytes2}" is not a valid boolean. The bytes array must contain a single byte of either a 0 or 1 value.`, {
      name: "InvalidBytesBooleanError"
    });
  }
}

class InvalidHexBooleanError extends BaseError {
  constructor(hex) {
    super(`Hex value "${hex}" is not a valid boolean. The hex value must be "0x0" (false) or "0x1" (true).`, { name: "InvalidHexBooleanError" });
  }
}

class SizeOverflowError extends BaseError {
  constructor({ givenSize, maxSize }) {
    super(`Size cannot exceed ${maxSize} bytes. Given size: ${givenSize} bytes.`, { name: "SizeOverflowError" });
  }
}
var init_encoding = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/errors/data.js
class SliceOffsetOutOfBoundsError extends BaseError {
  constructor({ offset, position, size }) {
    super(`Slice ${position === "start" ? "starting" : "ending"} at offset "${offset}" is out-of-bounds (size: ${size}).`, { name: "SliceOffsetOutOfBoundsError" });
  }
}

class SizeExceedsPaddingSizeError extends BaseError {
  constructor({ size, targetSize, type }) {
    super(`${type.charAt(0).toUpperCase()}${type.slice(1).toLowerCase()} size (${size}) exceeds padding size (${targetSize}).`, { name: "SizeExceedsPaddingSizeError" });
  }
}

class InvalidBytesLengthError extends BaseError {
  constructor({ size, targetSize, type }) {
    super(`${type.charAt(0).toUpperCase()}${type.slice(1).toLowerCase()} is expected to be ${targetSize} ${type} long, but is ${size} ${type} long.`, { name: "InvalidBytesLengthError" });
  }
}
var init_data = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/utils/data/pad.js
function pad(hexOrBytes, { dir, size = 32 } = {}) {
  if (typeof hexOrBytes === "string")
    return padHex(hexOrBytes, { dir, size });
  return padBytes(hexOrBytes, { dir, size });
}
function padHex(hex_, { dir, size = 32 } = {}) {
  if (size === null)
    return hex_;
  const hex = hex_.replace("0x", "");
  if (hex.length > size * 2)
    throw new SizeExceedsPaddingSizeError({
      size: Math.ceil(hex.length / 2),
      targetSize: size,
      type: "hex"
    });
  return `0x${hex[dir === "right" ? "padEnd" : "padStart"](size * 2, "0")}`;
}
function padBytes(bytes2, { dir, size = 32 } = {}) {
  if (size === null)
    return bytes2;
  if (bytes2.length > size)
    throw new SizeExceedsPaddingSizeError({
      size: bytes2.length,
      targetSize: size,
      type: "bytes"
    });
  const paddedBytes = new Uint8Array(size);
  for (let i = 0;i < size; i++) {
    const padEnd = dir === "right";
    paddedBytes[padEnd ? i : size - i - 1] = bytes2[padEnd ? i : bytes2.length - i - 1];
  }
  return paddedBytes;
}
var init_pad = __esm(() => {
  init_data();
});

// node_modules/viem/_esm/utils/data/isHex.js
function isHex(value, { strict = true } = {}) {
  if (!value)
    return false;
  if (typeof value !== "string")
    return false;
  return strict ? /^0x[0-9a-fA-F]*$/.test(value) : value.startsWith("0x");
}
var init_isHex = __esm(() => {
});

// node_modules/viem/_esm/utils/data/size.js
function size(value) {
  if (isHex(value, { strict: false }))
    return Math.ceil((value.length - 2) / 2);
  return value.length;
}
var init_size = __esm(() => {
  init_isHex();
});

// node_modules/viem/_esm/utils/data/trim.js
function trim(hexOrBytes, { dir = "left" } = {}) {
  let data2 = typeof hexOrBytes === "string" ? hexOrBytes.replace("0x", "") : hexOrBytes;
  let sliceLength = 0;
  for (let i = 0;i < data2.length - 1; i++) {
    if (data2[dir === "left" ? i : data2.length - i - 1].toString() === "0")
      sliceLength++;
    else
      break;
  }
  data2 = dir === "left" ? data2.slice(sliceLength) : data2.slice(0, data2.length - sliceLength);
  if (typeof hexOrBytes === "string") {
    if (data2.length === 1 && dir === "right")
      data2 = `${data2}0`;
    return `0x${data2.length % 2 === 1 ? `0${data2}` : data2}`;
  }
  return data2;
}
var init_trim = __esm(() => {
});

// node_modules/viem/_esm/utils/encoding/toBytes.js
function toBytes2(value, opts = {}) {
  if (typeof value === "number" || typeof value === "bigint")
    return numberToBytes(value, opts);
  if (typeof value === "boolean")
    return boolToBytes(value, opts);
  if (isHex(value))
    return hexToBytes2(value, opts);
  return stringToBytes(value, opts);
}
function boolToBytes(value, opts = {}) {
  const bytes2 = new Uint8Array(1);
  bytes2[0] = Number(value);
  if (typeof opts.size === "number") {
    assertSize(bytes2, { size: opts.size });
    return pad(bytes2, { size: opts.size });
  }
  return bytes2;
}
function hexToBytes2(hex_, opts = {}) {
  let hex = hex_;
  if (opts.size) {
    assertSize(hex, { size: opts.size });
    hex = pad(hex, { dir: "right", size: opts.size });
  }
  let hexString = hex.slice(2);
  if (hexString.length % 2)
    hexString = `0${hexString}`;
  const length = hexString.length / 2;
  const bytes2 = new Uint8Array(length);
  for (let index = 0, j = 0;index < length; index++) {
    const nibbleLeft = charCodeToBase16(hexString.charCodeAt(j++));
    const nibbleRight = charCodeToBase16(hexString.charCodeAt(j++));
    if (nibbleLeft === undefined || nibbleRight === undefined) {
      throw new BaseError(`Invalid byte sequence ("${hexString[j - 2]}${hexString[j - 1]}" in "${hexString}").`);
    }
    bytes2[index] = nibbleLeft * 16 + nibbleRight;
  }
  return bytes2;
}
function numberToBytes(value, opts) {
  const hex = numberToHex(value, opts);
  return hexToBytes2(hex);
}
function stringToBytes(value, opts = {}) {
  const bytes2 = encoder.encode(value);
  if (typeof opts.size === "number") {
    assertSize(bytes2, { size: opts.size });
    return pad(bytes2, { dir: "right", size: opts.size });
  }
  return bytes2;
}
var charCodeToBase16, encoder, charCodeMap;
var init_toBytes = __esm(() => {
  init_base();
  init_isHex();
  init_pad();
  init_fromHex();
  init_toHex();
  charCodeToBase16 = function(char) {
    if (char >= charCodeMap.zero && char <= charCodeMap.nine)
      return char - charCodeMap.zero;
    if (char >= charCodeMap.A && char <= charCodeMap.F)
      return char - (charCodeMap.A - 10);
    if (char >= charCodeMap.a && char <= charCodeMap.f)
      return char - (charCodeMap.a - 10);
    return;
  };
  encoder = new TextEncoder;
  charCodeMap = {
    zero: 48,
    nine: 57,
    A: 65,
    F: 70,
    a: 97,
    f: 102
  };
});

// node_modules/viem/_esm/utils/encoding/fromHex.js
function assertSize(hexOrBytes, { size: size3 }) {
  if (size(hexOrBytes) > size3)
    throw new SizeOverflowError({
      givenSize: size(hexOrBytes),
      maxSize: size3
    });
}
function hexToBigInt(hex, opts = {}) {
  const { signed } = opts;
  if (opts.size)
    assertSize(hex, { size: opts.size });
  const value = BigInt(hex);
  if (!signed)
    return value;
  const size3 = (hex.length - 2) / 2;
  const max = (1n << BigInt(size3) * 8n - 1n) - 1n;
  if (value <= max)
    return value;
  return value - BigInt(`0x${"f".padStart(size3 * 2, "f")}`) - 1n;
}
function hexToBool(hex_, opts = {}) {
  let hex = hex_;
  if (opts.size) {
    assertSize(hex, { size: opts.size });
    hex = trim(hex);
  }
  if (trim(hex) === "0x00")
    return false;
  if (trim(hex) === "0x01")
    return true;
  throw new InvalidHexBooleanError(hex);
}
function hexToNumber2(hex, opts = {}) {
  return Number(hexToBigInt(hex, opts));
}
var init_fromHex = __esm(() => {
  init_encoding();
  init_size();
  init_trim();
});

// node_modules/viem/_esm/utils/encoding/toHex.js
function toHex2(value, opts = {}) {
  if (typeof value === "number" || typeof value === "bigint")
    return numberToHex(value, opts);
  if (typeof value === "string") {
    return stringToHex(value, opts);
  }
  if (typeof value === "boolean")
    return boolToHex(value, opts);
  return bytesToHex2(value, opts);
}
function boolToHex(value, opts = {}) {
  const hex = `0x${Number(value)}`;
  if (typeof opts.size === "number") {
    assertSize(hex, { size: opts.size });
    return pad(hex, { size: opts.size });
  }
  return hex;
}
function bytesToHex2(value, opts = {}) {
  let string = "";
  for (let i = 0;i < value.length; i++) {
    string += hexes2[value[i]];
  }
  const hex = `0x${string}`;
  if (typeof opts.size === "number") {
    assertSize(hex, { size: opts.size });
    return pad(hex, { dir: "right", size: opts.size });
  }
  return hex;
}
function numberToHex(value_, opts = {}) {
  const { signed, size: size3 } = opts;
  const value = BigInt(value_);
  let maxValue;
  if (size3) {
    if (signed)
      maxValue = (1n << BigInt(size3) * 8n - 1n) - 1n;
    else
      maxValue = 2n ** (BigInt(size3) * 8n) - 1n;
  } else if (typeof value_ === "number") {
    maxValue = BigInt(Number.MAX_SAFE_INTEGER);
  }
  const minValue = typeof maxValue === "bigint" && signed ? -maxValue - 1n : 0;
  if (maxValue && value > maxValue || value < minValue) {
    const suffix = typeof value_ === "bigint" ? "n" : "";
    throw new IntegerOutOfRangeError({
      max: maxValue ? `${maxValue}${suffix}` : undefined,
      min: `${minValue}${suffix}`,
      signed,
      size: size3,
      value: `${value_}${suffix}`
    });
  }
  const hex = `0x${(signed && value < 0 ? (1n << BigInt(size3 * 8)) + BigInt(value) : value).toString(16)}`;
  if (size3)
    return pad(hex, { size: size3 });
  return hex;
}
function stringToHex(value_, opts = {}) {
  const value = encoder2.encode(value_);
  return bytesToHex2(value, opts);
}
var hexes2, encoder2;
var init_toHex = __esm(() => {
  init_encoding();
  init_pad();
  init_fromHex();
  hexes2 = Array.from({ length: 256 }, (_v, i) => i.toString(16).padStart(2, "0"));
  encoder2 = new TextEncoder;
});

// node_modules/viem/_esm/errors/address.js
class InvalidAddressError extends BaseError {
  constructor({ address }) {
    super(`Address "${address}" is invalid.`, {
      metaMessages: [
        "- Address must be a hex value of 20 bytes (40 hex characters).",
        "- Address must match its checksum counterpart."
      ],
      name: "InvalidAddressError"
    });
  }
}
var init_address = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/utils/lru.js
class LruMap extends Map {
  constructor(size3) {
    super();
    Object.defineProperty(this, "maxSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.maxSize = size3;
  }
  get(key) {
    const value = super.get(key);
    if (super.has(key) && value !== undefined) {
      this.delete(key);
      super.set(key, value);
    }
    return value;
  }
  set(key, value) {
    super.set(key, value);
    if (this.maxSize && this.size > this.maxSize) {
      const firstKey = this.keys().next().value;
      if (firstKey)
        this.delete(firstKey);
    }
    return this;
  }
}
var init_lru = __esm(() => {
});

// node_modules/@noble/hashes/esm/sha3.js
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds;round < 24; round++) {
    for (let x = 0;x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0;x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0;y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0;t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0;y < 50; y += 10) {
      for (let x = 0;x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0;x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  B.fill(0);
}

class Keccak extends Hash {
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    super();
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
    number(outputLen);
    if (0 >= this.blockLen || this.blockLen >= 200)
      throw new Error("Sha3 supports only keccak-f1600 function");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  keccak() {
    if (!isLE)
      byteSwap32(this.state32);
    keccakP(this.state32, this.rounds);
    if (!isLE)
      byteSwap32(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data2) {
    exists(this);
    const { blockLen, state } = this;
    data2 = toBytes(data2);
    const len = data2.length;
    for (let pos = 0;pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0;i < take; i++)
        state[this.pos++] ^= data2[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    exists(this, false);
    bytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length;pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes2) {
    number(bytes2);
    return this.xofInto(new Uint8Array(bytes2));
  }
  digestInto(out) {
    output(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    this.state.fill(0);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to || (to = new Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}
var SHA3_PI, SHA3_ROTL, _SHA3_IOTA, _0n6, _1n6, _2n5, _7n, _256n, _0x71n, SHA3_IOTA_H, SHA3_IOTA_L, rotlH, rotlL, gen, sha3_224, sha3_256, sha3_384, sha3_512, keccak_224, keccak_256, keccak_384, keccak_512, genShake, shake128, shake256;
var init_sha3 = __esm(() => {
  init__assert();
  init__u64();
  init_utils();
  SHA3_PI = [];
  SHA3_ROTL = [];
  _SHA3_IOTA = [];
  _0n6 = BigInt(0);
  _1n6 = BigInt(1);
  _2n5 = BigInt(2);
  _7n = BigInt(7);
  _256n = BigInt(256);
  _0x71n = BigInt(113);
  for (let round = 0, R = _1n6, x = 1, y = 0;round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    let t = _0n6;
    for (let j = 0;j < 7; j++) {
      R = (R << _1n6 ^ (R >> _7n) * _0x71n) % _256n;
      if (R & _2n5)
        t ^= _1n6 << (_1n6 << BigInt(j)) - _1n6;
    }
    _SHA3_IOTA.push(t);
  }
  [SHA3_IOTA_H, SHA3_IOTA_L] = split(_SHA3_IOTA, true);
  rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
  rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
  gen = (suffix, blockLen, outputLen) => wrapConstructor(() => new Keccak(blockLen, suffix, outputLen));
  sha3_224 = gen(6, 144, 224 / 8);
  sha3_256 = gen(6, 136, 256 / 8);
  sha3_384 = gen(6, 104, 384 / 8);
  sha3_512 = gen(6, 72, 512 / 8);
  keccak_224 = gen(1, 144, 224 / 8);
  keccak_256 = gen(1, 136, 256 / 8);
  keccak_384 = gen(1, 104, 384 / 8);
  keccak_512 = gen(1, 72, 512 / 8);
  genShake = (suffix, blockLen, outputLen) => wrapXOFConstructorWithOpts((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true));
  shake128 = genShake(31, 168, 128 / 8);
  shake256 = genShake(31, 136, 256 / 8);
});

// node_modules/viem/_esm/utils/hash/keccak256.js
function keccak256(value, to_) {
  const to = to_ || "hex";
  const bytes2 = keccak_256(isHex(value, { strict: false }) ? toBytes2(value) : value);
  if (to === "bytes")
    return bytes2;
  return toHex2(bytes2);
}
var init_keccak256 = __esm(() => {
  init_sha3();
  init_isHex();
  init_toBytes();
  init_toHex();
});

// node_modules/viem/_esm/utils/address/getAddress.js
function checksumAddress(address_, chainId) {
  if (checksumAddressCache.has(`${address_}.${chainId}`))
    return checksumAddressCache.get(`${address_}.${chainId}`);
  const hexAddress = chainId ? `${chainId}${address_.toLowerCase()}` : address_.substring(2).toLowerCase();
  const hash2 = keccak256(stringToBytes(hexAddress), "bytes");
  const address2 = (chainId ? hexAddress.substring(`${chainId}0x`.length) : hexAddress).split("");
  for (let i = 0;i < 40; i += 2) {
    if (hash2[i >> 1] >> 4 >= 8 && address2[i]) {
      address2[i] = address2[i].toUpperCase();
    }
    if ((hash2[i >> 1] & 15) >= 8 && address2[i + 1]) {
      address2[i + 1] = address2[i + 1].toUpperCase();
    }
  }
  const result = `0x${address2.join("")}`;
  checksumAddressCache.set(`${address_}.${chainId}`, result);
  return result;
}
function getAddress(address2, chainId) {
  if (!isAddress2(address2, { strict: false }))
    throw new InvalidAddressError({ address: address2 });
  return checksumAddress(address2, chainId);
}
var checksumAddressCache;
var init_getAddress = __esm(() => {
  init_address();
  init_toBytes();
  init_keccak256();
  init_lru();
  init_isAddress();
  checksumAddressCache = new LruMap(8192);
});

// node_modules/viem/_esm/utils/address/isAddress.js
function isAddress2(address2, options) {
  const { strict = true } = options ?? {};
  const cacheKey = `${address2}.${strict}`;
  if (isAddressCache.has(cacheKey))
    return isAddressCache.get(cacheKey);
  const result = (() => {
    if (!addressRegex.test(address2))
      return false;
    if (address2.toLowerCase() === address2)
      return true;
    if (strict)
      return checksumAddress(address2) === address2;
    return true;
  })();
  isAddressCache.set(cacheKey, result);
  return result;
}
var addressRegex, isAddressCache;
var init_isAddress = __esm(() => {
  init_lru();
  init_getAddress();
  addressRegex = /^0x[a-fA-F0-9]{40}$/;
  isAddressCache = new LruMap(8192);
});

// node_modules/viem/_esm/utils/data/concat.js
function concat(values) {
  if (typeof values[0] === "string")
    return concatHex(values);
  return concatBytes3(values);
}
function concatBytes3(values) {
  let length = 0;
  for (const arr of values) {
    length += arr.length;
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const arr of values) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
function concatHex(values) {
  return `0x${values.reduce((acc, x) => acc + x.replace("0x", ""), "")}`;
}
var init_concat = __esm(() => {
});

// node_modules/viem/_esm/errors/cursor.js
class NegativeOffsetError extends BaseError {
  constructor({ offset }) {
    super(`Offset \`${offset}\` cannot be negative.`, {
      name: "NegativeOffsetError"
    });
  }
}

class PositionOutOfBoundsError extends BaseError {
  constructor({ length, position }) {
    super(`Position \`${position}\` is out of bounds (\`0 < position < ${length}\`).`, { name: "PositionOutOfBoundsError" });
  }
}

class RecursiveReadLimitExceededError extends BaseError {
  constructor({ count, limit }) {
    super(`Recursive read limit of \`${limit}\` exceeded (recursive read count: \`${count}\`).`, { name: "RecursiveReadLimitExceededError" });
  }
}
var init_cursor = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/utils/cursor.js
function createCursor(bytes2, { recursiveReadLimit = 8192 } = {}) {
  const cursor2 = Object.create(staticCursor);
  cursor2.bytes = bytes2;
  cursor2.dataView = new DataView(bytes2.buffer, bytes2.byteOffset, bytes2.byteLength);
  cursor2.positionReadCount = new Map;
  cursor2.recursiveReadLimit = recursiveReadLimit;
  return cursor2;
}
var staticCursor;
var init_cursor2 = __esm(() => {
  init_cursor();
  staticCursor = {
    bytes: new Uint8Array,
    dataView: new DataView(new ArrayBuffer(0)),
    position: 0,
    positionReadCount: new Map,
    recursiveReadCount: 0,
    recursiveReadLimit: Number.POSITIVE_INFINITY,
    assertReadLimit() {
      if (this.recursiveReadCount >= this.recursiveReadLimit)
        throw new RecursiveReadLimitExceededError({
          count: this.recursiveReadCount + 1,
          limit: this.recursiveReadLimit
        });
    },
    assertPosition(position) {
      if (position < 0 || position > this.bytes.length - 1)
        throw new PositionOutOfBoundsError({
          length: this.bytes.length,
          position
        });
    },
    decrementPosition(offset) {
      if (offset < 0)
        throw new NegativeOffsetError({ offset });
      const position = this.position - offset;
      this.assertPosition(position);
      this.position = position;
    },
    getReadCount(position) {
      return this.positionReadCount.get(position || this.position) || 0;
    },
    incrementPosition(offset) {
      if (offset < 0)
        throw new NegativeOffsetError({ offset });
      const position = this.position + offset;
      this.assertPosition(position);
      this.position = position;
    },
    inspectByte(position_) {
      const position = position_ ?? this.position;
      this.assertPosition(position);
      return this.bytes[position];
    },
    inspectBytes(length, position_) {
      const position = position_ ?? this.position;
      this.assertPosition(position + length - 1);
      return this.bytes.subarray(position, position + length);
    },
    inspectUint8(position_) {
      const position = position_ ?? this.position;
      this.assertPosition(position);
      return this.bytes[position];
    },
    inspectUint16(position_) {
      const position = position_ ?? this.position;
      this.assertPosition(position + 1);
      return this.dataView.getUint16(position);
    },
    inspectUint24(position_) {
      const position = position_ ?? this.position;
      this.assertPosition(position + 2);
      return (this.dataView.getUint16(position) << 8) + this.dataView.getUint8(position + 2);
    },
    inspectUint32(position_) {
      const position = position_ ?? this.position;
      this.assertPosition(position + 3);
      return this.dataView.getUint32(position);
    },
    pushByte(byte) {
      this.assertPosition(this.position);
      this.bytes[this.position] = byte;
      this.position++;
    },
    pushBytes(bytes2) {
      this.assertPosition(this.position + bytes2.length - 1);
      this.bytes.set(bytes2, this.position);
      this.position += bytes2.length;
    },
    pushUint8(value) {
      this.assertPosition(this.position);
      this.bytes[this.position] = value;
      this.position++;
    },
    pushUint16(value) {
      this.assertPosition(this.position + 1);
      this.dataView.setUint16(this.position, value);
      this.position += 2;
    },
    pushUint24(value) {
      this.assertPosition(this.position + 2);
      this.dataView.setUint16(this.position, value >> 8);
      this.dataView.setUint8(this.position + 2, value & ~4294967040);
      this.position += 3;
    },
    pushUint32(value) {
      this.assertPosition(this.position + 3);
      this.dataView.setUint32(this.position, value);
      this.position += 4;
    },
    readByte() {
      this.assertReadLimit();
      this._touch();
      const value = this.inspectByte();
      this.position++;
      return value;
    },
    readBytes(length, size3) {
      this.assertReadLimit();
      this._touch();
      const value = this.inspectBytes(length);
      this.position += size3 ?? length;
      return value;
    },
    readUint8() {
      this.assertReadLimit();
      this._touch();
      const value = this.inspectUint8();
      this.position += 1;
      return value;
    },
    readUint16() {
      this.assertReadLimit();
      this._touch();
      const value = this.inspectUint16();
      this.position += 2;
      return value;
    },
    readUint24() {
      this.assertReadLimit();
      this._touch();
      const value = this.inspectUint24();
      this.position += 3;
      return value;
    },
    readUint32() {
      this.assertReadLimit();
      this._touch();
      const value = this.inspectUint32();
      this.position += 4;
      return value;
    },
    get remaining() {
      return this.bytes.length - this.position;
    },
    setPosition(position) {
      const oldPosition = this.position;
      this.assertPosition(position);
      this.position = position;
      return () => this.position = oldPosition;
    },
    _touch() {
      if (this.recursiveReadLimit === Number.POSITIVE_INFINITY)
        return;
      const count = this.getReadCount();
      this.positionReadCount.set(this.position, count + 1);
      if (count > 0)
        this.recursiveReadCount++;
    }
  };
});

// node_modules/viem/_esm/constants/unit.js
var etherUnits, gweiUnits;
var init_unit = __esm(() => {
  etherUnits = {
    gwei: 9,
    wei: 18
  };
  gweiUnits = {
    ether: -9,
    wei: 9
  };
});

// node_modules/viem/_esm/utils/unit/formatUnits.js
function formatUnits(value, decimals) {
  let display = value.toString();
  const negative = display.startsWith("-");
  if (negative)
    display = display.slice(1);
  display = display.padStart(decimals, "0");
  let [integer, fraction] = [
    display.slice(0, display.length - decimals),
    display.slice(display.length - decimals)
  ];
  fraction = fraction.replace(/(0+)$/, "");
  return `${negative ? "-" : ""}${integer || "0"}${fraction ? `.${fraction}` : ""}`;
}
var init_formatUnits = __esm(() => {
});

// node_modules/viem/_esm/utils/unit/formatEther.js
function formatEther(wei, unit2 = "wei") {
  return formatUnits(wei, etherUnits[unit2]);
}
var init_formatEther = __esm(() => {
  init_unit();
  init_formatUnits();
});

// node_modules/viem/_esm/utils/unit/formatGwei.js
function formatGwei(wei, unit3 = "wei") {
  return formatUnits(wei, gweiUnits[unit3]);
}
var init_formatGwei = __esm(() => {
  init_unit();
  init_formatUnits();
});

// node_modules/viem/_esm/errors/transaction.js
function prettyPrint(args) {
  const entries = Object.entries(args).map(([key, value]) => {
    if (value === undefined || value === false)
      return null;
    return [key, value];
  }).filter(Boolean);
  const maxLength = entries.reduce((acc, [key]) => Math.max(acc, key.length), 0);
  return entries.map(([key, value]) => `  ${`${key}:`.padEnd(maxLength + 1)}  ${value}`).join("\n");
}

class FeeConflictError extends BaseError {
  constructor() {
    super([
      "Cannot specify both a `gasPrice` and a `maxFeePerGas`/`maxPriorityFeePerGas`.",
      "Use `maxFeePerGas`/`maxPriorityFeePerGas` for EIP-1559 compatible networks, and `gasPrice` for others."
    ].join("\n"), { name: "FeeConflictError" });
  }
}

class InvalidLegacyVError extends BaseError {
  constructor({ v }) {
    super(`Invalid \`v\` value "${v}". Expected 27 or 28.`, {
      name: "InvalidLegacyVError"
    });
  }
}

class InvalidSerializableTransactionError extends BaseError {
  constructor({ transaction }) {
    super("Cannot infer a transaction type from provided transaction.", {
      metaMessages: [
        "Provided Transaction:",
        "{",
        prettyPrint(transaction),
        "}",
        "",
        "To infer the type, either provide:",
        "- a `type` to the Transaction, or",
        "- an EIP-1559 Transaction with `maxFeePerGas`, or",
        "- an EIP-2930 Transaction with `gasPrice` & `accessList`, or",
        "- an EIP-4844 Transaction with `blobs`, `blobVersionedHashes`, `sidecars`, or",
        "- an EIP-7702 Transaction with `authorizationList`, or",
        "- a Legacy Transaction with `gasPrice`"
      ],
      name: "InvalidSerializableTransactionError"
    });
  }
}

class InvalidStorageKeySizeError extends BaseError {
  constructor({ storageKey }) {
    super(`Size for storage key "${storageKey}" is invalid. Expected 32 bytes. Got ${Math.floor((storageKey.length - 2) / 2)} bytes.`, { name: "InvalidStorageKeySizeError" });
  }
}

class TransactionExecutionError extends BaseError {
  constructor(cause, { account, docsPath, chain, data: data2, gas, gasPrice, maxFeePerGas, maxPriorityFeePerGas, nonce, to, value }) {
    const prettyArgs = prettyPrint({
      chain: chain && `${chain?.name} (id: ${chain?.id})`,
      from: account?.address,
      to,
      value: typeof value !== "undefined" && `${formatEther(value)} ${chain?.nativeCurrency?.symbol || "ETH"}`,
      data: data2,
      gas,
      gasPrice: typeof gasPrice !== "undefined" && `${formatGwei(gasPrice)} gwei`,
      maxFeePerGas: typeof maxFeePerGas !== "undefined" && `${formatGwei(maxFeePerGas)} gwei`,
      maxPriorityFeePerGas: typeof maxPriorityFeePerGas !== "undefined" && `${formatGwei(maxPriorityFeePerGas)} gwei`,
      nonce
    });
    super(cause.shortMessage, {
      cause,
      docsPath,
      metaMessages: [
        ...cause.metaMessages ? [...cause.metaMessages, " "] : [],
        "Request Arguments:",
        prettyArgs
      ].filter(Boolean),
      name: "TransactionExecutionError"
    });
    Object.defineProperty(this, "cause", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.cause = cause;
  }
}

class TransactionNotFoundError extends BaseError {
  constructor({ blockHash, blockNumber, blockTag, hash: hash2, index }) {
    let identifier = "Transaction";
    if (blockTag && index !== undefined)
      identifier = `Transaction at block time "${blockTag}" at index "${index}"`;
    if (blockHash && index !== undefined)
      identifier = `Transaction at block hash "${blockHash}" at index "${index}"`;
    if (blockNumber && index !== undefined)
      identifier = `Transaction at block number "${blockNumber}" at index "${index}"`;
    if (hash2)
      identifier = `Transaction with hash "${hash2}"`;
    super(`${identifier} could not be found.`, {
      name: "TransactionNotFoundError"
    });
  }
}

class TransactionReceiptNotFoundError extends BaseError {
  constructor({ hash: hash2 }) {
    super(`Transaction receipt with hash "${hash2}" could not be found. The Transaction may not be processed on a block yet.`, {
      name: "TransactionReceiptNotFoundError"
    });
  }
}

class WaitForTransactionReceiptTimeoutError extends BaseError {
  constructor({ hash: hash2 }) {
    super(`Timed out while waiting for transaction with hash "${hash2}" to be confirmed.`, { name: "WaitForTransactionReceiptTimeoutError" });
  }
}
var init_transaction = __esm(() => {
  init_formatEther();
  init_formatGwei();
  init_base();
});

// node_modules/viem/_esm/constants/number.js
var maxInt8, maxInt16, maxInt24, maxInt32, maxInt40, maxInt48, maxInt56, maxInt64, maxInt72, maxInt80, maxInt88, maxInt96, maxInt104, maxInt112, maxInt120, maxInt128, maxInt136, maxInt144, maxInt152, maxInt160, maxInt168, maxInt176, maxInt184, maxInt192, maxInt200, maxInt208, maxInt216, maxInt224, maxInt232, maxInt240, maxInt248, maxInt256, minInt8, minInt16, minInt24, minInt32, minInt40, minInt48, minInt56, minInt64, minInt72, minInt80, minInt88, minInt96, minInt104, minInt112, minInt120, minInt128, minInt136, minInt144, minInt152, minInt160, minInt168, minInt176, minInt184, minInt192, minInt200, minInt208, minInt216, minInt224, minInt232, minInt240, minInt248, minInt256, maxUint8, maxUint16, maxUint24, maxUint32, maxUint40, maxUint48, maxUint56, maxUint64, maxUint72, maxUint80, maxUint88, maxUint96, maxUint104, maxUint112, maxUint120, maxUint128, maxUint136, maxUint144, maxUint152, maxUint160, maxUint168, maxUint176, maxUint184, maxUint192, maxUint200, maxUint208, maxUint216, maxUint224, maxUint232, maxUint240, maxUint248, maxUint256;
var init_number = __esm(() => {
  maxInt8 = 2n ** (8n - 1n) - 1n;
  maxInt16 = 2n ** (16n - 1n) - 1n;
  maxInt24 = 2n ** (24n - 1n) - 1n;
  maxInt32 = 2n ** (32n - 1n) - 1n;
  maxInt40 = 2n ** (40n - 1n) - 1n;
  maxInt48 = 2n ** (48n - 1n) - 1n;
  maxInt56 = 2n ** (56n - 1n) - 1n;
  maxInt64 = 2n ** (64n - 1n) - 1n;
  maxInt72 = 2n ** (72n - 1n) - 1n;
  maxInt80 = 2n ** (80n - 1n) - 1n;
  maxInt88 = 2n ** (88n - 1n) - 1n;
  maxInt96 = 2n ** (96n - 1n) - 1n;
  maxInt104 = 2n ** (104n - 1n) - 1n;
  maxInt112 = 2n ** (112n - 1n) - 1n;
  maxInt120 = 2n ** (120n - 1n) - 1n;
  maxInt128 = 2n ** (128n - 1n) - 1n;
  maxInt136 = 2n ** (136n - 1n) - 1n;
  maxInt144 = 2n ** (144n - 1n) - 1n;
  maxInt152 = 2n ** (152n - 1n) - 1n;
  maxInt160 = 2n ** (160n - 1n) - 1n;
  maxInt168 = 2n ** (168n - 1n) - 1n;
  maxInt176 = 2n ** (176n - 1n) - 1n;
  maxInt184 = 2n ** (184n - 1n) - 1n;
  maxInt192 = 2n ** (192n - 1n) - 1n;
  maxInt200 = 2n ** (200n - 1n) - 1n;
  maxInt208 = 2n ** (208n - 1n) - 1n;
  maxInt216 = 2n ** (216n - 1n) - 1n;
  maxInt224 = 2n ** (224n - 1n) - 1n;
  maxInt232 = 2n ** (232n - 1n) - 1n;
  maxInt240 = 2n ** (240n - 1n) - 1n;
  maxInt248 = 2n ** (248n - 1n) - 1n;
  maxInt256 = 2n ** (256n - 1n) - 1n;
  minInt8 = -(2n ** (8n - 1n));
  minInt16 = -(2n ** (16n - 1n));
  minInt24 = -(2n ** (24n - 1n));
  minInt32 = -(2n ** (32n - 1n));
  minInt40 = -(2n ** (40n - 1n));
  minInt48 = -(2n ** (48n - 1n));
  minInt56 = -(2n ** (56n - 1n));
  minInt64 = -(2n ** (64n - 1n));
  minInt72 = -(2n ** (72n - 1n));
  minInt80 = -(2n ** (80n - 1n));
  minInt88 = -(2n ** (88n - 1n));
  minInt96 = -(2n ** (96n - 1n));
  minInt104 = -(2n ** (104n - 1n));
  minInt112 = -(2n ** (112n - 1n));
  minInt120 = -(2n ** (120n - 1n));
  minInt128 = -(2n ** (128n - 1n));
  minInt136 = -(2n ** (136n - 1n));
  minInt144 = -(2n ** (144n - 1n));
  minInt152 = -(2n ** (152n - 1n));
  minInt160 = -(2n ** (160n - 1n));
  minInt168 = -(2n ** (168n - 1n));
  minInt176 = -(2n ** (176n - 1n));
  minInt184 = -(2n ** (184n - 1n));
  minInt192 = -(2n ** (192n - 1n));
  minInt200 = -(2n ** (200n - 1n));
  minInt208 = -(2n ** (208n - 1n));
  minInt216 = -(2n ** (216n - 1n));
  minInt224 = -(2n ** (224n - 1n));
  minInt232 = -(2n ** (232n - 1n));
  minInt240 = -(2n ** (240n - 1n));
  minInt248 = -(2n ** (248n - 1n));
  minInt256 = -(2n ** (256n - 1n));
  maxUint8 = 2n ** 8n - 1n;
  maxUint16 = 2n ** 16n - 1n;
  maxUint24 = 2n ** 24n - 1n;
  maxUint32 = 2n ** 32n - 1n;
  maxUint40 = 2n ** 40n - 1n;
  maxUint48 = 2n ** 48n - 1n;
  maxUint56 = 2n ** 56n - 1n;
  maxUint64 = 2n ** 64n - 1n;
  maxUint72 = 2n ** 72n - 1n;
  maxUint80 = 2n ** 80n - 1n;
  maxUint88 = 2n ** 88n - 1n;
  maxUint96 = 2n ** 96n - 1n;
  maxUint104 = 2n ** 104n - 1n;
  maxUint112 = 2n ** 112n - 1n;
  maxUint120 = 2n ** 120n - 1n;
  maxUint128 = 2n ** 128n - 1n;
  maxUint136 = 2n ** 136n - 1n;
  maxUint144 = 2n ** 144n - 1n;
  maxUint152 = 2n ** 152n - 1n;
  maxUint160 = 2n ** 160n - 1n;
  maxUint168 = 2n ** 168n - 1n;
  maxUint176 = 2n ** 176n - 1n;
  maxUint184 = 2n ** 184n - 1n;
  maxUint192 = 2n ** 192n - 1n;
  maxUint200 = 2n ** 200n - 1n;
  maxUint208 = 2n ** 208n - 1n;
  maxUint216 = 2n ** 216n - 1n;
  maxUint224 = 2n ** 224n - 1n;
  maxUint232 = 2n ** 232n - 1n;
  maxUint240 = 2n ** 240n - 1n;
  maxUint248 = 2n ** 248n - 1n;
  maxUint256 = 2n ** 256n - 1n;
});

// node_modules/viem/_esm/errors/chain.js
class ChainDoesNotSupportContract extends BaseError {
  constructor({ blockNumber, chain, contract }) {
    super(`Chain "${chain.name}" does not support contract "${contract.name}".`, {
      metaMessages: [
        "This could be due to any of the following:",
        ...blockNumber && contract.blockCreated && contract.blockCreated > blockNumber ? [
          `- The contract "${contract.name}" was not deployed until block ${contract.blockCreated} (current block ${blockNumber}).`
        ] : [
          `- The chain does not have the contract "${contract.name}" configured.`
        ]
      ],
      name: "ChainDoesNotSupportContract"
    });
  }
}

class ChainMismatchError extends BaseError {
  constructor({ chain, currentChainId }) {
    super(`The current chain of the wallet (id: ${currentChainId}) does not match the target chain for the transaction (id: ${chain.id} \u2013 ${chain.name}).`, {
      metaMessages: [
        `Current Chain ID:  ${currentChainId}`,
        `Expected Chain ID: ${chain.id} \u2013 ${chain.name}`
      ],
      name: "ChainMismatchError"
    });
  }
}

class ChainNotFoundError extends BaseError {
  constructor() {
    super([
      "No chain was provided to the request.",
      "Please provide a chain with the `chain` argument on the Action, or by supplying a `chain` to WalletClient."
    ].join("\n"), {
      name: "ChainNotFoundError"
    });
  }
}

class ClientChainNotConfiguredError extends BaseError {
  constructor() {
    super("No chain was provided to the Client.", {
      name: "ClientChainNotConfiguredError"
    });
  }
}

class InvalidChainIdError extends BaseError {
  constructor({ chainId }) {
    super(typeof chainId === "number" ? `Chain ID "${chainId}" is invalid.` : "Chain ID is invalid.", { name: "InvalidChainIdError" });
  }
}
var init_chain = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/errors/node.js
class ExecutionRevertedError extends BaseError {
  constructor({ cause, message } = {}) {
    const reason = message?.replace("execution reverted: ", "")?.replace("execution reverted", "");
    super(`Execution reverted ${reason ? `with reason: ${reason}` : "for an unknown reason"}.`, {
      cause,
      name: "ExecutionRevertedError"
    });
  }
}

class FeeCapTooHighError extends BaseError {
  constructor({ cause, maxFeePerGas } = {}) {
    super(`The fee cap (\`maxFeePerGas\`${maxFeePerGas ? ` = ${formatGwei(maxFeePerGas)} gwei` : ""}) cannot be higher than the maximum allowed value (2^256-1).`, {
      cause,
      name: "FeeCapTooHighError"
    });
  }
}

class FeeCapTooLowError extends BaseError {
  constructor({ cause, maxFeePerGas } = {}) {
    super(`The fee cap (\`maxFeePerGas\`${maxFeePerGas ? ` = ${formatGwei(maxFeePerGas)}` : ""} gwei) cannot be lower than the block base fee.`, {
      cause,
      name: "FeeCapTooLowError"
    });
  }
}

class NonceTooHighError extends BaseError {
  constructor({ cause, nonce } = {}) {
    super(`Nonce provided for the transaction ${nonce ? `(${nonce}) ` : ""}is higher than the next one expected.`, { cause, name: "NonceTooHighError" });
  }
}

class NonceTooLowError extends BaseError {
  constructor({ cause, nonce } = {}) {
    super([
      `Nonce provided for the transaction ${nonce ? `(${nonce}) ` : ""}is lower than the current nonce of the account.`,
      "Try increasing the nonce or find the latest nonce with `getTransactionCount`."
    ].join("\n"), { cause, name: "NonceTooLowError" });
  }
}

class NonceMaxValueError extends BaseError {
  constructor({ cause, nonce } = {}) {
    super(`Nonce provided for the transaction ${nonce ? `(${nonce}) ` : ""}exceeds the maximum allowed nonce.`, { cause, name: "NonceMaxValueError" });
  }
}

class InsufficientFundsError extends BaseError {
  constructor({ cause } = {}) {
    super([
      "The total cost (gas * gas fee + value) of executing this transaction exceeds the balance of the account."
    ].join("\n"), {
      cause,
      metaMessages: [
        "This error could arise when the account does not have enough funds to:",
        " - pay for the total gas fee,",
        " - pay for the value to send.",
        " ",
        "The cost of the transaction is calculated as `gas * gas fee + value`, where:",
        " - `gas` is the amount of gas needed for transaction to execute,",
        " - `gas fee` is the gas fee,",
        " - `value` is the amount of ether to send to the recipient."
      ],
      name: "InsufficientFundsError"
    });
  }
}

class IntrinsicGasTooHighError extends BaseError {
  constructor({ cause, gas } = {}) {
    super(`The amount of gas ${gas ? `(${gas}) ` : ""}provided for the transaction exceeds the limit allowed for the block.`, {
      cause,
      name: "IntrinsicGasTooHighError"
    });
  }
}

class IntrinsicGasTooLowError extends BaseError {
  constructor({ cause, gas } = {}) {
    super(`The amount of gas ${gas ? `(${gas}) ` : ""}provided for the transaction is too low.`, {
      cause,
      name: "IntrinsicGasTooLowError"
    });
  }
}

class TransactionTypeNotSupportedError extends BaseError {
  constructor({ cause }) {
    super("The transaction type is not supported for this chain.", {
      cause,
      name: "TransactionTypeNotSupportedError"
    });
  }
}

class TipAboveFeeCapError extends BaseError {
  constructor({ cause, maxPriorityFeePerGas, maxFeePerGas } = {}) {
    super([
      `The provided tip (\`maxPriorityFeePerGas\`${maxPriorityFeePerGas ? ` = ${formatGwei(maxPriorityFeePerGas)} gwei` : ""}) cannot be higher than the fee cap (\`maxFeePerGas\`${maxFeePerGas ? ` = ${formatGwei(maxFeePerGas)} gwei` : ""}).`
    ].join("\n"), {
      cause,
      name: "TipAboveFeeCapError"
    });
  }
}

class UnknownNodeError extends BaseError {
  constructor({ cause }) {
    super(`An error occurred while executing: ${cause?.shortMessage}`, {
      cause,
      name: "UnknownNodeError"
    });
  }
}
var init_node = __esm(() => {
  init_formatGwei();
  init_base();
  Object.defineProperty(ExecutionRevertedError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 3
  });
  Object.defineProperty(ExecutionRevertedError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /execution reverted/
  });
  Object.defineProperty(FeeCapTooHighError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /max fee per gas higher than 2\^256-1|fee cap higher than 2\^256-1/
  });
  Object.defineProperty(FeeCapTooLowError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /max fee per gas less than block base fee|fee cap less than block base fee|transaction is outdated/
  });
  Object.defineProperty(NonceTooHighError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /nonce too high/
  });
  Object.defineProperty(NonceTooLowError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /nonce too low|transaction already imported|already known/
  });
  Object.defineProperty(NonceMaxValueError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /nonce has max value/
  });
  Object.defineProperty(InsufficientFundsError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /insufficient funds|exceeds transaction sender account balance/
  });
  Object.defineProperty(IntrinsicGasTooHighError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /intrinsic gas too high|gas limit reached/
  });
  Object.defineProperty(IntrinsicGasTooLowError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /intrinsic gas too low/
  });
  Object.defineProperty(TransactionTypeNotSupportedError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /transaction type not valid/
  });
  Object.defineProperty(TipAboveFeeCapError, "nodeMessage", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: /max priority fee per gas higher than max fee per gas|tip higher than fee cap/
  });
});

// node_modules/viem/_esm/utils/data/slice.js
function slice(value, start, end, { strict } = {}) {
  if (isHex(value, { strict: false }))
    return sliceHex(value, start, end, {
      strict
    });
  return sliceBytes(value, start, end, {
    strict
  });
}
function sliceBytes(value_, start, end, { strict } = {}) {
  assertStartOffset(value_, start);
  const value = value_.slice(start, end);
  if (strict)
    assertEndOffset(value, start, end);
  return value;
}
function sliceHex(value_, start, end, { strict } = {}) {
  assertStartOffset(value_, start);
  const value = `0x${value_.replace("0x", "").slice((start ?? 0) * 2, (end ?? value_.length) * 2)}`;
  if (strict)
    assertEndOffset(value, start, end);
  return value;
}
var assertStartOffset, assertEndOffset;
var init_slice = __esm(() => {
  init_data();
  init_isHex();
  init_size();
  assertStartOffset = function(value, start) {
    if (typeof start === "number" && start > 0 && start > size(value) - 1)
      throw new SliceOffsetOutOfBoundsError({
        offset: start,
        position: "start",
        size: size(value)
      });
  };
  assertEndOffset = function(value, start, end) {
    if (typeof start === "number" && typeof end === "number" && size(value) !== end - start) {
      throw new SliceOffsetOutOfBoundsError({
        offset: end,
        position: "end",
        size: size(value)
      });
    }
  };
});

// node_modules/viem/_esm/utils/abi/formatAbiItem.js
function formatAbiItem(abiItem, { includeName = false } = {}) {
  if (abiItem.type !== "function" && abiItem.type !== "event" && abiItem.type !== "error")
    throw new InvalidDefinitionTypeError(abiItem.type);
  return `${abiItem.name}(${formatAbiParams(abiItem.inputs, { includeName })})`;
}
function formatAbiParams(params, { includeName = false } = {}) {
  if (!params)
    return "";
  return params.map((param) => formatAbiParam(param, { includeName })).join(includeName ? ", " : ",");
}
var formatAbiParam;
var init_formatAbiItem = __esm(() => {
  init_abi();
  formatAbiParam = function(param, { includeName }) {
    if (param.type.startsWith("tuple")) {
      return `(${formatAbiParams(param.components, { includeName })})${param.type.slice("tuple".length)}`;
    }
    return param.type + (includeName && param.name ? ` ${param.name}` : "");
  };
});

// node_modules/viem/_esm/errors/abi.js
class AbiConstructorNotFoundError extends BaseError {
  constructor({ docsPath }) {
    super([
      "A constructor was not found on the ABI.",
      "Make sure you are using the correct ABI and that the constructor exists on it."
    ].join("\n"), {
      docsPath,
      name: "AbiConstructorNotFoundError"
    });
  }
}

class AbiConstructorParamsNotFoundError extends BaseError {
  constructor({ docsPath }) {
    super([
      "Constructor arguments were provided (`args`), but a constructor parameters (`inputs`) were not found on the ABI.",
      "Make sure you are using the correct ABI, and that the `inputs` attribute on the constructor exists."
    ].join("\n"), {
      docsPath,
      name: "AbiConstructorParamsNotFoundError"
    });
  }
}

class AbiDecodingDataSizeTooSmallError extends BaseError {
  constructor({ data: data3, params, size: size8 }) {
    super([`Data size of ${size8} bytes is too small for given parameters.`].join("\n"), {
      metaMessages: [
        `Params: (${formatAbiParams(params, { includeName: true })})`,
        `Data:   ${data3} (${size8} bytes)`
      ],
      name: "AbiDecodingDataSizeTooSmallError"
    });
    Object.defineProperty(this, "data", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "params", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "size", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.data = data3;
    this.params = params;
    this.size = size8;
  }
}

class AbiDecodingZeroDataError extends BaseError {
  constructor() {
    super('Cannot decode zero data ("0x") with ABI parameters.', {
      name: "AbiDecodingZeroDataError"
    });
  }
}

class AbiEncodingArrayLengthMismatchError extends BaseError {
  constructor({ expectedLength, givenLength, type }) {
    super([
      `ABI encoding array length mismatch for type ${type}.`,
      `Expected length: ${expectedLength}`,
      `Given length: ${givenLength}`
    ].join("\n"), { name: "AbiEncodingArrayLengthMismatchError" });
  }
}

class AbiEncodingBytesSizeMismatchError extends BaseError {
  constructor({ expectedSize, value }) {
    super(`Size of bytes "${value}" (bytes${size(value)}) does not match expected size (bytes${expectedSize}).`, { name: "AbiEncodingBytesSizeMismatchError" });
  }
}

class AbiEncodingLengthMismatchError extends BaseError {
  constructor({ expectedLength, givenLength }) {
    super([
      "ABI encoding params/values length mismatch.",
      `Expected length (params): ${expectedLength}`,
      `Given length (values): ${givenLength}`
    ].join("\n"), { name: "AbiEncodingLengthMismatchError" });
  }
}

class AbiErrorSignatureNotFoundError extends BaseError {
  constructor(signature, { docsPath }) {
    super([
      `Encoded error signature "${signature}" not found on ABI.`,
      "Make sure you are using the correct ABI and that the error exists on it.",
      `You can look up the decoded signature here: https://openchain.xyz/signatures?query=${signature}.`
    ].join("\n"), {
      docsPath,
      name: "AbiErrorSignatureNotFoundError"
    });
    Object.defineProperty(this, "signature", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.signature = signature;
  }
}

class AbiEventSignatureEmptyTopicsError extends BaseError {
  constructor({ docsPath }) {
    super("Cannot extract event signature from empty topics.", {
      docsPath,
      name: "AbiEventSignatureEmptyTopicsError"
    });
  }
}

class AbiEventSignatureNotFoundError extends BaseError {
  constructor(signature, { docsPath }) {
    super([
      `Encoded event signature "${signature}" not found on ABI.`,
      "Make sure you are using the correct ABI and that the event exists on it.",
      `You can look up the signature here: https://openchain.xyz/signatures?query=${signature}.`
    ].join("\n"), {
      docsPath,
      name: "AbiEventSignatureNotFoundError"
    });
  }
}

class AbiEventNotFoundError extends BaseError {
  constructor(eventName, { docsPath } = {}) {
    super([
      `Event ${eventName ? `"${eventName}" ` : ""}not found on ABI.`,
      "Make sure you are using the correct ABI and that the event exists on it."
    ].join("\n"), {
      docsPath,
      name: "AbiEventNotFoundError"
    });
  }
}

class AbiFunctionNotFoundError extends BaseError {
  constructor(functionName, { docsPath } = {}) {
    super([
      `Function ${functionName ? `"${functionName}" ` : ""}not found on ABI.`,
      "Make sure you are using the correct ABI and that the function exists on it."
    ].join("\n"), {
      docsPath,
      name: "AbiFunctionNotFoundError"
    });
  }
}

class AbiFunctionOutputsNotFoundError extends BaseError {
  constructor(functionName, { docsPath }) {
    super([
      `Function "${functionName}" does not contain any \`outputs\` on ABI.`,
      "Cannot decode function result without knowing what the parameter types are.",
      "Make sure you are using the correct ABI and that the function exists on it."
    ].join("\n"), {
      docsPath,
      name: "AbiFunctionOutputsNotFoundError"
    });
  }
}

class AbiItemAmbiguityError extends BaseError {
  constructor(x, y) {
    super("Found ambiguous types in overloaded ABI items.", {
      metaMessages: [
        `\`${x.type}\` in \`${formatAbiItem(x.abiItem)}\`, and`,
        `\`${y.type}\` in \`${formatAbiItem(y.abiItem)}\``,
        "",
        "These types encode differently and cannot be distinguished at runtime.",
        "Remove one of the ambiguous items in the ABI."
      ],
      name: "AbiItemAmbiguityError"
    });
  }
}

class BytesSizeMismatchError extends BaseError {
  constructor({ expectedSize, givenSize }) {
    super(`Expected bytes${expectedSize}, got bytes${givenSize}.`, {
      name: "BytesSizeMismatchError"
    });
  }
}

class DecodeLogDataMismatch extends BaseError {
  constructor({ abiItem, data: data3, params, size: size8 }) {
    super([
      `Data size of ${size8} bytes is too small for non-indexed event parameters.`
    ].join("\n"), {
      metaMessages: [
        `Params: (${formatAbiParams(params, { includeName: true })})`,
        `Data:   ${data3} (${size8} bytes)`
      ],
      name: "DecodeLogDataMismatch"
    });
    Object.defineProperty(this, "abiItem", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "data", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "params", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "size", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.abiItem = abiItem;
    this.data = data3;
    this.params = params;
    this.size = size8;
  }
}

class DecodeLogTopicsMismatch extends BaseError {
  constructor({ abiItem, param }) {
    super([
      `Expected a topic for indexed event parameter${param.name ? ` "${param.name}"` : ""} on event "${formatAbiItem(abiItem, { includeName: true })}".`
    ].join("\n"), { name: "DecodeLogTopicsMismatch" });
    Object.defineProperty(this, "abiItem", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.abiItem = abiItem;
  }
}

class InvalidAbiEncodingTypeError extends BaseError {
  constructor(type, { docsPath }) {
    super([
      `Type "${type}" is not a valid encoding type.`,
      "Please provide a valid ABI type."
    ].join("\n"), { docsPath, name: "InvalidAbiEncodingType" });
  }
}

class InvalidAbiDecodingTypeError extends BaseError {
  constructor(type, { docsPath }) {
    super([
      `Type "${type}" is not a valid decoding type.`,
      "Please provide a valid ABI type."
    ].join("\n"), { docsPath, name: "InvalidAbiDecodingType" });
  }
}

class InvalidArrayError extends BaseError {
  constructor(value) {
    super([`Value "${value}" is not a valid array.`].join("\n"), {
      name: "InvalidArrayError"
    });
  }
}

class InvalidDefinitionTypeError extends BaseError {
  constructor(type) {
    super([
      `"${type}" is not a valid definition type.`,
      'Valid types: "function", "event", "error"'
    ].join("\n"), { name: "InvalidDefinitionTypeError" });
  }
}

class UnsupportedPackedAbiType extends BaseError {
  constructor(type) {
    super(`Type "${type}" is not supported for packed encoding.`, {
      name: "UnsupportedPackedAbiType"
    });
  }
}
var init_abi = __esm(() => {
  init_formatAbiItem();
  init_size();
  init_base();
});

// node_modules/viem/_esm/utils/abi/encodeAbiParameters.js
function encodeAbiParameters(params, values) {
  if (params.length !== values.length)
    throw new AbiEncodingLengthMismatchError({
      expectedLength: params.length,
      givenLength: values.length
    });
  const preparedParams = prepareParams({
    params,
    values
  });
  const data3 = encodeParams(preparedParams);
  if (data3.length === 0)
    return "0x";
  return data3;
}
function getArrayComponents(type) {
  const matches = type.match(/^(.*)\[(\d+)?\]$/);
  return matches ? [matches[2] ? Number(matches[2]) : null, matches[1]] : undefined;
}
var prepareParams, prepareParam, encodeParams, encodeAddress, encodeArray, encodeBytes, encodeBool, encodeNumber, encodeString, encodeTuple;
var init_encodeAbiParameters = __esm(() => {
  init_abi();
  init_address();
  init_base();
  init_isAddress();
  init_concat();
  init_pad();
  init_size();
  init_slice();
  init_toHex();
  prepareParams = function({ params, values }) {
    const preparedParams = [];
    for (let i = 0;i < params.length; i++) {
      preparedParams.push(prepareParam({ param: params[i], value: values[i] }));
    }
    return preparedParams;
  };
  prepareParam = function({ param, value }) {
    const arrayComponents = getArrayComponents(param.type);
    if (arrayComponents) {
      const [length, type] = arrayComponents;
      return encodeArray(value, { length, param: { ...param, type } });
    }
    if (param.type === "tuple") {
      return encodeTuple(value, {
        param
      });
    }
    if (param.type === "address") {
      return encodeAddress(value);
    }
    if (param.type === "bool") {
      return encodeBool(value);
    }
    if (param.type.startsWith("uint") || param.type.startsWith("int")) {
      const signed = param.type.startsWith("int");
      return encodeNumber(value, { signed });
    }
    if (param.type.startsWith("bytes")) {
      return encodeBytes(value, { param });
    }
    if (param.type === "string") {
      return encodeString(value);
    }
    throw new InvalidAbiEncodingTypeError(param.type, {
      docsPath: "/docs/contract/encodeAbiParameters"
    });
  };
  encodeParams = function(preparedParams) {
    let staticSize = 0;
    for (let i = 0;i < preparedParams.length; i++) {
      const { dynamic, encoded } = preparedParams[i];
      if (dynamic)
        staticSize += 32;
      else
        staticSize += size(encoded);
    }
    const staticParams = [];
    const dynamicParams = [];
    let dynamicSize = 0;
    for (let i = 0;i < preparedParams.length; i++) {
      const { dynamic, encoded } = preparedParams[i];
      if (dynamic) {
        staticParams.push(numberToHex(staticSize + dynamicSize, { size: 32 }));
        dynamicParams.push(encoded);
        dynamicSize += size(encoded);
      } else {
        staticParams.push(encoded);
      }
    }
    return concat([...staticParams, ...dynamicParams]);
  };
  encodeAddress = function(value) {
    if (!isAddress2(value))
      throw new InvalidAddressError({ address: value });
    return { dynamic: false, encoded: padHex(value.toLowerCase()) };
  };
  encodeArray = function(value, { length, param }) {
    const dynamic = length === null;
    if (!Array.isArray(value))
      throw new InvalidArrayError(value);
    if (!dynamic && value.length !== length)
      throw new AbiEncodingArrayLengthMismatchError({
        expectedLength: length,
        givenLength: value.length,
        type: `${param.type}[${length}]`
      });
    let dynamicChild = false;
    const preparedParams = [];
    for (let i = 0;i < value.length; i++) {
      const preparedParam = prepareParam({ param, value: value[i] });
      if (preparedParam.dynamic)
        dynamicChild = true;
      preparedParams.push(preparedParam);
    }
    if (dynamic || dynamicChild) {
      const data3 = encodeParams(preparedParams);
      if (dynamic) {
        const length2 = numberToHex(preparedParams.length, { size: 32 });
        return {
          dynamic: true,
          encoded: preparedParams.length > 0 ? concat([length2, data3]) : length2
        };
      }
      if (dynamicChild)
        return { dynamic: true, encoded: data3 };
    }
    return {
      dynamic: false,
      encoded: concat(preparedParams.map(({ encoded }) => encoded))
    };
  };
  encodeBytes = function(value, { param }) {
    const [, paramSize] = param.type.split("bytes");
    const bytesSize = size(value);
    if (!paramSize) {
      let value_ = value;
      if (bytesSize % 32 !== 0)
        value_ = padHex(value_, {
          dir: "right",
          size: Math.ceil((value.length - 2) / 2 / 32) * 32
        });
      return {
        dynamic: true,
        encoded: concat([padHex(numberToHex(bytesSize, { size: 32 })), value_])
      };
    }
    if (bytesSize !== Number.parseInt(paramSize))
      throw new AbiEncodingBytesSizeMismatchError({
        expectedSize: Number.parseInt(paramSize),
        value
      });
    return { dynamic: false, encoded: padHex(value, { dir: "right" }) };
  };
  encodeBool = function(value) {
    if (typeof value !== "boolean")
      throw new BaseError(`Invalid boolean value: "${value}" (type: ${typeof value}). Expected: \`true\` or \`false\`.`);
    return { dynamic: false, encoded: padHex(boolToHex(value)) };
  };
  encodeNumber = function(value, { signed }) {
    return {
      dynamic: false,
      encoded: numberToHex(value, {
        size: 32,
        signed
      })
    };
  };
  encodeString = function(value) {
    const hexValue = stringToHex(value);
    const partsLength = Math.ceil(size(hexValue) / 32);
    const parts = [];
    for (let i = 0;i < partsLength; i++) {
      parts.push(padHex(slice(hexValue, i * 32, (i + 1) * 32), {
        dir: "right"
      }));
    }
    return {
      dynamic: true,
      encoded: concat([
        padHex(numberToHex(size(hexValue), { size: 32 })),
        ...parts
      ])
    };
  };
  encodeTuple = function(value, { param }) {
    let dynamic = false;
    const preparedParams = [];
    for (let i = 0;i < param.components.length; i++) {
      const param_ = param.components[i];
      const index = Array.isArray(value) ? i : param_.name;
      const preparedParam = prepareParam({
        param: param_,
        value: value[index]
      });
      preparedParams.push(preparedParam);
      if (preparedParam.dynamic)
        dynamic = true;
    }
    return {
      dynamic,
      encoded: dynamic ? encodeParams(preparedParams) : concat(preparedParams.map(({ encoded }) => encoded))
    };
  };
});

// node_modules/viem/_esm/utils/stringify.js
var stringify;
var init_stringify = __esm(() => {
  stringify = (value, replacer, space) => JSON.stringify(value, (key, value_) => {
    const value2 = typeof value_ === "bigint" ? value_.toString() : value_;
    return typeof replacer === "function" ? replacer(key, value2) : value2;
  }, space);
});

// node_modules/viem/_esm/accounts/utils/parseAccount.js
function parseAccount(account) {
  if (typeof account === "string")
    return { address: account, type: "json-rpc" };
  return account;
}
var init_parseAccount = __esm(() => {
});

// node_modules/abitype/dist/esm/version.js
var version3;
var init_version2 = __esm(() => {
  version3 = "1.0.6";
});

// node_modules/abitype/dist/esm/errors.js
class BaseError2 extends Error {
  constructor(shortMessage, args = {}) {
    const details = args.cause instanceof BaseError2 ? args.cause.details : args.cause?.message ? args.cause.message : args.details;
    const docsPath = args.cause instanceof BaseError2 ? args.cause.docsPath || args.docsPath : args.docsPath;
    const message = [
      shortMessage || "An error occurred.",
      "",
      ...args.metaMessages ? [...args.metaMessages, ""] : [],
      ...docsPath ? [`Docs: https://abitype.dev${docsPath}`] : [],
      ...details ? [`Details: ${details}`] : [],
      `Version: abitype@${version3}`
    ].join("\n");
    super(message);
    Object.defineProperty(this, "details", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "docsPath", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "metaMessages", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "shortMessage", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "AbiTypeError"
    });
    if (args.cause)
      this.cause = args.cause;
    this.details = details;
    this.docsPath = docsPath;
    this.metaMessages = args.metaMessages;
    this.shortMessage = shortMessage;
  }
}
var init_errors = __esm(() => {
  init_version2();
});

// node_modules/abitype/dist/esm/regex.js
function execTyped(regex2, string) {
  const match = regex2.exec(string);
  return match?.groups;
}
var bytesRegex2, integerRegex2, isTupleRegex;
var init_regex = __esm(() => {
  bytesRegex2 = /^bytes([1-9]|1[0-9]|2[0-9]|3[0-2])?$/;
  integerRegex2 = /^u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/;
  isTupleRegex = /^\(.+?\).*?$/;
});

// node_modules/abitype/dist/esm/human-readable/formatAbiParameter.js
function formatAbiParameter(abiParameter) {
  let type = abiParameter.type;
  if (tupleRegex.test(abiParameter.type) && ("components" in abiParameter)) {
    type = "(";
    const length = abiParameter.components.length;
    for (let i = 0;i < length; i++) {
      const component = abiParameter.components[i];
      type += formatAbiParameter(component);
      if (i < length - 1)
        type += ", ";
    }
    const result = execTyped(tupleRegex, abiParameter.type);
    type += `)${result?.array ?? ""}`;
    return formatAbiParameter({
      ...abiParameter,
      type
    });
  }
  if (("indexed" in abiParameter) && abiParameter.indexed)
    type = `${type} indexed`;
  if (abiParameter.name)
    return `${type} ${abiParameter.name}`;
  return type;
}
var tupleRegex;
var init_formatAbiParameter = __esm(() => {
  init_regex();
  tupleRegex = /^tuple(?<array>(\[(\d*)\])*)$/;
});

// node_modules/abitype/dist/esm/human-readable/formatAbiParameters.js
function formatAbiParameters(abiParameters) {
  let params = "";
  const length = abiParameters.length;
  for (let i = 0;i < length; i++) {
    const abiParameter = abiParameters[i];
    params += formatAbiParameter(abiParameter);
    if (i !== length - 1)
      params += ", ";
  }
  return params;
}
var init_formatAbiParameters = __esm(() => {
  init_formatAbiParameter();
});

// node_modules/abitype/dist/esm/human-readable/formatAbiItem.js
function formatAbiItem3(abiItem) {
  if (abiItem.type === "function")
    return `function ${abiItem.name}(${formatAbiParameters(abiItem.inputs)})${abiItem.stateMutability && abiItem.stateMutability !== "nonpayable" ? ` ${abiItem.stateMutability}` : ""}${abiItem.outputs.length ? ` returns (${formatAbiParameters(abiItem.outputs)})` : ""}`;
  if (abiItem.type === "event")
    return `event ${abiItem.name}(${formatAbiParameters(abiItem.inputs)})`;
  if (abiItem.type === "error")
    return `error ${abiItem.name}(${formatAbiParameters(abiItem.inputs)})`;
  if (abiItem.type === "constructor")
    return `constructor(${formatAbiParameters(abiItem.inputs)})${abiItem.stateMutability === "payable" ? " payable" : ""}`;
  if (abiItem.type === "fallback")
    return "fallback()";
  return "receive() external payable";
}
var init_formatAbiItem2 = __esm(() => {
  init_formatAbiParameters();
});

// node_modules/abitype/dist/esm/human-readable/runtime/signatures.js
function isErrorSignature(signature) {
  return errorSignatureRegex.test(signature);
}
function execErrorSignature(signature) {
  return execTyped(errorSignatureRegex, signature);
}
function isEventSignature(signature) {
  return eventSignatureRegex.test(signature);
}
function execEventSignature(signature) {
  return execTyped(eventSignatureRegex, signature);
}
function isFunctionSignature(signature) {
  return functionSignatureRegex.test(signature);
}
function execFunctionSignature(signature) {
  return execTyped(functionSignatureRegex, signature);
}
function isStructSignature(signature) {
  return structSignatureRegex.test(signature);
}
function execStructSignature(signature) {
  return execTyped(structSignatureRegex, signature);
}
function isConstructorSignature(signature) {
  return constructorSignatureRegex.test(signature);
}
function execConstructorSignature(signature) {
  return execTyped(constructorSignatureRegex, signature);
}
function isFallbackSignature(signature) {
  return fallbackSignatureRegex.test(signature);
}
function isReceiveSignature(signature) {
  return receiveSignatureRegex.test(signature);
}
var errorSignatureRegex, eventSignatureRegex, functionSignatureRegex, structSignatureRegex, constructorSignatureRegex, fallbackSignatureRegex, receiveSignatureRegex, modifiers, eventModifiers, functionModifiers;
var init_signatures = __esm(() => {
  init_regex();
  errorSignatureRegex = /^error (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*)\((?<parameters>.*?)\)$/;
  eventSignatureRegex = /^event (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*)\((?<parameters>.*?)\)$/;
  functionSignatureRegex = /^function (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*)\((?<parameters>.*?)\)(?: (?<scope>external|public{1}))?(?: (?<stateMutability>pure|view|nonpayable|payable{1}))?(?: returns\s?\((?<returns>.*?)\))?$/;
  structSignatureRegex = /^struct (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*) \{(?<properties>.*?)\}$/;
  constructorSignatureRegex = /^constructor\((?<parameters>.*?)\)(?:\s(?<stateMutability>payable{1}))?$/;
  fallbackSignatureRegex = /^fallback\(\) external(?:\s(?<stateMutability>payable{1}))?$/;
  receiveSignatureRegex = /^receive\(\) external payable$/;
  modifiers = new Set([
    "memory",
    "indexed",
    "storage",
    "calldata"
  ]);
  eventModifiers = new Set(["indexed"]);
  functionModifiers = new Set([
    "calldata",
    "memory",
    "storage"
  ]);
});

// node_modules/abitype/dist/esm/human-readable/errors/abiItem.js
class UnknownTypeError extends BaseError2 {
  constructor({ type }) {
    super("Unknown type.", {
      metaMessages: [
        `Type "${type}" is not a valid ABI type. Perhaps you forgot to include a struct signature?`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "UnknownTypeError"
    });
  }
}

class UnknownSolidityTypeError extends BaseError2 {
  constructor({ type }) {
    super("Unknown type.", {
      metaMessages: [`Type "${type}" is not a valid ABI type.`]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "UnknownSolidityTypeError"
    });
  }
}
var init_abiItem = __esm(() => {
  init_errors();
});

// node_modules/abitype/dist/esm/human-readable/errors/abiParameter.js
class InvalidAbiParametersError extends BaseError2 {
  constructor({ params }) {
    super("Failed to parse ABI parameters.", {
      details: `parseAbiParameters(${JSON.stringify(params, null, 2)})`,
      docsPath: "/api/human#parseabiparameters-1"
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidAbiParametersError"
    });
  }
}

class InvalidParameterError extends BaseError2 {
  constructor({ param }) {
    super("Invalid ABI parameter.", {
      details: param
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidParameterError"
    });
  }
}

class SolidityProtectedKeywordError extends BaseError2 {
  constructor({ param, name }) {
    super("Invalid ABI parameter.", {
      details: param,
      metaMessages: [
        `"${name}" is a protected Solidity keyword. More info: https://docs.soliditylang.org/en/latest/cheatsheet.html`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "SolidityProtectedKeywordError"
    });
  }
}

class InvalidModifierError extends BaseError2 {
  constructor({ param, type, modifier }) {
    super("Invalid ABI parameter.", {
      details: param,
      metaMessages: [
        `Modifier "${modifier}" not allowed${type ? ` in "${type}" type` : ""}.`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidModifierError"
    });
  }
}

class InvalidFunctionModifierError extends BaseError2 {
  constructor({ param, type, modifier }) {
    super("Invalid ABI parameter.", {
      details: param,
      metaMessages: [
        `Modifier "${modifier}" not allowed${type ? ` in "${type}" type` : ""}.`,
        `Data location can only be specified for array, struct, or mapping types, but "${modifier}" was given.`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidFunctionModifierError"
    });
  }
}

class InvalidAbiTypeParameterError extends BaseError2 {
  constructor({ abiParameter }) {
    super("Invalid ABI parameter.", {
      details: JSON.stringify(abiParameter, null, 2),
      metaMessages: ["ABI parameter type is invalid."]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidAbiTypeParameterError"
    });
  }
}
var init_abiParameter = __esm(() => {
  init_errors();
});

// node_modules/abitype/dist/esm/human-readable/errors/signature.js
class InvalidSignatureError extends BaseError2 {
  constructor({ signature, type }) {
    super(`Invalid ${type} signature.`, {
      details: signature
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidSignatureError"
    });
  }
}

class UnknownSignatureError extends BaseError2 {
  constructor({ signature }) {
    super("Unknown signature.", {
      details: signature
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "UnknownSignatureError"
    });
  }
}

class InvalidStructSignatureError extends BaseError2 {
  constructor({ signature }) {
    super("Invalid struct signature.", {
      details: signature,
      metaMessages: ["No properties exist."]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidStructSignatureError"
    });
  }
}
var init_signature = __esm(() => {
  init_errors();
});

// node_modules/abitype/dist/esm/human-readable/errors/struct.js
class CircularReferenceError extends BaseError2 {
  constructor({ type }) {
    super("Circular reference detected.", {
      metaMessages: [`Struct "${type}" is a circular reference.`]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "CircularReferenceError"
    });
  }
}
var init_struct = __esm(() => {
  init_errors();
});

// node_modules/abitype/dist/esm/human-readable/errors/splitParameters.js
class InvalidParenthesisError extends BaseError2 {
  constructor({ current, depth }) {
    super("Unbalanced parentheses.", {
      metaMessages: [
        `"${current.trim()}" has too many ${depth > 0 ? "opening" : "closing"} parentheses.`
      ],
      details: `Depth "${depth}"`
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidParenthesisError"
    });
  }
}
var init_splitParameters = __esm(() => {
  init_errors();
});

// node_modules/abitype/dist/esm/human-readable/runtime/cache.js
function getParameterCacheKey(param, type) {
  if (type)
    return `${type}:${param}`;
  return param;
}
var parameterCache;
var init_cache = __esm(() => {
  parameterCache = new Map([
    ["address", { type: "address" }],
    ["bool", { type: "bool" }],
    ["bytes", { type: "bytes" }],
    ["bytes32", { type: "bytes32" }],
    ["int", { type: "int256" }],
    ["int256", { type: "int256" }],
    ["string", { type: "string" }],
    ["uint", { type: "uint256" }],
    ["uint8", { type: "uint8" }],
    ["uint16", { type: "uint16" }],
    ["uint24", { type: "uint24" }],
    ["uint32", { type: "uint32" }],
    ["uint64", { type: "uint64" }],
    ["uint96", { type: "uint96" }],
    ["uint112", { type: "uint112" }],
    ["uint160", { type: "uint160" }],
    ["uint192", { type: "uint192" }],
    ["uint256", { type: "uint256" }],
    ["address owner", { type: "address", name: "owner" }],
    ["address to", { type: "address", name: "to" }],
    ["bool approved", { type: "bool", name: "approved" }],
    ["bytes _data", { type: "bytes", name: "_data" }],
    ["bytes data", { type: "bytes", name: "data" }],
    ["bytes signature", { type: "bytes", name: "signature" }],
    ["bytes32 hash", { type: "bytes32", name: "hash" }],
    ["bytes32 r", { type: "bytes32", name: "r" }],
    ["bytes32 root", { type: "bytes32", name: "root" }],
    ["bytes32 s", { type: "bytes32", name: "s" }],
    ["string name", { type: "string", name: "name" }],
    ["string symbol", { type: "string", name: "symbol" }],
    ["string tokenURI", { type: "string", name: "tokenURI" }],
    ["uint tokenId", { type: "uint256", name: "tokenId" }],
    ["uint8 v", { type: "uint8", name: "v" }],
    ["uint256 balance", { type: "uint256", name: "balance" }],
    ["uint256 tokenId", { type: "uint256", name: "tokenId" }],
    ["uint256 value", { type: "uint256", name: "value" }],
    [
      "event:address indexed from",
      { type: "address", name: "from", indexed: true }
    ],
    ["event:address indexed to", { type: "address", name: "to", indexed: true }],
    [
      "event:uint indexed tokenId",
      { type: "uint256", name: "tokenId", indexed: true }
    ],
    [
      "event:uint256 indexed tokenId",
      { type: "uint256", name: "tokenId", indexed: true }
    ]
  ]);
});

// node_modules/abitype/dist/esm/human-readable/runtime/utils.js
function parseSignature(signature2, structs = {}) {
  if (isFunctionSignature(signature2)) {
    const match = execFunctionSignature(signature2);
    if (!match)
      throw new InvalidSignatureError({ signature: signature2, type: "function" });
    const inputParams = splitParameters2(match.parameters);
    const inputs = [];
    const inputLength = inputParams.length;
    for (let i = 0;i < inputLength; i++) {
      inputs.push(parseAbiParameter(inputParams[i], {
        modifiers: functionModifiers,
        structs,
        type: "function"
      }));
    }
    const outputs = [];
    if (match.returns) {
      const outputParams = splitParameters2(match.returns);
      const outputLength = outputParams.length;
      for (let i = 0;i < outputLength; i++) {
        outputs.push(parseAbiParameter(outputParams[i], {
          modifiers: functionModifiers,
          structs,
          type: "function"
        }));
      }
    }
    return {
      name: match.name,
      type: "function",
      stateMutability: match.stateMutability ?? "nonpayable",
      inputs,
      outputs
    };
  }
  if (isEventSignature(signature2)) {
    const match = execEventSignature(signature2);
    if (!match)
      throw new InvalidSignatureError({ signature: signature2, type: "event" });
    const params = splitParameters2(match.parameters);
    const abiParameters = [];
    const length = params.length;
    for (let i = 0;i < length; i++) {
      abiParameters.push(parseAbiParameter(params[i], {
        modifiers: eventModifiers,
        structs,
        type: "event"
      }));
    }
    return { name: match.name, type: "event", inputs: abiParameters };
  }
  if (isErrorSignature(signature2)) {
    const match = execErrorSignature(signature2);
    if (!match)
      throw new InvalidSignatureError({ signature: signature2, type: "error" });
    const params = splitParameters2(match.parameters);
    const abiParameters = [];
    const length = params.length;
    for (let i = 0;i < length; i++) {
      abiParameters.push(parseAbiParameter(params[i], { structs, type: "error" }));
    }
    return { name: match.name, type: "error", inputs: abiParameters };
  }
  if (isConstructorSignature(signature2)) {
    const match = execConstructorSignature(signature2);
    if (!match)
      throw new InvalidSignatureError({ signature: signature2, type: "constructor" });
    const params = splitParameters2(match.parameters);
    const abiParameters = [];
    const length = params.length;
    for (let i = 0;i < length; i++) {
      abiParameters.push(parseAbiParameter(params[i], { structs, type: "constructor" }));
    }
    return {
      type: "constructor",
      stateMutability: match.stateMutability ?? "nonpayable",
      inputs: abiParameters
    };
  }
  if (isFallbackSignature(signature2))
    return { type: "fallback" };
  if (isReceiveSignature(signature2))
    return {
      type: "receive",
      stateMutability: "payable"
    };
  throw new UnknownSignatureError({ signature: signature2 });
}
function parseAbiParameter(param, options) {
  const parameterCacheKey = getParameterCacheKey(param, options?.type);
  if (parameterCache.has(parameterCacheKey))
    return parameterCache.get(parameterCacheKey);
  const isTuple = isTupleRegex.test(param);
  const match = execTyped(isTuple ? abiParameterWithTupleRegex : abiParameterWithoutTupleRegex, param);
  if (!match)
    throw new InvalidParameterError({ param });
  if (match.name && isSolidityKeyword(match.name))
    throw new SolidityProtectedKeywordError({ param, name: match.name });
  const name = match.name ? { name: match.name } : {};
  const indexed = match.modifier === "indexed" ? { indexed: true } : {};
  const structs = options?.structs ?? {};
  let type;
  let components = {};
  if (isTuple) {
    type = "tuple";
    const params = splitParameters2(match.type);
    const components_ = [];
    const length = params.length;
    for (let i = 0;i < length; i++) {
      components_.push(parseAbiParameter(params[i], { structs }));
    }
    components = { components: components_ };
  } else if (match.type in structs) {
    type = "tuple";
    components = { components: structs[match.type] };
  } else if (dynamicIntegerRegex.test(match.type)) {
    type = `${match.type}256`;
  } else {
    type = match.type;
    if (!(options?.type === "struct") && !isSolidityType(type))
      throw new UnknownSolidityTypeError({ type });
  }
  if (match.modifier) {
    if (!options?.modifiers?.has?.(match.modifier))
      throw new InvalidModifierError({
        param,
        type: options?.type,
        modifier: match.modifier
      });
    if (functionModifiers.has(match.modifier) && !isValidDataLocation(type, !!match.array))
      throw new InvalidFunctionModifierError({
        param,
        type: options?.type,
        modifier: match.modifier
      });
  }
  const abiParameter2 = {
    type: `${type}${match.array ?? ""}`,
    ...name,
    ...indexed,
    ...components
  };
  parameterCache.set(parameterCacheKey, abiParameter2);
  return abiParameter2;
}
function splitParameters2(params, result = [], current = "", depth = 0) {
  const length = params.trim().length;
  for (let i = 0;i < length; i++) {
    const char = params[i];
    const tail = params.slice(i + 1);
    switch (char) {
      case ",":
        return depth === 0 ? splitParameters2(tail, [...result, current.trim()]) : splitParameters2(tail, result, `${current}${char}`, depth);
      case "(":
        return splitParameters2(tail, result, `${current}${char}`, depth + 1);
      case ")":
        return splitParameters2(tail, result, `${current}${char}`, depth - 1);
      default:
        return splitParameters2(tail, result, `${current}${char}`, depth);
    }
  }
  if (current === "")
    return result;
  if (depth !== 0)
    throw new InvalidParenthesisError({ current, depth });
  result.push(current.trim());
  return result;
}
function isSolidityType(type) {
  return type === "address" || type === "bool" || type === "function" || type === "string" || bytesRegex2.test(type) || integerRegex2.test(type);
}
function isSolidityKeyword(name) {
  return name === "address" || name === "bool" || name === "function" || name === "string" || name === "tuple" || bytesRegex2.test(name) || integerRegex2.test(name) || protectedKeywordsRegex.test(name);
}
function isValidDataLocation(type, isArray) {
  return isArray || type === "bytes" || type === "string" || type === "tuple";
}
var abiParameterWithoutTupleRegex, abiParameterWithTupleRegex, dynamicIntegerRegex, protectedKeywordsRegex;
var init_utils3 = __esm(() => {
  init_regex();
  init_abiItem();
  init_abiParameter();
  init_signature();
  init_splitParameters();
  init_cache();
  init_signatures();
  abiParameterWithoutTupleRegex = /^(?<type>[a-zA-Z$_][a-zA-Z0-9$_]*)(?<array>(?:\[\d*?\])+?)?(?:\s(?<modifier>calldata|indexed|memory|storage{1}))?(?:\s(?<name>[a-zA-Z$_][a-zA-Z0-9$_]*))?$/;
  abiParameterWithTupleRegex = /^\((?<type>.+?)\)(?<array>(?:\[\d*?\])+?)?(?:\s(?<modifier>calldata|indexed|memory|storage{1}))?(?:\s(?<name>[a-zA-Z$_][a-zA-Z0-9$_]*))?$/;
  dynamicIntegerRegex = /^u?int$/;
  protectedKeywordsRegex = /^(?:after|alias|anonymous|apply|auto|byte|calldata|case|catch|constant|copyof|default|defined|error|event|external|false|final|function|immutable|implements|in|indexed|inline|internal|let|mapping|match|memory|mutable|null|of|override|partial|private|promise|public|pure|reference|relocatable|return|returns|sizeof|static|storage|struct|super|supports|switch|this|true|try|typedef|typeof|var|view|virtual)$/;
});

// node_modules/abitype/dist/esm/human-readable/runtime/structs.js
function parseStructs(signatures3) {
  const shallowStructs = {};
  const signaturesLength = signatures3.length;
  for (let i = 0;i < signaturesLength; i++) {
    const signature3 = signatures3[i];
    if (!isStructSignature(signature3))
      continue;
    const match = execStructSignature(signature3);
    if (!match)
      throw new InvalidSignatureError({ signature: signature3, type: "struct" });
    const properties = match.properties.split(";");
    const components = [];
    const propertiesLength = properties.length;
    for (let k = 0;k < propertiesLength; k++) {
      const property = properties[k];
      const trimmed = property.trim();
      if (!trimmed)
        continue;
      const abiParameter3 = parseAbiParameter(trimmed, {
        type: "struct"
      });
      components.push(abiParameter3);
    }
    if (!components.length)
      throw new InvalidStructSignatureError({ signature: signature3 });
    shallowStructs[match.name] = components;
  }
  const resolvedStructs = {};
  const entries = Object.entries(shallowStructs);
  const entriesLength = entries.length;
  for (let i = 0;i < entriesLength; i++) {
    const [name, parameters] = entries[i];
    resolvedStructs[name] = resolveStructs(parameters, shallowStructs);
  }
  return resolvedStructs;
}
var resolveStructs, typeWithoutTupleRegex;
var init_structs = __esm(() => {
  init_regex();
  init_abiItem();
  init_abiParameter();
  init_signature();
  init_struct();
  init_signatures();
  init_utils3();
  resolveStructs = function(abiParameters, structs, ancestors = new Set) {
    const components = [];
    const length = abiParameters.length;
    for (let i = 0;i < length; i++) {
      const abiParameter3 = abiParameters[i];
      const isTuple = isTupleRegex.test(abiParameter3.type);
      if (isTuple)
        components.push(abiParameter3);
      else {
        const match = execTyped(typeWithoutTupleRegex, abiParameter3.type);
        if (!match?.type)
          throw new InvalidAbiTypeParameterError({ abiParameter: abiParameter3 });
        const { array, type } = match;
        if (type in structs) {
          if (ancestors.has(type))
            throw new CircularReferenceError({ type });
          components.push({
            ...abiParameter3,
            type: `tuple${array ?? ""}`,
            components: resolveStructs(structs[type] ?? [], structs, new Set([...ancestors, type]))
          });
        } else {
          if (isSolidityType(type))
            components.push(abiParameter3);
          else
            throw new UnknownTypeError({ type });
        }
      }
    }
    return components;
  };
  typeWithoutTupleRegex = /^(?<type>[a-zA-Z$_][a-zA-Z0-9$_]*)(?<array>(?:\[\d*?\])+?)?$/;
});

// node_modules/abitype/dist/esm/human-readable/parseAbi.js
function parseAbi(signatures4) {
  const structs2 = parseStructs(signatures4);
  const abi4 = [];
  const length = signatures4.length;
  for (let i = 0;i < length; i++) {
    const signature3 = signatures4[i];
    if (isStructSignature(signature3))
      continue;
    abi4.push(parseSignature(signature3, structs2));
  }
  return abi4;
}
var init_parseAbi = __esm(() => {
  init_signatures();
  init_structs();
  init_utils3();
});

// node_modules/abitype/dist/esm/human-readable/parseAbiParameters.js
function parseAbiParameters(params) {
  const abiParameters = [];
  if (typeof params === "string") {
    const parameters = splitParameters2(params);
    const length = parameters.length;
    for (let i = 0;i < length; i++) {
      abiParameters.push(parseAbiParameter(parameters[i], { modifiers }));
    }
  } else {
    const structs3 = parseStructs(params);
    const length = params.length;
    for (let i = 0;i < length; i++) {
      const signature3 = params[i];
      if (isStructSignature(signature3))
        continue;
      const parameters = splitParameters2(signature3);
      const length2 = parameters.length;
      for (let k = 0;k < length2; k++) {
        abiParameters.push(parseAbiParameter(parameters[k], { modifiers, structs: structs3 }));
      }
    }
  }
  if (abiParameters.length === 0)
    throw new InvalidAbiParametersError({ params });
  return abiParameters;
}
var init_parseAbiParameters = __esm(() => {
  init_abiParameter();
  init_signatures();
  init_structs();
  init_utils3();
  init_utils3();
});

// node_modules/abitype/dist/esm/exports/index.js
var init_exports = __esm(() => {
  init_formatAbiItem2();
  init_parseAbi();
  init_parseAbiParameters();
});

// node_modules/viem/_esm/utils/hash/hashSignature.js
function hashSignature(sig) {
  return hash2(sig);
}
var hash2;
var init_hashSignature = __esm(() => {
  init_toBytes();
  init_keccak256();
  hash2 = (value) => keccak256(toBytes2(value));
});

// node_modules/viem/_esm/utils/hash/normalizeSignature.js
function normalizeSignature(signature3) {
  let active = true;
  let current = "";
  let level = 0;
  let result = "";
  let valid = false;
  for (let i = 0;i < signature3.length; i++) {
    const char = signature3[i];
    if (["(", ")", ","].includes(char))
      active = true;
    if (char === "(")
      level++;
    if (char === ")")
      level--;
    if (!active)
      continue;
    if (level === 0) {
      if (char === " " && ["event", "function", ""].includes(result))
        result = "";
      else {
        result += char;
        if (char === ")") {
          valid = true;
          break;
        }
      }
      continue;
    }
    if (char === " ") {
      if (signature3[i - 1] !== "," && current !== "," && current !== ",(") {
        current = "";
        active = false;
      }
      continue;
    }
    result += char;
    current += char;
  }
  if (!valid)
    throw new BaseError("Unable to normalize signature.");
  return result;
}
var init_normalizeSignature = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/utils/hash/toSignature.js
var toSignature;
var init_toSignature = __esm(() => {
  init_exports();
  init_normalizeSignature();
  toSignature = (def) => {
    const def_ = (() => {
      if (typeof def === "string")
        return def;
      return formatAbiItem3(def);
    })();
    return normalizeSignature(def_);
  };
});

// node_modules/viem/_esm/utils/hash/toSignatureHash.js
function toSignatureHash(fn) {
  return hashSignature(toSignature(fn));
}
var init_toSignatureHash = __esm(() => {
  init_hashSignature();
  init_toSignature();
});

// node_modules/viem/_esm/utils/hash/toEventSelector.js
var toEventSelector;
var init_toEventSelector = __esm(() => {
  init_toSignatureHash();
  toEventSelector = toSignatureHash;
});

// node_modules/viem/_esm/utils/hash/toFunctionSelector.js
var toFunctionSelector;
var init_toFunctionSelector = __esm(() => {
  init_slice();
  init_toSignatureHash();
  toFunctionSelector = (fn) => slice(toSignatureHash(fn), 0, 4);
});

// node_modules/viem/_esm/utils/abi/getAbiItem.js
function getAbiItem(parameters) {
  const { abi: abi5, args = [], name } = parameters;
  const isSelector = isHex(name, { strict: false });
  const abiItems = abi5.filter((abiItem3) => {
    if (isSelector) {
      if (abiItem3.type === "function")
        return toFunctionSelector(abiItem3) === name;
      if (abiItem3.type === "event")
        return toEventSelector(abiItem3) === name;
      return false;
    }
    return ("name" in abiItem3) && abiItem3.name === name;
  });
  if (abiItems.length === 0)
    return;
  if (abiItems.length === 1)
    return abiItems[0];
  let matchedAbiItem = undefined;
  for (const abiItem3 of abiItems) {
    if (!("inputs" in abiItem3))
      continue;
    if (!args || args.length === 0) {
      if (!abiItem3.inputs || abiItem3.inputs.length === 0)
        return abiItem3;
      continue;
    }
    if (!abiItem3.inputs)
      continue;
    if (abiItem3.inputs.length === 0)
      continue;
    if (abiItem3.inputs.length !== args.length)
      continue;
    const matched = args.every((arg, index) => {
      const abiParameter4 = ("inputs" in abiItem3) && abiItem3.inputs[index];
      if (!abiParameter4)
        return false;
      return isArgOfType(arg, abiParameter4);
    });
    if (matched) {
      if (matchedAbiItem && ("inputs" in matchedAbiItem) && matchedAbiItem.inputs) {
        const ambiguousTypes = getAmbiguousTypes(abiItem3.inputs, matchedAbiItem.inputs, args);
        if (ambiguousTypes)
          throw new AbiItemAmbiguityError({
            abiItem: abiItem3,
            type: ambiguousTypes[0]
          }, {
            abiItem: matchedAbiItem,
            type: ambiguousTypes[1]
          });
      }
      matchedAbiItem = abiItem3;
    }
  }
  if (matchedAbiItem)
    return matchedAbiItem;
  return abiItems[0];
}
function isArgOfType(arg, abiParameter4) {
  const argType = typeof arg;
  const abiParameterType = abiParameter4.type;
  switch (abiParameterType) {
    case "address":
      return isAddress2(arg, { strict: false });
    case "bool":
      return argType === "boolean";
    case "function":
      return argType === "string";
    case "string":
      return argType === "string";
    default: {
      if (abiParameterType === "tuple" && ("components" in abiParameter4))
        return Object.values(abiParameter4.components).every((component, index) => {
          return isArgOfType(Object.values(arg)[index], component);
        });
      if (/^u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/.test(abiParameterType))
        return argType === "number" || argType === "bigint";
      if (/^bytes([1-9]|1[0-9]|2[0-9]|3[0-2])?$/.test(abiParameterType))
        return argType === "string" || arg instanceof Uint8Array;
      if (/[a-z]+[1-9]{0,3}(\[[0-9]{0,}\])+$/.test(abiParameterType)) {
        return Array.isArray(arg) && arg.every((x) => isArgOfType(x, {
          ...abiParameter4,
          type: abiParameterType.replace(/(\[[0-9]{0,}\])$/, "")
        }));
      }
      return false;
    }
  }
}
function getAmbiguousTypes(sourceParameters, targetParameters, args) {
  for (const parameterIndex in sourceParameters) {
    const sourceParameter = sourceParameters[parameterIndex];
    const targetParameter = targetParameters[parameterIndex];
    if (sourceParameter.type === "tuple" && targetParameter.type === "tuple" && ("components" in sourceParameter) && ("components" in targetParameter))
      return getAmbiguousTypes(sourceParameter.components, targetParameter.components, args[parameterIndex]);
    const types = [sourceParameter.type, targetParameter.type];
    const ambiguous = (() => {
      if (types.includes("address") && types.includes("bytes20"))
        return true;
      if (types.includes("address") && types.includes("string"))
        return isAddress2(args[parameterIndex], { strict: false });
      if (types.includes("address") && types.includes("bytes"))
        return isAddress2(args[parameterIndex], { strict: false });
      return false;
    })();
    if (ambiguous)
      return types;
  }
  return;
}
var init_getAbiItem = __esm(() => {
  init_abi();
  init_isHex();
  init_isAddress();
  init_toEventSelector();
  init_toFunctionSelector();
});

// node_modules/viem/_esm/utils/abi/prepareEncodeFunctionData.js
function prepareEncodeFunctionData(parameters) {
  const { abi: abi7, args, functionName } = parameters;
  let abiItem3 = abi7[0];
  if (functionName) {
    const item = getAbiItem({
      abi: abi7,
      args,
      name: functionName
    });
    if (!item)
      throw new AbiFunctionNotFoundError(functionName, { docsPath: docsPath2 });
    abiItem3 = item;
  }
  if (abiItem3.type !== "function")
    throw new AbiFunctionNotFoundError(undefined, { docsPath: docsPath2 });
  return {
    abi: [abiItem3],
    functionName: toFunctionSelector(formatAbiItem(abiItem3))
  };
}
var docsPath2;
var init_prepareEncodeFunctionData = __esm(() => {
  init_abi();
  init_toFunctionSelector();
  init_formatAbiItem();
  init_getAbiItem();
  docsPath2 = "/docs/contract/encodeFunctionData";
});

// node_modules/viem/_esm/utils/abi/encodeFunctionData.js
function encodeFunctionData(parameters) {
  const { args } = parameters;
  const { abi: abi7, functionName } = (() => {
    if (parameters.abi.length === 1 && parameters.functionName?.startsWith("0x"))
      return parameters;
    return prepareEncodeFunctionData(parameters);
  })();
  const abiItem3 = abi7[0];
  const signature3 = functionName;
  const data3 = ("inputs" in abiItem3) && abiItem3.inputs ? encodeAbiParameters(abiItem3.inputs, args ?? []) : undefined;
  return concatHex([signature3, data3 ?? "0x"]);
}
var init_encodeFunctionData = __esm(() => {
  init_concat();
  init_encodeAbiParameters();
  init_prepareEncodeFunctionData();
});

// node_modules/viem/_esm/constants/solidity.js
var panicReasons, solidityError, solidityPanic;
var init_solidity = __esm(() => {
  panicReasons = {
    1: "An `assert` condition failed.",
    17: "Arithmetic operation resulted in underflow or overflow.",
    18: "Division or modulo by zero (e.g. `5 / 0` or `23 % 0`).",
    33: "Attempted to convert to an invalid type.",
    34: "Attempted to access a storage byte array that is incorrectly encoded.",
    49: "Performed `.pop()` on an empty array",
    50: "Array index is out of bounds.",
    65: "Allocated too much memory or created an array which is too large.",
    81: "Attempted to call a zero-initialized variable of internal function type."
  };
  solidityError = {
    inputs: [
      {
        name: "message",
        type: "string"
      }
    ],
    name: "Error",
    type: "error"
  };
  solidityPanic = {
    inputs: [
      {
        name: "reason",
        type: "uint256"
      }
    ],
    name: "Panic",
    type: "error"
  };
});

// node_modules/viem/_esm/utils/encoding/fromBytes.js
function bytesToBigInt(bytes2, opts = {}) {
  if (typeof opts.size !== "undefined")
    assertSize(bytes2, { size: opts.size });
  const hex = bytesToHex2(bytes2, opts);
  return hexToBigInt(hex, opts);
}
function bytesToBool(bytes_, opts = {}) {
  let bytes2 = bytes_;
  if (typeof opts.size !== "undefined") {
    assertSize(bytes2, { size: opts.size });
    bytes2 = trim(bytes2);
  }
  if (bytes2.length > 1 || bytes2[0] > 1)
    throw new InvalidBytesBooleanError(bytes2);
  return Boolean(bytes2[0]);
}
function bytesToNumber(bytes2, opts = {}) {
  if (typeof opts.size !== "undefined")
    assertSize(bytes2, { size: opts.size });
  const hex = bytesToHex2(bytes2, opts);
  return hexToNumber2(hex, opts);
}
function bytesToString(bytes_, opts = {}) {
  let bytes2 = bytes_;
  if (typeof opts.size !== "undefined") {
    assertSize(bytes2, { size: opts.size });
    bytes2 = trim(bytes2, { dir: "right" });
  }
  return new TextDecoder().decode(bytes2);
}
var init_fromBytes = __esm(() => {
  init_encoding();
  init_trim();
  init_fromHex();
  init_toHex();
});

// node_modules/viem/_esm/utils/abi/decodeAbiParameters.js
function decodeAbiParameters(params, data3) {
  const bytes2 = typeof data3 === "string" ? hexToBytes2(data3) : data3;
  const cursor5 = createCursor(bytes2);
  if (size(bytes2) === 0 && params.length > 0)
    throw new AbiDecodingZeroDataError;
  if (size(data3) && size(data3) < 32)
    throw new AbiDecodingDataSizeTooSmallError({
      data: typeof data3 === "string" ? data3 : bytesToHex2(data3),
      params,
      size: size(data3)
    });
  let consumed = 0;
  const values = [];
  for (let i = 0;i < params.length; ++i) {
    const param = params[i];
    cursor5.setPosition(consumed);
    const [data4, consumed_] = decodeParameter(cursor5, param, {
      staticPosition: 0
    });
    consumed += consumed_;
    values.push(data4);
  }
  return values;
}
var decodeParameter, decodeAddress, decodeArray, decodeBool, decodeBytes, decodeNumber, decodeTuple, decodeString, hasDynamicChild, sizeOfLength, sizeOfOffset;
var init_decodeAbiParameters = __esm(() => {
  init_abi();
  init_getAddress();
  init_cursor2();
  init_size();
  init_slice();
  init_trim();
  init_fromBytes();
  init_toBytes();
  init_toHex();
  init_encodeAbiParameters();
  decodeParameter = function(cursor5, param, { staticPosition }) {
    const arrayComponents = getArrayComponents(param.type);
    if (arrayComponents) {
      const [length, type] = arrayComponents;
      return decodeArray(cursor5, { ...param, type }, { length, staticPosition });
    }
    if (param.type === "tuple")
      return decodeTuple(cursor5, param, { staticPosition });
    if (param.type === "address")
      return decodeAddress(cursor5);
    if (param.type === "bool")
      return decodeBool(cursor5);
    if (param.type.startsWith("bytes"))
      return decodeBytes(cursor5, param, { staticPosition });
    if (param.type.startsWith("uint") || param.type.startsWith("int"))
      return decodeNumber(cursor5, param);
    if (param.type === "string")
      return decodeString(cursor5, { staticPosition });
    throw new InvalidAbiDecodingTypeError(param.type, {
      docsPath: "/docs/contract/decodeAbiParameters"
    });
  };
  decodeAddress = function(cursor5) {
    const value = cursor5.readBytes(32);
    return [checksumAddress(bytesToHex2(sliceBytes(value, -20))), 32];
  };
  decodeArray = function(cursor5, param, { length, staticPosition }) {
    if (!length) {
      const offset = bytesToNumber(cursor5.readBytes(sizeOfOffset));
      const start = staticPosition + offset;
      const startOfData = start + sizeOfLength;
      cursor5.setPosition(start);
      const length2 = bytesToNumber(cursor5.readBytes(sizeOfLength));
      const dynamicChild = hasDynamicChild(param);
      let consumed2 = 0;
      const value2 = [];
      for (let i = 0;i < length2; ++i) {
        cursor5.setPosition(startOfData + (dynamicChild ? i * 32 : consumed2));
        const [data3, consumed_] = decodeParameter(cursor5, param, {
          staticPosition: startOfData
        });
        consumed2 += consumed_;
        value2.push(data3);
      }
      cursor5.setPosition(staticPosition + 32);
      return [value2, 32];
    }
    if (hasDynamicChild(param)) {
      const offset = bytesToNumber(cursor5.readBytes(sizeOfOffset));
      const start = staticPosition + offset;
      const value2 = [];
      for (let i = 0;i < length; ++i) {
        cursor5.setPosition(start + i * 32);
        const [data3] = decodeParameter(cursor5, param, {
          staticPosition: start
        });
        value2.push(data3);
      }
      cursor5.setPosition(staticPosition + 32);
      return [value2, 32];
    }
    let consumed = 0;
    const value = [];
    for (let i = 0;i < length; ++i) {
      const [data3, consumed_] = decodeParameter(cursor5, param, {
        staticPosition: staticPosition + consumed
      });
      consumed += consumed_;
      value.push(data3);
    }
    return [value, consumed];
  };
  decodeBool = function(cursor5) {
    return [bytesToBool(cursor5.readBytes(32), { size: 32 }), 32];
  };
  decodeBytes = function(cursor5, param, { staticPosition }) {
    const [_, size11] = param.type.split("bytes");
    if (!size11) {
      const offset = bytesToNumber(cursor5.readBytes(32));
      cursor5.setPosition(staticPosition + offset);
      const length = bytesToNumber(cursor5.readBytes(32));
      if (length === 0) {
        cursor5.setPosition(staticPosition + 32);
        return ["0x", 32];
      }
      const data3 = cursor5.readBytes(length);
      cursor5.setPosition(staticPosition + 32);
      return [bytesToHex2(data3), 32];
    }
    const value = bytesToHex2(cursor5.readBytes(Number.parseInt(size11), 32));
    return [value, 32];
  };
  decodeNumber = function(cursor5, param) {
    const signed = param.type.startsWith("int");
    const size11 = Number.parseInt(param.type.split("int")[1] || "256");
    const value = cursor5.readBytes(32);
    return [
      size11 > 48 ? bytesToBigInt(value, { signed }) : bytesToNumber(value, { signed }),
      32
    ];
  };
  decodeTuple = function(cursor5, param, { staticPosition }) {
    const hasUnnamedChild = param.components.length === 0 || param.components.some(({ name }) => !name);
    const value = hasUnnamedChild ? [] : {};
    let consumed = 0;
    if (hasDynamicChild(param)) {
      const offset = bytesToNumber(cursor5.readBytes(sizeOfOffset));
      const start = staticPosition + offset;
      for (let i = 0;i < param.components.length; ++i) {
        const component = param.components[i];
        cursor5.setPosition(start + consumed);
        const [data3, consumed_] = decodeParameter(cursor5, component, {
          staticPosition: start
        });
        consumed += consumed_;
        value[hasUnnamedChild ? i : component?.name] = data3;
      }
      cursor5.setPosition(staticPosition + 32);
      return [value, 32];
    }
    for (let i = 0;i < param.components.length; ++i) {
      const component = param.components[i];
      const [data3, consumed_] = decodeParameter(cursor5, component, {
        staticPosition
      });
      value[hasUnnamedChild ? i : component?.name] = data3;
      consumed += consumed_;
    }
    return [value, consumed];
  };
  decodeString = function(cursor5, { staticPosition }) {
    const offset = bytesToNumber(cursor5.readBytes(32));
    const start = staticPosition + offset;
    cursor5.setPosition(start);
    const length = bytesToNumber(cursor5.readBytes(32));
    if (length === 0) {
      cursor5.setPosition(staticPosition + 32);
      return ["", 32];
    }
    const data3 = cursor5.readBytes(length, 32);
    const value = bytesToString(trim(data3));
    cursor5.setPosition(staticPosition + 32);
    return [value, 32];
  };
  hasDynamicChild = function(param) {
    const { type } = param;
    if (type === "string")
      return true;
    if (type === "bytes")
      return true;
    if (type.endsWith("[]"))
      return true;
    if (type === "tuple")
      return param.components?.some(hasDynamicChild);
    const arrayComponents = getArrayComponents(param.type);
    if (arrayComponents && hasDynamicChild({ ...param, type: arrayComponents[1] }))
      return true;
    return false;
  };
  sizeOfLength = 32;
  sizeOfOffset = 32;
});

// node_modules/viem/_esm/utils/abi/decodeErrorResult.js
function decodeErrorResult(parameters) {
  const { abi: abi9, data: data3 } = parameters;
  const signature3 = slice(data3, 0, 4);
  if (signature3 === "0x")
    throw new AbiDecodingZeroDataError;
  const abi_ = [...abi9 || [], solidityError, solidityPanic];
  const abiItem3 = abi_.find((x) => x.type === "error" && signature3 === toFunctionSelector(formatAbiItem(x)));
  if (!abiItem3)
    throw new AbiErrorSignatureNotFoundError(signature3, {
      docsPath: "/docs/contract/decodeErrorResult"
    });
  return {
    abiItem: abiItem3,
    args: ("inputs" in abiItem3) && abiItem3.inputs && abiItem3.inputs.length > 0 ? decodeAbiParameters(abiItem3.inputs, slice(data3, 4)) : undefined,
    errorName: abiItem3.name
  };
}
var init_decodeErrorResult = __esm(() => {
  init_solidity();
  init_abi();
  init_slice();
  init_toFunctionSelector();
  init_decodeAbiParameters();
  init_formatAbiItem();
});

// node_modules/viem/_esm/utils/abi/formatAbiItemWithArgs.js
function formatAbiItemWithArgs({ abiItem: abiItem3, args, includeFunctionName = true, includeName = false }) {
  if (!("name" in abiItem3))
    return;
  if (!("inputs" in abiItem3))
    return;
  if (!abiItem3.inputs)
    return;
  return `${includeFunctionName ? abiItem3.name : ""}(${abiItem3.inputs.map((input, i) => `${includeName && input.name ? `${input.name}: ` : ""}${typeof args[i] === "object" ? stringify(args[i]) : args[i]}`).join(", ")})`;
}
var init_formatAbiItemWithArgs = __esm(() => {
  init_stringify();
});

// node_modules/viem/_esm/errors/stateOverride.js
function prettyStateMapping(stateMapping) {
  return stateMapping.reduce((pretty, { slot, value }) => {
    return `${pretty}        ${slot}: ${value}\n`;
  }, "");
}
function prettyStateOverride(stateOverride) {
  return stateOverride.reduce((pretty, { address: address7, ...state }) => {
    let val = `${pretty}    ${address7}:\n`;
    if (state.nonce)
      val += `      nonce: ${state.nonce}\n`;
    if (state.balance)
      val += `      balance: ${state.balance}\n`;
    if (state.code)
      val += `      code: ${state.code}\n`;
    if (state.state) {
      val += "      state:\n";
      val += prettyStateMapping(state.state);
    }
    if (state.stateDiff) {
      val += "      stateDiff:\n";
      val += prettyStateMapping(state.stateDiff);
    }
    return val;
  }, "  State Override:\n").slice(0, -1);
}

class AccountStateConflictError extends BaseError {
  constructor({ address: address7 }) {
    super(`State for account "${address7}" is set multiple times.`, {
      name: "AccountStateConflictError"
    });
  }
}

class StateAssignmentConflictError extends BaseError {
  constructor() {
    super("state and stateDiff are set on the same account.", {
      name: "StateAssignmentConflictError"
    });
  }
}
var init_stateOverride = __esm(() => {
  init_base();
});

// node_modules/viem/_esm/errors/utils.js
var getContractAddress, getUrl;
var init_utils4 = __esm(() => {
  getContractAddress = (address7) => address7;
  getUrl = (url6) => url6;
});

// node_modules/viem/_esm/errors/contract.js
class CallExecutionError extends BaseError {
  constructor(cause, { account: account_, docsPath: docsPath3, chain: chain2, data: data3, gas, gasPrice, maxFeePerGas, maxPriorityFeePerGas, nonce, to, value, stateOverride: stateOverride2 }) {
    const account = account_ ? parseAccount(account_) : undefined;
    let prettyArgs = prettyPrint({
      from: account?.address,
      to,
      value: typeof value !== "undefined" && `${formatEther(value)} ${chain2?.nativeCurrency?.symbol || "ETH"}`,
      data: data3,
      gas,
      gasPrice: typeof gasPrice !== "undefined" && `${formatGwei(gasPrice)} gwei`,
      maxFeePerGas: typeof maxFeePerGas !== "undefined" && `${formatGwei(maxFeePerGas)} gwei`,
      maxPriorityFeePerGas: typeof maxPriorityFeePerGas !== "undefined" && `${formatGwei(maxPriorityFeePerGas)} gwei`,
      nonce
    });
    if (stateOverride2) {
      prettyArgs += `\n${prettyStateOverride(stateOverride2)}`;
    }
    super(cause.shortMessage, {
      cause,
      docsPath: docsPath3,
      metaMessages: [
        ...cause.metaMessages ? [...cause.metaMessages, " "] : [],
        "Raw Call Arguments:",
        prettyArgs
      ].filter(Boolean),
      name: "CallExecutionError"
    });
    Object.defineProperty(this, "cause", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.cause = cause;
  }
}

class ContractFunctionExecutionError extends BaseError {
  constructor(cause, { abi: abi10, args, contractAddress, docsPath: docsPath3, functionName, sender }) {
    const abiItem3 = getAbiItem({ abi: abi10, args, name: functionName });
    const formattedArgs = abiItem3 ? formatAbiItemWithArgs({
      abiItem: abiItem3,
      args,
      includeFunctionName: false,
      includeName: false
    }) : undefined;
    const functionWithParams = abiItem3 ? formatAbiItem(abiItem3, { includeName: true }) : undefined;
    const prettyArgs = prettyPrint({
      address: contractAddress && getContractAddress(contractAddress),
      function: functionWithParams,
      args: formattedArgs && formattedArgs !== "()" && `${[...Array(functionName?.length ?? 0).keys()].map(() => " ").join("")}${formattedArgs}`,
      sender
    });
    super(cause.shortMessage || `An unknown error occurred while executing the contract function "${functionName}".`, {
      cause,
      docsPath: docsPath3,
      metaMessages: [
        ...cause.metaMessages ? [...cause.metaMessages, " "] : [],
        prettyArgs && "Contract Call:",
        prettyArgs
      ].filter(Boolean),
      name: "ContractFunctionExecutionError"
    });
    Object.defineProperty(this, "abi", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "args", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "cause", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "contractAddress", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "formattedArgs", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "functionName", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "sender", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.abi = abi10;
    this.args = args;
    this.cause = cause;
    this.contractAddress = contractAddress;
    this.functionName = functionName;
    this.sender = sender;
  }
}

class ContractFunctionRevertedError extends BaseError {
  constructor({ abi: abi10, data: data3, functionName, message }) {
    let cause;
    let decodedData = undefined;
    let metaMessages;
    let reason;
    if (data3 && data3 !== "0x") {
      try {
        decodedData = decodeErrorResult({ abi: abi10, data: data3 });
        const { abiItem: abiItem3, errorName, args: errorArgs } = decodedData;
        if (errorName === "Error") {
          reason = errorArgs[0];
        } else if (errorName === "Panic") {
          const [firstArg] = errorArgs;
          reason = panicReasons[firstArg];
        } else {
          const errorWithParams = abiItem3 ? formatAbiItem(abiItem3, { includeName: true }) : undefined;
          const formattedArgs = abiItem3 && errorArgs ? formatAbiItemWithArgs({
            abiItem: abiItem3,
            args: errorArgs,
            includeFunctionName: false,
            includeName: false
          }) : undefined;
          metaMessages = [
            errorWithParams ? `Error: ${errorWithParams}` : "",
            formattedArgs && formattedArgs !== "()" ? `       ${[...Array(errorName?.length ?? 0).keys()].map(() => " ").join("")}${formattedArgs}` : ""
          ];
        }
      } catch (err) {
        cause = err;
      }
    } else if (message)
      reason = message;
    let signature3;
    if (cause instanceof AbiErrorSignatureNotFoundError) {
      signature3 = cause.signature;
      metaMessages = [
        `Unable to decode signature "${signature3}" as it was not found on the provided ABI.`,
        "Make sure you are using the correct ABI and that the error exists on it.",
        `You can look up the decoded signature here: https://openchain.xyz/signatures?query=${signature3}.`
      ];
    }
    super(reason && reason !== "execution reverted" || signature3 ? [
      `The contract function "${functionName}" reverted with the following ${signature3 ? "signature" : "reason"}:`,
      reason || signature3
    ].join("\n") : `The contract function "${functionName}" reverted.`, {
      cause,
      metaMessages,
      name: "ContractFunctionRevertedError"
    });
    Object.defineProperty(this, "data", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "reason", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "signature", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.data = decodedData;
    this.reason = reason;
    this.signature = signature3;
  }
}

class ContractFunctionZeroDataError extends BaseError {
  constructor({ functionName }) {
    super(`The contract function "${functionName}" returned no data ("0x").`, {
      metaMessages: [
        "This could be due to any of the following:",
        `  - The contract does not have the function "${functionName}",`,
        "  - The parameters passed to the contract function may be invalid, or",
        "  - The address is not a contract."
      ],
      name: "ContractFunctionZeroDataError"
    });
  }
}

class CounterfactualDeploymentFailedError extends BaseError {
  constructor({ factory }) {
    super(`Deployment for counterfactual contract call failed${factory ? ` for factory "${factory}".` : ""}`, {
      metaMessages: [
        "Please ensure:",
        "- The `factory` is a valid contract deployment factory (ie. Create2 Factory, ERC-4337 Factory, etc).",
        "- The `factoryData` is a valid encoded function call for contract deployment function on the factory."
      ],
      name: "CounterfactualDeploymentFailedError"
    });
  }
}

class RawContractError extends BaseError {
  constructor({ data: data3, message }) {
    super(message || "", { name: "RawContractError" });
    Object.defineProperty(this, "code", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: 3
    });
    Object.defineProperty(this, "data", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.data = data3;
  }
}
var init_contract = __esm(() => {
  init_parseAccount();
  init_solidity();
  init_decodeErrorResult();
  init_formatAbiItem();
  init_formatAbiItemWithArgs();
  init_getAbiItem();
  init_formatEther();
  init_formatGwei();
  init_abi();
  init_base();
  init_stateOverride();
  init_transaction();
  init_utils4();
});

// node_modules/viem/_esm/errors/request.js
class HttpRequestError extends BaseError {
  constructor({ body: body2, cause, details, headers, status, url: url6 }) {
    super("HTTP request failed.", {
      cause,
      details,
      metaMessages: [
        status && `Status: ${status}`,
        `URL: ${getUrl(url6)}`,
        body2 && `Request body: ${stringify(body2)}`
      ].filter(Boolean),
      name: "HttpRequestError"
    });
    Object.defineProperty(this, "body", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "headers", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "status", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "url", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.body = body2;
    this.headers = headers;
    this.status = status;
    this.url = url6;
  }
}

class RpcRequestError extends BaseError {
  constructor({ body: body2, error, url: url6 }) {
    super("RPC Request failed.", {
      cause: error,
      details: error.message,
      metaMessages: [`URL: ${getUrl(url6)}`, `Request body: ${stringify(body2)}`],
      name: "RpcRequestError"
    });
    Object.defineProperty(this, "code", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.code = error.code;
  }
}

class TimeoutError extends BaseError {
  constructor({ body: body2, url: url6 }) {
    super("The request took too long to respond.", {
      details: "The request timed out.",
      metaMessages: [`URL: ${getUrl(url6)}`, `Request body: ${stringify(body2)}`],
      name: "TimeoutError"
    });
  }
}
var init_request = __esm(() => {
  init_stringify();
  init_base();
  init_utils4();
});

// node_modules/viem/_esm/errors/rpc.js
class RpcError extends BaseError {
  constructor(cause, { code, docsPath: docsPath3, metaMessages, name, shortMessage }) {
    super(shortMessage, {
      cause,
      docsPath: docsPath3,
      metaMessages: metaMessages || cause?.metaMessages,
      name: name || "RpcError"
    });
    Object.defineProperty(this, "code", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.name = name || cause.name;
    this.code = cause instanceof RpcRequestError ? cause.code : code ?? unknownErrorCode;
  }
}

class ProviderRpcError extends RpcError {
  constructor(cause, options) {
    super(cause, options);
    Object.defineProperty(this, "data", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.data = options.data;
  }
}

class ParseRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: ParseRpcError.code,
      name: "ParseRpcError",
      shortMessage: "Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text."
    });
  }
}

class InvalidRequestRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: InvalidRequestRpcError.code,
      name: "InvalidRequestRpcError",
      shortMessage: "JSON is not a valid request object."
    });
  }
}

class MethodNotFoundRpcError extends RpcError {
  constructor(cause, { method } = {}) {
    super(cause, {
      code: MethodNotFoundRpcError.code,
      name: "MethodNotFoundRpcError",
      shortMessage: `The method${method ? ` "${method}"` : ""} does not exist / is not available.`
    });
  }
}

class InvalidParamsRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: InvalidParamsRpcError.code,
      name: "InvalidParamsRpcError",
      shortMessage: [
        "Invalid parameters were provided to the RPC method.",
        "Double check you have provided the correct parameters."
      ].join("\n")
    });
  }
}

class InternalRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: InternalRpcError.code,
      name: "InternalRpcError",
      shortMessage: "An internal error was received."
    });
  }
}

class InvalidInputRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: InvalidInputRpcError.code,
      name: "InvalidInputRpcError",
      shortMessage: [
        "Missing or invalid parameters.",
        "Double check you have provided the correct parameters."
      ].join("\n")
    });
  }
}

class ResourceNotFoundRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: ResourceNotFoundRpcError.code,
      name: "ResourceNotFoundRpcError",
      shortMessage: "Requested resource not found."
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "ResourceNotFoundRpcError"
    });
  }
}

class ResourceUnavailableRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: ResourceUnavailableRpcError.code,
      name: "ResourceUnavailableRpcError",
      shortMessage: "Requested resource not available."
    });
  }
}

class TransactionRejectedRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: TransactionRejectedRpcError.code,
      name: "TransactionRejectedRpcError",
      shortMessage: "Transaction creation failed."
    });
  }
}

class MethodNotSupportedRpcError extends RpcError {
  constructor(cause, { method } = {}) {
    super(cause, {
      code: MethodNotSupportedRpcError.code,
      name: "MethodNotSupportedRpcError",
      shortMessage: `Method${method ? ` "${method}"` : ""} is not implemented.`
    });
  }
}

class LimitExceededRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: LimitExceededRpcError.code,
      name: "LimitExceededRpcError",
      shortMessage: "Request exceeds defined limit."
    });
  }
}

class JsonRpcVersionUnsupportedError extends RpcError {
  constructor(cause) {
    super(cause, {
      code: JsonRpcVersionUnsupportedError.code,
      name: "JsonRpcVersionUnsupportedError",
      shortMessage: "Version of JSON-RPC protocol is not supported."
    });
  }
}

class UserRejectedRequestError extends ProviderRpcError {
  constructor(cause) {
    super(cause, {
      code: UserRejectedRequestError.code,
      name: "UserRejectedRequestError",
      shortMessage: "User rejected the request."
    });
  }
}

class UnauthorizedProviderError extends ProviderRpcError {
  constructor(cause) {
    super(cause, {
      code: UnauthorizedProviderError.code,
      name: "UnauthorizedProviderError",
      shortMessage: "The requested method and/or account has not been authorized by the user."
    });
  }
}

class UnsupportedProviderMethodError extends ProviderRpcError {
  constructor(cause, { method } = {}) {
    super(cause, {
      code: UnsupportedProviderMethodError.code,
      name: "UnsupportedProviderMethodError",
      shortMessage: `The Provider does not support the requested method${method ? ` " ${method}"` : ""}.`
    });
  }
}

class ProviderDisconnectedError extends ProviderRpcError {
  constructor(cause) {
    super(cause, {
      code: ProviderDisconnectedError.code,
      name: "ProviderDisconnectedError",
      shortMessage: "The Provider is disconnected from all chains."
    });
  }
}

class ChainDisconnectedError extends ProviderRpcError {
  constructor(cause) {
    super(cause, {
      code: ChainDisconnectedError.code,
      name: "ChainDisconnectedError",
      shortMessage: "The Provider is not connected to the requested chain."
    });
  }
}

class SwitchChainError extends ProviderRpcError {
  constructor(cause) {
    super(cause, {
      code: SwitchChainError.code,
      name: "SwitchChainError",
      shortMessage: "An error occurred when attempting to switch chain."
    });
  }
}

class UnknownRpcError extends RpcError {
  constructor(cause) {
    super(cause, {
      name: "UnknownRpcError",
      shortMessage: "An unknown RPC error occurred."
    });
  }
}
var unknownErrorCode;
var init_rpc = __esm(() => {
  init_base();
  init_request();
  unknownErrorCode = -1;
  Object.defineProperty(ParseRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32700
  });
  Object.defineProperty(InvalidRequestRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32600
  });
  Object.defineProperty(MethodNotFoundRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32601
  });
  Object.defineProperty(InvalidParamsRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32602
  });
  Object.defineProperty(InternalRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32603
  });
  Object.defineProperty(InvalidInputRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32000
  });
  Object.defineProperty(ResourceNotFoundRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32001
  });
  Object.defineProperty(ResourceUnavailableRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32002
  });
  Object.defineProperty(TransactionRejectedRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32003
  });
  Object.defineProperty(MethodNotSupportedRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32004
  });
  Object.defineProperty(LimitExceededRpcError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32005
  });
  Object.defineProperty(JsonRpcVersionUnsupportedError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: -32006
  });
  Object.defineProperty(UserRejectedRequestError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 4001
  });
  Object.defineProperty(UnauthorizedProviderError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 4100
  });
  Object.defineProperty(UnsupportedProviderMethodError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 4200
  });
  Object.defineProperty(ProviderDisconnectedError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 4900
  });
  Object.defineProperty(ChainDisconnectedError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 4901
  });
  Object.defineProperty(SwitchChainError, "code", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: 4902
  });
});

// node_modules/viem/_esm/utils/errors/getNodeError.js
function getNodeError(err, args) {
  const message = (err.details || "").toLowerCase();
  const executionRevertedError = err instanceof BaseError ? err.walk((e) => e?.code === ExecutionRevertedError.code) : err;
  if (executionRevertedError instanceof BaseError)
    return new ExecutionRevertedError({
      cause: err,
      message: executionRevertedError.details
    });
  if (ExecutionRevertedError.nodeMessage.test(message))
    return new ExecutionRevertedError({
      cause: err,
      message: err.details
    });
  if (FeeCapTooHighError.nodeMessage.test(message))
    return new FeeCapTooHighError({
      cause: err,
      maxFeePerGas: args?.maxFeePerGas
    });
  if (FeeCapTooLowError.nodeMessage.test(message))
    return new FeeCapTooLowError({
      cause: err,
      maxFeePerGas: args?.maxFeePerGas
    });
  if (NonceTooHighError.nodeMessage.test(message))
    return new NonceTooHighError({ cause: err, nonce: args?.nonce });
  if (NonceTooLowError.nodeMessage.test(message))
    return new NonceTooLowError({ cause: err, nonce: args?.nonce });
  if (NonceMaxValueError.nodeMessage.test(message))
    return new NonceMaxValueError({ cause: err, nonce: args?.nonce });
  if (InsufficientFundsError.nodeMessage.test(message))
    return new InsufficientFundsError({ cause: err });
  if (IntrinsicGasTooHighError.nodeMessage.test(message))
    return new IntrinsicGasTooHighError({ cause: err, gas: args?.gas });
  if (IntrinsicGasTooLowError.nodeMessage.test(message))
    return new IntrinsicGasTooLowError({ cause: err, gas: args?.gas });
  if (TransactionTypeNotSupportedError.nodeMessage.test(message))
    return new TransactionTypeNotSupportedError({ cause: err });
  if (TipAboveFeeCapError.nodeMessage.test(message))
    return new TipAboveFeeCapError({
      cause: err,
      maxFeePerGas: args?.maxFeePerGas,
      maxPriorityFeePerGas: args?.maxPriorityFeePerGas
    });
  return new UnknownNodeError({
    cause: err
  });
}
var init_getNodeError = __esm(() => {
  init_base();
  init_node();
});

// node_modules/viem/_esm/utils/formatters/extract.js
function extract(value_, { format }) {
  if (!format)
    return {};
  const value = {};
  function extract_(formatted2) {
    const keys = Object.keys(formatted2);
    for (const key of keys) {
      if (key in value_)
        value[key] = value_[key];
      if (formatted2[key] && typeof formatted2[key] === "object" && !Array.isArray(formatted2[key]))
        extract_(formatted2[key]);
    }
  }
  const formatted = format(value_ || {});
  extract_(formatted);
  return value;
}
var init_extract = __esm(() => {
});

// node_modules/viem/_esm/utils/formatters/formatter.js
function defineFormatter(type, format) {
  return ({ exclude, format: overrides }) => {
    return {
      exclude,
      format: (args) => {
        const formatted = format(args);
        if (exclude) {
          for (const key of exclude) {
            delete formatted[key];
          }
        }
        return {
          ...formatted,
          ...overrides(args)
        };
      },
      type
    };
  };
}
var init_formatter = __esm(() => {
});

// node_modules/viem/_esm/utils/formatters/transactionRequest.js
function formatTransactionRequest(request4) {
  const rpcRequest = {};
  if (typeof request4.authorizationList !== "undefined")
    rpcRequest.authorizationList = formatAuthorizationList(request4.authorizationList);
  if (typeof request4.accessList !== "undefined")
    rpcRequest.accessList = request4.accessList;
  if (typeof request4.blobVersionedHashes !== "undefined")
    rpcRequest.blobVersionedHashes = request4.blobVersionedHashes;
  if (typeof request4.blobs !== "undefined") {
    if (typeof request4.blobs[0] !== "string")
      rpcRequest.blobs = request4.blobs.map((x) => bytesToHex2(x));
    else
      rpcRequest.blobs = request4.blobs;
  }
  if (typeof request4.data !== "undefined")
    rpcRequest.data = request4.data;
  if (typeof request4.from !== "undefined")
    rpcRequest.from = request4.from;
  if (typeof request4.gas !== "undefined")
    rpcRequest.gas = numberToHex(request4.gas);
  if (typeof request4.gasPrice !== "undefined")
    rpcRequest.gasPrice = numberToHex(request4.gasPrice);
  if (typeof request4.maxFeePerBlobGas !== "undefined")
    rpcRequest.maxFeePerBlobGas = numberToHex(request4.maxFeePerBlobGas);
  if (typeof request4.maxFeePerGas !== "undefined")
    rpcRequest.maxFeePerGas = numberToHex(request4.maxFeePerGas);
  if (typeof request4.maxPriorityFeePerGas !== "undefined")
    rpcRequest.maxPriorityFeePerGas = numberToHex(request4.maxPriorityFeePerGas);
  if (typeof request4.nonce !== "undefined")
    rpcRequest.nonce = numberToHex(request4.nonce);
  if (typeof request4.to !== "undefined")
    rpcRequest.to = request4.to;
  if (typeof request4.type !== "undefined")
    rpcRequest.type = rpcTransactionType[request4.type];
  if (typeof request4.value !== "undefined")
    rpcRequest.value = numberToHex(request4.value);
  return rpcRequest;
}
var formatAuthorizationList, rpcTransactionType;
var init_transactionRequest = __esm(() => {
  init_toHex();
  formatAuthorizationList = function(authorizationList) {
    return authorizationList.map((authorization) => ({
      address: authorization.contractAddress,
      r: authorization.r,
      s: authorization.s,
      chainId: numberToHex(authorization.chainId),
      nonce: numberToHex(authorization.nonce),
      ...typeof authorization.yParity !== "undefined" ? { yParity: numberToHex(authorization.yParity) } : {},
      ...typeof authorization.v !== "undefined" && typeof authorization.yParity === "undefined" ? { v: numberToHex(authorization.v) } : {}
    }));
  };
  rpcTransactionType = {
    legacy: "0x0",
    eip2930: "0x1",
    eip1559: "0x2",
    eip4844: "0x3",
    eip7702: "0x4"
  };
});

// node_modules/viem/_esm/utils/stateOverride.js
function serializeStateMapping(stateMapping) {
  if (!stateMapping || stateMapping.length === 0)
    return;
  return stateMapping.reduce((acc, { slot, value }) => {
    if (slot.length !== 66)
      throw new InvalidBytesLengthError({
        size: slot.length,
        targetSize: 66,
        type: "hex"
      });
    if (value.length !== 66)
      throw new InvalidBytesLengthError({
        size: value.length,
        targetSize: 66,
        type: "hex"
      });
    acc[slot] = value;
    return acc;
  }, {});
}
function serializeAccountStateOverride(parameters) {
  const { balance, nonce, state, stateDiff, code } = parameters;
  const rpcAccountStateOverride = {};
  if (code !== undefined)
    rpcAccountStateOverride.code = code;
  if (balance !== undefined)
    rpcAccountStateOverride.balance = numberToHex(balance);
  if (nonce !== undefined)
    rpcAccountStateOverride.nonce = numberToHex(nonce);
  if (state !== undefined)
    rpcAccountStateOverride.state = serializeStateMapping(state);
  if (stateDiff !== undefined) {
    if (rpcAccountStateOverride.state)
      throw new StateAssignmentConflictError;
    rpcAccountStateOverride.stateDiff = serializeStateMapping(stateDiff);
  }
  return rpcAccountStateOverride;
}
function serializeStateOverride(parameters) {
  if (!parameters)
    return;
  const rpcStateOverride = {};
  for (const { address: address8, ...accountState } of parameters) {
    if (!isAddress2(address8, { strict: false }))
      throw new InvalidAddressError({ address: address8 });
    if (rpcStateOverride[address8])
      throw new AccountStateConflictError({ address: address8 });
    rpcStateOverride[address8] = serializeAccountStateOverride(accountState);
  }
  return rpcStateOverride;
}
var init_stateOverride2 = __esm(() => {
  init_address();
  init_data();
  init_stateOverride();
  init_isAddress();
  init_toHex();
});

// node_modules/viem/_esm/utils/transaction/assertRequest.js
function assertRequest(args) {
  const { account: account_, gasPrice, maxFeePerGas, maxPriorityFeePerGas, to } = args;
  const account = account_ ? parseAccount(account_) : undefined;
  if (account && !isAddress2(account.address))
    throw new InvalidAddressError({ address: account.address });
  if (to && !isAddress2(to))
    throw new InvalidAddressError({ address: to });
  if (typeof gasPrice !== "undefined" && (typeof maxFeePerGas !== "undefined" || typeof maxPriorityFeePerGas !== "undefined"))
    throw new FeeConflictError;
  if (maxFeePerGas && maxFeePerGas > maxUint256)
    throw new FeeCapTooHighError({ maxFeePerGas });
  if (maxPriorityFeePerGas && maxFeePerGas && maxPriorityFeePerGas > maxFeePerGas)
    throw new TipAboveFeeCapError({ maxFeePerGas, maxPriorityFeePerGas });
}
var init_assertRequest = __esm(() => {
  init_parseAccount();
  init_number();
  init_address();
  init_node();
  init_transaction();
  init_isAddress();
});

// node_modules/viem/_esm/utils/address/isAddressEqual.js
function isAddressEqual(a, b) {
  if (!isAddress2(a, { strict: false }))
    throw new InvalidAddressError({ address: a });
  if (!isAddress2(b, { strict: false }))
    throw new InvalidAddressError({ address: b });
  return a.toLowerCase() === b.toLowerCase();
}
var init_isAddressEqual = __esm(() => {
  init_address();
  init_isAddress();
});

// node_modules/viem/_esm/utils/abi/decodeFunctionResult.js
function decodeFunctionResult(parameters) {
  const { abi: abi14, args, functionName, data: data4 } = parameters;
  let abiItem3 = abi14[0];
  if (functionName) {
    const item = getAbiItem({ abi: abi14, args, name: functionName });
    if (!item)
      throw new AbiFunctionNotFoundError(functionName, { docsPath: docsPath4 });
    abiItem3 = item;
  }
  if (abiItem3.type !== "function")
    throw new AbiFunctionNotFoundError(undefined, { docsPath: docsPath4 });
  if (!abiItem3.outputs)
    throw new AbiFunctionOutputsNotFoundError(abiItem3.name, { docsPath: docsPath4 });
  const values = decodeAbiParameters(abiItem3.outputs, data4);
  if (values && values.length > 1)
    return values;
  if (values && values.length === 1)
    return values[0];
  return;
}
var docsPath4;
var init_decodeFunctionResult = __esm(() => {
  init_abi();
  init_decodeAbiParameters();
  init_getAbiItem();
  docsPath4 = "/docs/contract/decodeFunctionResult";
});

// node_modules/viem/_esm/constants/abis.js
var multicall3Abi, universalResolverErrors, universalResolverResolveAbi, universalResolverReverseAbi, textResolverAbi, addressResolverAbi, universalSignatureValidatorAbi;
var init_abis = __esm(() => {
  multicall3Abi = [
    {
      inputs: [
        {
          components: [
            {
              name: "target",
              type: "address"
            },
            {
              name: "allowFailure",
              type: "bool"
            },
            {
              name: "callData",
              type: "bytes"
            }
          ],
          name: "calls",
          type: "tuple[]"
        }
      ],
      name: "aggregate3",
      outputs: [
        {
          components: [
            {
              name: "success",
              type: "bool"
            },
            {
              name: "returnData",
              type: "bytes"
            }
          ],
          name: "returnData",
          type: "tuple[]"
        }
      ],
      stateMutability: "view",
      type: "function"
    }
  ];
  universalResolverErrors = [
    {
      inputs: [],
      name: "ResolverNotFound",
      type: "error"
    },
    {
      inputs: [],
      name: "ResolverWildcardNotSupported",
      type: "error"
    },
    {
      inputs: [],
      name: "ResolverNotContract",
      type: "error"
    },
    {
      inputs: [
        {
          name: "returnData",
          type: "bytes"
        }
      ],
      name: "ResolverError",
      type: "error"
    },
    {
      inputs: [
        {
          components: [
            {
              name: "status",
              type: "uint16"
            },
            {
              name: "message",
              type: "string"
            }
          ],
          name: "errors",
          type: "tuple[]"
        }
      ],
      name: "HttpError",
      type: "error"
    }
  ];
  universalResolverResolveAbi = [
    ...universalResolverErrors,
    {
      name: "resolve",
      type: "function",
      stateMutability: "view",
      inputs: [
        { name: "name", type: "bytes" },
        { name: "data", type: "bytes" }
      ],
      outputs: [
        { name: "", type: "bytes" },
        { name: "address", type: "address" }
      ]
    },
    {
      name: "resolve",
      type: "function",
      stateMutability: "view",
      inputs: [
        { name: "name", type: "bytes" },
        { name: "data", type: "bytes" },
        { name: "gateways", type: "string[]" }
      ],
      outputs: [
        { name: "", type: "bytes" },
        { name: "address", type: "address" }
      ]
    }
  ];
  universalResolverReverseAbi = [
    ...universalResolverErrors,
    {
      name: "reverse",
      type: "function",
      stateMutability: "view",
      inputs: [{ type: "bytes", name: "reverseName" }],
      outputs: [
        { type: "string", name: "resolvedName" },
        { type: "address", name: "resolvedAddress" },
        { type: "address", name: "reverseResolver" },
        { type: "address", name: "resolver" }
      ]
    },
    {
      name: "reverse",
      type: "function",
      stateMutability: "view",
      inputs: [
        { type: "bytes", name: "reverseName" },
        { type: "string[]", name: "gateways" }
      ],
      outputs: [
        { type: "string", name: "resolvedName" },
        { type: "address", name: "resolvedAddress" },
        { type: "address", name: "reverseResolver" },
        { type: "address", name: "resolver" }
      ]
    }
  ];
  textResolverAbi = [
    {
      name: "text",
      type: "function",
      stateMutability: "view",
      inputs: [
        { name: "name", type: "bytes32" },
        { name: "key", type: "string" }
      ],
      outputs: [{ name: "", type: "string" }]
    }
  ];
  addressResolverAbi = [
    {
      name: "addr",
      type: "function",
      stateMutability: "view",
      inputs: [{ name: "name", type: "bytes32" }],
      outputs: [{ name: "", type: "address" }]
    },
    {
      name: "addr",
      type: "function",
      stateMutability: "view",
      inputs: [
        { name: "name", type: "bytes32" },
        { name: "coinType", type: "uint256" }
      ],
      outputs: [{ name: "", type: "bytes" }]
    }
  ];
  universalSignatureValidatorAbi = [
    {
      inputs: [
        {
          name: "_signer",
          type: "address"
        },
        {
          name: "_hash",
          type: "bytes32"
        },
        {
          name: "_signature",
          type: "bytes"
        }
      ],
      stateMutability: "nonpayable",
      type: "constructor"
    },
    {
      inputs: [
        {
          name: "_signer",
          type: "address"
        },
        {
          name: "_hash",
          type: "bytes32"
        },
        {
          name: "_signature",
          type: "bytes"
        }
      ],
      outputs: [
        {
          type: "bool"
        }
      ],
      stateMutability: "nonpayable",
      type: "function",
      name: "isValidSig"
    }
  ];
});

// node_modules/viem/_esm/constants/contract.js
var aggregate3Signature;
var init_contract2 = __esm(() => {
  aggregate3Signature = "0x82ad56cb";
});

// node_modules/viem/_esm/constants/contracts.js
var deploylessCallViaBytecodeBytecode, deploylessCallViaFactoryBytecode, universalSignatureValidatorByteCode;
var init_contracts = __esm(() => {
  deploylessCallViaBytecodeBytecode = "0x608060405234801561001057600080fd5b5060405161018e38038061018e83398101604081905261002f91610124565b6000808351602085016000f59050803b61004857600080fd5b6000808351602085016000855af16040513d6000823e81610067573d81fd5b3d81f35b634e487b7160e01b600052604160045260246000fd5b600082601f83011261009257600080fd5b81516001600160401b038111156100ab576100ab61006b565b604051601f8201601f19908116603f011681016001600160401b03811182821017156100d9576100d961006b565b6040528181528382016020018510156100f157600080fd5b60005b82811015610110576020818601810151838301820152016100f4565b506000918101602001919091529392505050565b6000806040838503121561013757600080fd5b82516001600160401b0381111561014d57600080fd5b61015985828601610081565b602085015190935090506001600160401b0381111561017757600080fd5b61018385828601610081565b915050925092905056fe";
  deploylessCallViaFactoryBytecode = "0x608060405234801561001057600080fd5b506040516102c03803806102c083398101604081905261002f916101e6565b836001600160a01b03163b6000036100e457600080836001600160a01b03168360405161005c9190610270565b6000604051808303816000865af19150503d8060008114610099576040519150601f19603f3d011682016040523d82523d6000602084013e61009e565b606091505b50915091508115806100b857506001600160a01b0386163b155b156100e1578060405163101bb98d60e01b81526004016100d8919061028c565b60405180910390fd5b50505b6000808451602086016000885af16040513d6000823e81610103573d81fd5b3d81f35b80516001600160a01b038116811461011e57600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561015457818101518382015260200161013c565b50506000910152565b600082601f83011261016e57600080fd5b81516001600160401b0381111561018757610187610123565b604051601f8201601f19908116603f011681016001600160401b03811182821017156101b5576101b5610123565b6040528181528382016020018510156101cd57600080fd5b6101de826020830160208701610139565b949350505050565b600080600080608085870312156101fc57600080fd5b61020585610107565b60208601519094506001600160401b0381111561022157600080fd5b61022d8782880161015d565b93505061023c60408601610107565b60608601519092506001600160401b0381111561025857600080fd5b6102648782880161015d565b91505092959194509250565b60008251610282818460208701610139565b9190910192915050565b60208152600082518060208401526102ab816040850160208701610139565b601f01601f1916919091016040019291505056fe";
  universalSignatureValidatorByteCode = "0x608060405234801561001057600080fd5b5060405161069438038061069483398101604081905261002f9161051e565b600061003c848484610048565b9050806000526001601ff35b60007f64926492649264926492649264926492649264926492649264926492649264926100748361040c565b036101e7576000606080848060200190518101906100929190610577565b60405192955090935091506000906001600160a01b038516906100b69085906105dd565b6000604051808303816000865af19150503d80600081146100f3576040519150601f19603f3d011682016040523d82523d6000602084013e6100f8565b606091505b50509050876001600160a01b03163b60000361016057806101605760405162461bcd60e51b815260206004820152601e60248201527f5369676e617475726556616c696461746f723a206465706c6f796d656e74000060448201526064015b60405180910390fd5b604051630b135d3f60e11b808252906001600160a01b038a1690631626ba7e90610190908b9087906004016105f9565b602060405180830381865afa1580156101ad573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d19190610633565b6001600160e01b03191614945050505050610405565b6001600160a01b0384163b1561027a57604051630b135d3f60e11b808252906001600160a01b03861690631626ba7e9061022790879087906004016105f9565b602060405180830381865afa158015610244573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102689190610633565b6001600160e01b031916149050610405565b81516041146102df5760405162461bcd60e51b815260206004820152603a602482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e6174757265206c656e6774680000000000006064820152608401610157565b6102e7610425565b5060208201516040808401518451859392600091859190811061030c5761030c61065d565b016020015160f81c9050601b811480159061032b57508060ff16601c14155b1561038c5760405162461bcd60e51b815260206004820152603b602482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e617475726520762076616c756500000000006064820152608401610157565b60408051600081526020810180835289905260ff83169181019190915260608101849052608081018390526001600160a01b0389169060019060a0016020604051602081039080840390855afa1580156103ea573d6000803e3d6000fd5b505050602060405103516001600160a01b0316149450505050505b9392505050565b600060208251101561041d57600080fd5b508051015190565b60405180606001604052806003906020820280368337509192915050565b6001600160a01b038116811461045857600080fd5b50565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561048c578181015183820152602001610474565b50506000910152565b600082601f8301126104a657600080fd5b81516001600160401b038111156104bf576104bf61045b565b604051601f8201601f19908116603f011681016001600160401b03811182821017156104ed576104ed61045b565b60405281815283820160200185101561050557600080fd5b610516826020830160208701610471565b949350505050565b60008060006060848603121561053357600080fd5b835161053e81610443565b6020850151604086015191945092506001600160401b0381111561056157600080fd5b61056d86828701610495565b9150509250925092565b60008060006060848603121561058c57600080fd5b835161059781610443565b60208501519093506001600160401b038111156105b357600080fd5b6105bf86828701610495565b604086015190935090506001600160401b0381111561056157600080fd5b600082516105ef818460208701610471565b9190910192915050565b828152604060208201526000825180604084015261061e816060850160208701610471565b601f01601f1916919091016060019392505050565b60006020828403121561064557600080fd5b81516001600160e01b03198116811461040557600080fd5b634e487b7160e01b600052603260045260246000fdfe5369676e617475726556616c696461746f72237265636f7665725369676e6572";
});

// node_modules/viem/_esm/utils/abi/encodeDeployData.js
function encodeDeployData(parameters) {
  const { abi: abi15, args, bytecode } = parameters;
  if (!args || args.length === 0)
    return bytecode;
  const description = abi15.find((x) => ("type" in x) && x.type === "constructor");
  if (!description)
    throw new AbiConstructorNotFoundError({ docsPath: docsPath5 });
  if (!("inputs" in description))
    throw new AbiConstructorParamsNotFoundError({ docsPath: docsPath5 });
  if (!description.inputs || description.inputs.length === 0)
    throw new AbiConstructorParamsNotFoundError({ docsPath: docsPath5 });
  const data4 = encodeAbiParameters(description.inputs, args);
  return concatHex([bytecode, data4]);
}
var docsPath5;
var init_encodeDeployData = __esm(() => {
  init_abi();
  init_concat();
  init_encodeAbiParameters();
  docsPath5 = "/docs/contract/encodeDeployData";
});

// node_modules/viem/_esm/utils/chain/getChainContractAddress.js
function getChainContractAddress({ blockNumber, chain: chain3, contract: name }) {
  const contract2 = chain3?.contracts?.[name];
  if (!contract2)
    throw new ChainDoesNotSupportContract({
      chain: chain3,
      contract: { name }
    });
  if (blockNumber && contract2.blockCreated && contract2.blockCreated > blockNumber)
    throw new ChainDoesNotSupportContract({
      blockNumber,
      chain: chain3,
      contract: {
        name,
        blockCreated: contract2.blockCreated
      }
    });
  return contract2.address;
}
var init_getChainContractAddress = __esm(() => {
  init_chain();
});

// node_modules/viem/_esm/utils/errors/getCallError.js
function getCallError(err, { docsPath: docsPath6, ...args }) {
  const cause = (() => {
    const cause2 = getNodeError(err, args);
    if (cause2 instanceof UnknownNodeError)
      return err;
    return cause2;
  })();
  return new CallExecutionError(cause, {
    docsPath: docsPath6,
    ...args
  });
}
var init_getCallError = __esm(() => {
  init_contract();
  init_node();
  init_getNodeError();
});

// node_modules/viem/_esm/utils/promise/withResolvers.js
function withResolvers() {
  let resolve = () => {
    return;
  };
  let reject = () => {
    return;
  };
  const promise = new Promise((resolve_, reject_) => {
    resolve = resolve_;
    reject = reject_;
  });
  return { promise, resolve, reject };
}
var init_withResolvers = __esm(() => {
});

// node_modules/viem/_esm/utils/promise/createBatchScheduler.js
function createBatchScheduler({ fn, id, shouldSplitBatch, wait = 0, sort }) {
  const exec = async () => {
    const scheduler = getScheduler();
    flush();
    const args = scheduler.map(({ args: args2 }) => args2);
    if (args.length === 0)
      return;
    fn(args).then((data4) => {
      if (sort && Array.isArray(data4))
        data4.sort(sort);
      for (let i = 0;i < scheduler.length; i++) {
        const { resolve } = scheduler[i];
        resolve?.([data4[i], data4]);
      }
    }).catch((err) => {
      for (let i = 0;i < scheduler.length; i++) {
        const { reject } = scheduler[i];
        reject?.(err);
      }
    });
  };
  const flush = () => schedulerCache.delete(id);
  const getBatchedArgs = () => getScheduler().map(({ args }) => args);
  const getScheduler = () => schedulerCache.get(id) || [];
  const setScheduler = (item) => schedulerCache.set(id, [...getScheduler(), item]);
  return {
    flush,
    async schedule(args) {
      const { promise, resolve, reject } = withResolvers();
      const split2 = shouldSplitBatch?.([...getBatchedArgs(), args]);
      if (split2)
        exec();
      const hasActiveScheduler = getScheduler().length > 0;
      if (hasActiveScheduler) {
        setScheduler({ args, resolve, reject });
        return promise;
      }
      setScheduler({ args, resolve, reject });
      setTimeout(exec, wait);
      return promise;
    }
  };
}
var schedulerCache;
var init_createBatchScheduler = __esm(() => {
  init_withResolvers();
  schedulerCache = new Map;
});

// node_modules/viem/_esm/errors/ccip.js
class OffchainLookupError extends BaseError {
  constructor({ callbackSelector, cause, data: data4, extraData, sender, urls }) {
    super(cause.shortMessage || "An error occurred while fetching for an offchain result.", {
      cause,
      metaMessages: [
        ...cause.metaMessages || [],
        cause.metaMessages?.length ? "" : [],
        "Offchain Gateway Call:",
        urls && [
          "  Gateway URL(s):",
          ...urls.map((url6) => `    ${getUrl(url6)}`)
        ],
        `  Sender: ${sender}`,
        `  Data: ${data4}`,
        `  Callback selector: ${callbackSelector}`,
        `  Extra data: ${extraData}`
      ].flat(),
      name: "OffchainLookupError"
    });
  }
}

class OffchainLookupResponseMalformedError extends BaseError {
  constructor({ result, url: url6 }) {
    super("Offchain gateway response is malformed. Response data must be a hex value.", {
      metaMessages: [
        `Gateway URL: ${getUrl(url6)}`,
        `Response: ${stringify(result)}`
      ],
      name: "OffchainLookupResponseMalformedError"
    });
  }
}

class OffchainLookupSenderMismatchError extends BaseError {
  constructor({ sender, to }) {
    super("Reverted sender address does not match target contract address (`to`).", {
      metaMessages: [
        `Contract address: ${to}`,
        `OffchainLookup sender address: ${sender}`
      ],
      name: "OffchainLookupSenderMismatchError"
    });
  }
}
var init_ccip = __esm(() => {
  init_stringify();
  init_base();
  init_utils4();
});

// node_modules/viem/_esm/utils/ccip.js
var exports_ccip = {};
__export(exports_ccip, {
  offchainLookupSignature: () => {
    {
      return offchainLookupSignature;
    }
  },
  offchainLookupAbiItem: () => {
    {
      return offchainLookupAbiItem;
    }
  },
  offchainLookup: () => {
    {
      return offchainLookup;
    }
  },
  ccipRequest: () => {
    {
      return ccipRequest;
    }
  }
});
async function offchainLookup(client, { blockNumber, blockTag, data: data4, to }) {
  const { args } = decodeErrorResult({
    data: data4,
    abi: [offchainLookupAbiItem]
  });
  const [sender, urls, callData, callbackSelector, extraData] = args;
  const { ccipRead } = client;
  const ccipRequest_ = ccipRead && typeof ccipRead?.request === "function" ? ccipRead.request : ccipRequest;
  try {
    if (!isAddressEqual(to, sender))
      throw new OffchainLookupSenderMismatchError({ sender, to });
    const result = await ccipRequest_({ data: callData, sender, urls });
    const { data: data_ } = await call2(client, {
      blockNumber,
      blockTag,
      data: concat([
        callbackSelector,
        encodeAbiParameters([{ type: "bytes" }, { type: "bytes" }], [result, extraData])
      ]),
      to
    });
    return data_;
  } catch (err) {
    throw new OffchainLookupError({
      callbackSelector,
      cause: err,
      data: data4,
      extraData,
      sender,
      urls
    });
  }
}
async function ccipRequest({ data: data4, sender, urls }) {
  let error = new Error("An unknown error occurred.");
  for (let i = 0;i < urls.length; i++) {
    const url6 = urls[i];
    const method = url6.includes("{data}") ? "GET" : "POST";
    const body2 = method === "POST" ? { data: data4, sender } : undefined;
    const headers = method === "POST" ? { "Content-Type": "application/json" } : {};
    try {
      const response = await fetch(url6.replace("{sender}", sender).replace("{data}", data4), {
        body: JSON.stringify(body2),
        headers,
        method
      });
      let result;
      if (response.headers.get("Content-Type")?.startsWith("application/json")) {
        result = (await response.json()).data;
      } else {
        result = await response.text();
      }
      if (!response.ok) {
        error = new HttpRequestError({
          body: body2,
          details: result?.error ? stringify(result.error) : response.statusText,
          headers: response.headers,
          status: response.status,
          url: url6
        });
        continue;
      }
      if (!isHex(result)) {
        error = new OffchainLookupResponseMalformedError({
          result,
          url: url6
        });
        continue;
      }
      return result;
    } catch (err) {
      error = new HttpRequestError({
        body: body2,
        details: err.message,
        url: url6
      });
    }
  }
  throw error;
}
var offchainLookupSignature, offchainLookupAbiItem;
var init_ccip2 = __esm(() => {
  init_call();
  init_ccip();
  init_request();
  init_decodeErrorResult();
  init_encodeAbiParameters();
  init_isAddressEqual();
  init_concat();
  init_isHex();
  init_stringify();
  offchainLookupSignature = "0x556f1830";
  offchainLookupAbiItem = {
    name: "OffchainLookup",
    type: "error",
    inputs: [
      {
        name: "sender",
        type: "address"
      },
      {
        name: "urls",
        type: "string[]"
      },
      {
        name: "callData",
        type: "bytes"
      },
      {
        name: "callbackFunction",
        type: "bytes4"
      },
      {
        name: "extraData",
        type: "bytes"
      }
    ]
  };
});

// node_modules/viem/_esm/actions/public/call.js
async function call2(client, args) {
  const { account: account_ = client.account, batch = Boolean(client.batch?.multicall), blockNumber, blockTag = "latest", accessList, blobs, code, data: data_, factory, factoryData, gas, gasPrice, maxFeePerBlobGas, maxFeePerGas, maxPriorityFeePerGas, nonce, to, value, stateOverride: stateOverride5, ...rest } = args;
  const account = account_ ? parseAccount(account_) : undefined;
  if (code && (factory || factoryData))
    throw new BaseError("Cannot provide both `code` & `factory`/`factoryData` as parameters.");
  if (code && to)
    throw new BaseError("Cannot provide both `code` & `to` as parameters.");
  const deploylessCallViaBytecode = code && data_;
  const deploylessCallViaFactory = factory && factoryData && to && data_;
  const deploylessCall = deploylessCallViaBytecode || deploylessCallViaFactory;
  const data4 = (() => {
    if (deploylessCallViaBytecode)
      return toDeploylessCallViaBytecodeData({
        code,
        data: data_
      });
    if (deploylessCallViaFactory)
      return toDeploylessCallViaFactoryData({
        data: data_,
        factory,
        factoryData,
        to
      });
    return data_;
  })();
  try {
    assertRequest(args);
    const blockNumberHex = blockNumber ? numberToHex(blockNumber) : undefined;
    const block3 = blockNumberHex || blockTag;
    const rpcStateOverride = serializeStateOverride(stateOverride5);
    const chainFormat = client.chain?.formatters?.transactionRequest?.format;
    const format = chainFormat || formatTransactionRequest;
    const request5 = format({
      ...extract(rest, { format: chainFormat }),
      from: account?.address,
      accessList,
      blobs,
      data: data4,
      gas,
      gasPrice,
      maxFeePerBlobGas,
      maxFeePerGas,
      maxPriorityFeePerGas,
      nonce,
      to: deploylessCall ? undefined : to,
      value
    });
    if (batch && shouldPerformMulticall({ request: request5 }) && !rpcStateOverride) {
      try {
        return await scheduleMulticall(client, {
          ...request5,
          blockNumber,
          blockTag
        });
      } catch (err) {
        if (!(err instanceof ClientChainNotConfiguredError) && !(err instanceof ChainDoesNotSupportContract))
          throw err;
      }
    }
    const response = await client.request({
      method: "eth_call",
      params: rpcStateOverride ? [
        request5,
        block3,
        rpcStateOverride
      ] : [request5, block3]
    });
    if (response === "0x")
      return { data: undefined };
    return { data: response };
  } catch (err) {
    const data5 = getRevertErrorData(err);
    const { offchainLookup: offchainLookup2, offchainLookupSignature: offchainLookupSignature2 } = await Promise.resolve().then(() => (init_ccip2(), exports_ccip));
    if (client.ccipRead !== false && data5?.slice(0, 10) === offchainLookupSignature2 && to)
      return { data: await offchainLookup2(client, { data: data5, to }) };
    if (deploylessCall && data5?.slice(0, 10) === "0x101bb98d")
      throw new CounterfactualDeploymentFailedError({ factory });
    throw getCallError(err, {
      ...args,
      account,
      chain: client.chain
    });
  }
}
async function scheduleMulticall(client, args) {
  const { batchSize = 1024, wait = 0 } = typeof client.batch?.multicall === "object" ? client.batch.multicall : {};
  const { blockNumber, blockTag = "latest", data: data4, multicallAddress: multicallAddress_, to } = args;
  let multicallAddress = multicallAddress_;
  if (!multicallAddress) {
    if (!client.chain)
      throw new ClientChainNotConfiguredError;
    multicallAddress = getChainContractAddress({
      blockNumber,
      chain: client.chain,
      contract: "multicall3"
    });
  }
  const blockNumberHex = blockNumber ? numberToHex(blockNumber) : undefined;
  const block3 = blockNumberHex || blockTag;
  const { schedule } = createBatchScheduler({
    id: `${client.uid}.${block3}`,
    wait,
    shouldSplitBatch(args2) {
      const size12 = args2.reduce((size13, { data: data5 }) => size13 + (data5.length - 2), 0);
      return size12 > batchSize * 2;
    },
    fn: async (requests) => {
      const calls = requests.map((request5) => ({
        allowFailure: true,
        callData: request5.data,
        target: request5.to
      }));
      const calldata = encodeFunctionData({
        abi: multicall3Abi,
        args: [calls],
        functionName: "aggregate3"
      });
      const data5 = await client.request({
        method: "eth_call",
        params: [
          {
            data: calldata,
            to: multicallAddress
          },
          block3
        ]
      });
      return decodeFunctionResult({
        abi: multicall3Abi,
        args: [calls],
        functionName: "aggregate3",
        data: data5 || "0x"
      });
    }
  });
  const [{ returnData, success }] = await schedule({ data: data4, to });
  if (!success)
    throw new RawContractError({ data: returnData });
  if (returnData === "0x")
    return { data: undefined };
  return { data: returnData };
}
function getRevertErrorData(err) {
  if (!(err instanceof BaseError))
    return;
  const error = err.walk();
  return typeof error?.data === "object" ? error.data?.data : error.data;
}
var shouldPerformMulticall, toDeploylessCallViaBytecodeData, toDeploylessCallViaFactoryData;
var init_call = __esm(() => {
  init_exports();
  init_parseAccount();
  init_abis();
  init_contract2();
  init_contracts();
  init_base();
  init_chain();
  init_contract();
  init_decodeFunctionResult();
  init_encodeDeployData();
  init_encodeFunctionData();
  init_getChainContractAddress();
  init_toHex();
  init_getCallError();
  init_extract();
  init_transactionRequest();
  init_createBatchScheduler();
  init_stateOverride2();
  init_assertRequest();
  shouldPerformMulticall = function({ request: request5 }) {
    const { data: data4, to, ...request_ } = request5;
    if (!data4)
      return false;
    if (data4.startsWith(aggregate3Signature))
      return false;
    if (!to)
      return false;
    if (Object.values(request_).filter((x) => typeof x !== "undefined").length > 0)
      return false;
    return true;
  };
  toDeploylessCallViaBytecodeData = function(parameters) {
    const { code, data: data4 } = parameters;
    return encodeDeployData({
      abi: parseAbi(["constructor(bytes, bytes)"]),
      bytecode: deploylessCallViaBytecodeBytecode,
      args: [code, data4]
    });
  };
  toDeploylessCallViaFactoryData = function(parameters) {
    const { data: data4, factory, factoryData, to } = parameters;
    return encodeDeployData({
      abi: parseAbi(["constructor(address, bytes, address, bytes)"]),
      bytecode: deploylessCallViaFactoryBytecode,
      args: [to, data4, factory, factoryData]
    });
  };
});

// node_modules/hono/dist/utils/body.js
async function parseFormData(request2, options) {
  const formData = await request2.formData();
  if (formData) {
    return convertFormDataToBodyData(formData, options);
  }
  return {};
}
var convertFormDataToBodyData = function(formData, options) {
  const form = Object.create(null);
  formData.forEach((value, key) => {
    const shouldParseAllValues = options.all || key.endsWith("[]");
    if (!shouldParseAllValues) {
      form[key] = value;
    } else {
      handleParsingAllValues(form, key, value);
    }
  });
  if (options.dot) {
    Object.entries(form).forEach(([key, value]) => {
      const shouldParseDotValues = key.includes(".");
      if (shouldParseDotValues) {
        handleParsingNestedValues(form, key, value);
        delete form[key];
      }
    });
  }
  return form;
};
var parseBody = async (request2, options = Object.create(null)) => {
  const { all = false, dot = false } = options;
  const headers = request2 instanceof HonoRequest ? request2.raw.headers : request2.headers;
  const contentType = headers.get("Content-Type");
  if (contentType?.startsWith("multipart/form-data") || contentType?.startsWith("application/x-www-form-urlencoded")) {
    return parseFormData(request2, { all, dot });
  }
  return {};
};
var handleParsingAllValues = (form, key, value) => {
  if (form[key] !== undefined) {
    if (Array.isArray(form[key])) {
      form[key].push(value);
    } else {
      form[key] = [form[key], value];
    }
  } else {
    form[key] = value;
  }
};
var handleParsingNestedValues = (form, key, value) => {
  let nestedForm = form;
  const keys = key.split(".");
  keys.forEach((key2, index) => {
    if (index === keys.length - 1) {
      nestedForm[key2] = value;
    } else {
      if (!nestedForm[key2] || typeof nestedForm[key2] !== "object" || Array.isArray(nestedForm[key2]) || nestedForm[key2] instanceof File) {
        nestedForm[key2] = Object.create(null);
      }
      nestedForm = nestedForm[key2];
    }
  });
};

// node_modules/hono/dist/utils/url.js
var splitPath = (path) => {
  const paths = path.split("/");
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
};
var splitRoutingPath = (routePath) => {
  const { groups, path } = extractGroupsFromPath(routePath);
  const paths = splitPath(path);
  return replaceGroupMarks(paths, groups);
};
var extractGroupsFromPath = (path) => {
  const groups = [];
  path = path.replace(/\{[^}]+\}/g, (match, index) => {
    const mark = `@${index}`;
    groups.push([mark, match]);
    return mark;
  });
  return { groups, path };
};
var replaceGroupMarks = (paths, groups) => {
  for (let i = groups.length - 1;i >= 0; i--) {
    const [mark] = groups[i];
    for (let j = paths.length - 1;j >= 0; j--) {
      if (paths[j].includes(mark)) {
        paths[j] = paths[j].replace(mark, groups[i][1]);
        break;
      }
    }
  }
  return paths;
};
var patternCache = {};
var getPattern = (label) => {
  if (label === "*") {
    return "*";
  }
  const match = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match) {
    if (!patternCache[label]) {
      if (match[2]) {
        patternCache[label] = [label, match[1], new RegExp("^" + match[2] + "$")];
      } else {
        patternCache[label] = [label, match[1], true];
      }
    }
    return patternCache[label];
  }
  return null;
};
var tryDecode = (str, decoder) => {
  try {
    return decoder(str);
  } catch {
    return str.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
      try {
        return decoder(match);
      } catch {
        return match;
      }
    });
  }
};
var tryDecodeURI = (str) => tryDecode(str, decodeURI);
var getPath = (request2) => {
  const url = request2.url;
  const start = url.indexOf("/", 8);
  let i = start;
  for (;i < url.length; i++) {
    const charCode = url.charCodeAt(i);
    if (charCode === 37) {
      const queryIndex = url.indexOf("?", i);
      const path = url.slice(start, queryIndex === -1 ? undefined : queryIndex);
      return tryDecodeURI(path.includes("%25") ? path.replace(/%25/g, "%2525") : path);
    } else if (charCode === 63) {
      break;
    }
  }
  return url.slice(start, i);
};
var getPathNoStrict = (request2) => {
  const result = getPath(request2);
  return result.length > 1 && result[result.length - 1] === "/" ? result.slice(0, -1) : result;
};
var mergePath = (...paths) => {
  let p = "";
  let endsWithSlash = false;
  for (let path of paths) {
    if (p[p.length - 1] === "/") {
      p = p.slice(0, -1);
      endsWithSlash = true;
    }
    if (path[0] !== "/") {
      path = `/${path}`;
    }
    if (path === "/" && endsWithSlash) {
      p = `${p}/`;
    } else if (path !== "/") {
      p = `${p}${path}`;
    }
    if (path === "/" && p === "") {
      p = "/";
    }
  }
  return p;
};
var checkOptionalParameter = (path) => {
  if (!path.match(/\:.+\?$/)) {
    return null;
  }
  const segments = path.split("/");
  const results = [];
  let basePath = "";
  segments.forEach((segment) => {
    if (segment !== "" && !/\:/.test(segment)) {
      basePath += "/" + segment;
    } else if (/\:/.test(segment)) {
      if (/\?/.test(segment)) {
        if (results.length === 0 && basePath === "") {
          results.push("/");
        } else {
          results.push(basePath);
        }
        const optionalSegment = segment.replace("?", "");
        basePath += "/" + optionalSegment;
        results.push(basePath);
      } else {
        basePath += "/" + segment;
      }
    }
  });
  return results.filter((v, i, a) => a.indexOf(v) === i);
};
var _decodeURI = (value) => {
  if (!/[%+]/.test(value)) {
    return value;
  }
  if (value.indexOf("+") !== -1) {
    value = value.replace(/\+/g, " ");
  }
  return value.indexOf("%") !== -1 ? decodeURIComponent_(value) : value;
};
var _getQueryParam = (url, key, multiple) => {
  let encoded;
  if (!multiple && key && !/[%+]/.test(key)) {
    let keyIndex2 = url.indexOf(`?${key}`, 8);
    if (keyIndex2 === -1) {
      keyIndex2 = url.indexOf(`&${key}`, 8);
    }
    while (keyIndex2 !== -1) {
      const trailingKeyCode = url.charCodeAt(keyIndex2 + key.length + 1);
      if (trailingKeyCode === 61) {
        const valueIndex = keyIndex2 + key.length + 2;
        const endIndex = url.indexOf("&", valueIndex);
        return _decodeURI(url.slice(valueIndex, endIndex === -1 ? undefined : endIndex));
      } else if (trailingKeyCode == 38 || isNaN(trailingKeyCode)) {
        return "";
      }
      keyIndex2 = url.indexOf(`&${key}`, keyIndex2 + 1);
    }
    encoded = /[%+]/.test(url);
    if (!encoded) {
      return;
    }
  }
  const results = {};
  encoded ??= /[%+]/.test(url);
  let keyIndex = url.indexOf("?", 8);
  while (keyIndex !== -1) {
    const nextKeyIndex = url.indexOf("&", keyIndex + 1);
    let valueIndex = url.indexOf("=", keyIndex);
    if (valueIndex > nextKeyIndex && nextKeyIndex !== -1) {
      valueIndex = -1;
    }
    let name = url.slice(keyIndex + 1, valueIndex === -1 ? nextKeyIndex === -1 ? undefined : nextKeyIndex : valueIndex);
    if (encoded) {
      name = _decodeURI(name);
    }
    keyIndex = nextKeyIndex;
    if (name === "") {
      continue;
    }
    let value;
    if (valueIndex === -1) {
      value = "";
    } else {
      value = url.slice(valueIndex + 1, nextKeyIndex === -1 ? undefined : nextKeyIndex);
      if (encoded) {
        value = _decodeURI(value);
      }
    }
    if (multiple) {
      if (!(results[name] && Array.isArray(results[name]))) {
        results[name] = [];
      }
      results[name].push(value);
    } else {
      results[name] ??= value;
    }
  }
  return key ? results[key] : results;
};
var getQueryParam = _getQueryParam;
var getQueryParams = (url, key) => {
  return _getQueryParam(url, key, true);
};
var decodeURIComponent_ = decodeURIComponent;

// node_modules/hono/dist/request.js
var tryDecodeURIComponent = (str) => tryDecode(str, decodeURIComponent_);
var HonoRequest = class {
  raw;
  #validatedData;
  #matchResult;
  routeIndex = 0;
  path;
  bodyCache = {};
  constructor(request2, path = "/", matchResult = [[]]) {
    this.raw = request2;
    this.path = path;
    this.#matchResult = matchResult;
    this.#validatedData = {};
  }
  param(key) {
    return key ? this.#getDecodedParam(key) : this.#getAllDecodedParams();
  }
  #getDecodedParam(key) {
    const paramKey = this.#matchResult[0][this.routeIndex][1][key];
    const param = this.#getParamValue(paramKey);
    return param ? /\%/.test(param) ? tryDecodeURIComponent(param) : param : undefined;
  }
  #getAllDecodedParams() {
    const decoded = {};
    const keys = Object.keys(this.#matchResult[0][this.routeIndex][1]);
    for (const key of keys) {
      const value = this.#getParamValue(this.#matchResult[0][this.routeIndex][1][key]);
      if (value && typeof value === "string") {
        decoded[key] = /\%/.test(value) ? tryDecodeURIComponent(value) : value;
      }
    }
    return decoded;
  }
  #getParamValue(paramKey) {
    return this.#matchResult[1] ? this.#matchResult[1][paramKey] : paramKey;
  }
  query(key) {
    return getQueryParam(this.url, key);
  }
  queries(key) {
    return getQueryParams(this.url, key);
  }
  header(name) {
    if (name) {
      return this.raw.headers.get(name.toLowerCase()) ?? undefined;
    }
    const headerData = {};
    this.raw.headers.forEach((value, key) => {
      headerData[key] = value;
    });
    return headerData;
  }
  async parseBody(options) {
    return this.bodyCache.parsedBody ??= await parseBody(this, options);
  }
  #cachedBody = (key) => {
    const { bodyCache, raw } = this;
    const cachedBody = bodyCache[key];
    if (cachedBody) {
      return cachedBody;
    }
    const anyCachedKey = Object.keys(bodyCache)[0];
    if (anyCachedKey) {
      return bodyCache[anyCachedKey].then((body2) => {
        if (anyCachedKey === "json") {
          body2 = JSON.stringify(body2);
        }
        return new Response(body2)[key]();
      });
    }
    return bodyCache[key] = raw[key]();
  };
  json() {
    return this.#cachedBody("json");
  }
  text() {
    return this.#cachedBody("text");
  }
  arrayBuffer() {
    return this.#cachedBody("arrayBuffer");
  }
  blob() {
    return this.#cachedBody("blob");
  }
  formData() {
    return this.#cachedBody("formData");
  }
  addValidatedData(target, data) {
    this.#validatedData[target] = data;
  }
  valid(target) {
    return this.#validatedData[target];
  }
  get url() {
    return this.raw.url;
  }
  get method() {
    return this.raw.method;
  }
  get matchedRoutes() {
    return this.#matchResult[0].map(([[, route]]) => route);
  }
  get routePath() {
    return this.#matchResult[0].map(([[, route]]) => route)[this.routeIndex].path;
  }
};

// node_modules/hono/dist/utils/html.js
var HtmlEscapedCallbackPhase = {
  Stringify: 1,
  BeforeStream: 2,
  Stream: 3
};
var raw = (value, callbacks) => {
  const escapedString = new String(value);
  escapedString.isEscaped = true;
  escapedString.callbacks = callbacks;
  return escapedString;
};
var resolveCallback = async (str, phase, preserveCallbacks, context, buffer) => {
  if (typeof str === "object" && !(str instanceof String)) {
    if (!(str instanceof Promise)) {
      str = str.toString();
    }
    if (str instanceof Promise) {
      str = await str;
    }
  }
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return Promise.resolve(str);
  }
  if (buffer) {
    buffer[0] += str;
  } else {
    buffer = [str];
  }
  const resStr = Promise.all(callbacks.map((c) => c({ phase, buffer, context }))).then((res) => Promise.all(res.filter(Boolean).map((str2) => resolveCallback(str2, phase, false, context, buffer))).then(() => buffer[0]));
  if (preserveCallbacks) {
    return raw(await resStr, callbacks);
  } else {
    return resStr;
  }
};

// node_modules/hono/dist/context.js
var TEXT_PLAIN = "text/plain; charset=UTF-8";
var setHeaders = (headers, map = {}) => {
  for (const key of Object.keys(map)) {
    headers.set(key, map[key]);
  }
  return headers;
};
var Context = class {
  #rawRequest;
  #req;
  env = {};
  #var;
  finalized = false;
  error;
  #status = 200;
  #executionCtx;
  #headers;
  #preparedHeaders;
  #res;
  #isFresh = true;
  #layout;
  #renderer;
  #notFoundHandler;
  #matchResult;
  #path;
  constructor(req, options) {
    this.#rawRequest = req;
    if (options) {
      this.#executionCtx = options.executionCtx;
      this.env = options.env;
      this.#notFoundHandler = options.notFoundHandler;
      this.#path = options.path;
      this.#matchResult = options.matchResult;
    }
  }
  get req() {
    this.#req ??= new HonoRequest(this.#rawRequest, this.#path, this.#matchResult);
    return this.#req;
  }
  get event() {
    if (this.#executionCtx && ("respondWith" in this.#executionCtx)) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    this.#isFresh = false;
    return this.#res ||= new Response("404 Not Found", { status: 404 });
  }
  set res(_res) {
    this.#isFresh = false;
    if (this.#res && _res) {
      try {
        for (const [k, v] of this.#res.headers.entries()) {
          if (k === "content-type") {
            continue;
          }
          if (k === "set-cookie") {
            const cookies = this.#res.headers.getSetCookie();
            _res.headers.delete("set-cookie");
            for (const cookie of cookies) {
              _res.headers.append("set-cookie", cookie);
            }
          } else {
            _res.headers.set(k, v);
          }
        }
      } catch (e) {
        if (e instanceof TypeError && e.message.includes("immutable")) {
          this.res = new Response(_res.body, {
            headers: _res.headers,
            status: _res.status
          });
          return;
        } else {
          throw e;
        }
      }
    }
    this.#res = _res;
    this.finalized = true;
  }
  render = (...args) => {
    this.#renderer ??= (content) => this.html(content);
    return this.#renderer(...args);
  };
  setLayout = (layout) => this.#layout = layout;
  getLayout = () => this.#layout;
  setRenderer = (renderer) => {
    this.#renderer = renderer;
  };
  header = (name, value, options) => {
    if (value === undefined) {
      if (this.#headers) {
        this.#headers.delete(name);
      } else if (this.#preparedHeaders) {
        delete this.#preparedHeaders[name.toLocaleLowerCase()];
      }
      if (this.finalized) {
        this.res.headers.delete(name);
      }
      return;
    }
    if (options?.append) {
      if (!this.#headers) {
        this.#isFresh = false;
        this.#headers = new Headers(this.#preparedHeaders);
        this.#preparedHeaders = {};
      }
      this.#headers.append(name, value);
    } else {
      if (this.#headers) {
        this.#headers.set(name, value);
      } else {
        this.#preparedHeaders ??= {};
        this.#preparedHeaders[name.toLowerCase()] = value;
      }
    }
    if (this.finalized) {
      if (options?.append) {
        this.res.headers.append(name, value);
      } else {
        this.res.headers.set(name, value);
      }
    }
  };
  status = (status) => {
    this.#isFresh = false;
    this.#status = status;
  };
  set = (key, value) => {
    this.#var ??= new Map;
    this.#var.set(key, value);
  };
  get = (key) => {
    return this.#var ? this.#var.get(key) : undefined;
  };
  get var() {
    if (!this.#var) {
      return {};
    }
    return Object.fromEntries(this.#var);
  }
  #newResponse(data, arg, headers) {
    if (this.#isFresh && !headers && !arg && this.#status === 200) {
      return new Response(data, {
        headers: this.#preparedHeaders
      });
    }
    if (arg && typeof arg !== "number") {
      const header = new Headers(arg.headers);
      if (this.#headers) {
        this.#headers.forEach((v, k) => {
          if (k === "set-cookie") {
            header.append(k, v);
          } else {
            header.set(k, v);
          }
        });
      }
      const headers2 = setHeaders(header, this.#preparedHeaders);
      return new Response(data, {
        headers: headers2,
        status: arg.status ?? this.#status
      });
    }
    const status = typeof arg === "number" ? arg : this.#status;
    this.#preparedHeaders ??= {};
    this.#headers ??= new Headers;
    setHeaders(this.#headers, this.#preparedHeaders);
    if (this.#res) {
      this.#res.headers.forEach((v, k) => {
        if (k === "set-cookie") {
          this.#headers?.append(k, v);
        } else {
          this.#headers?.set(k, v);
        }
      });
      setHeaders(this.#headers, this.#preparedHeaders);
    }
    headers ??= {};
    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === "string") {
        this.#headers.set(k, v);
      } else {
        this.#headers.delete(k);
        for (const v2 of v) {
          this.#headers.append(k, v2);
        }
      }
    }
    return new Response(data, {
      status,
      headers: this.#headers
    });
  }
  newResponse = (...args) => this.#newResponse(...args);
  body = (data, arg, headers) => {
    return typeof arg === "number" ? this.#newResponse(data, arg, headers) : this.#newResponse(data, arg);
  };
  text = (text, arg, headers) => {
    if (!this.#preparedHeaders) {
      if (this.#isFresh && !headers && !arg) {
        return new Response(text);
      }
      this.#preparedHeaders = {};
    }
    this.#preparedHeaders["content-type"] = TEXT_PLAIN;
    return typeof arg === "number" ? this.#newResponse(text, arg, headers) : this.#newResponse(text, arg);
  };
  json = (object, arg, headers) => {
    const body2 = JSON.stringify(object);
    this.#preparedHeaders ??= {};
    this.#preparedHeaders["content-type"] = "application/json; charset=UTF-8";
    return typeof arg === "number" ? this.#newResponse(body2, arg, headers) : this.#newResponse(body2, arg);
  };
  html = (html2, arg, headers) => {
    this.#preparedHeaders ??= {};
    this.#preparedHeaders["content-type"] = "text/html; charset=UTF-8";
    if (typeof html2 === "object") {
      return resolveCallback(html2, HtmlEscapedCallbackPhase.Stringify, false, {}).then((html22) => {
        return typeof arg === "number" ? this.#newResponse(html22, arg, headers) : this.#newResponse(html22, arg);
      });
    }
    return typeof arg === "number" ? this.#newResponse(html2, arg, headers) : this.#newResponse(html2, arg);
  };
  redirect = (location, status) => {
    this.#headers ??= new Headers;
    this.#headers.set("Location", String(location));
    return this.newResponse(null, status ?? 302);
  };
  notFound = () => {
    this.#notFoundHandler ??= () => new Response;
    return this.#notFoundHandler(this);
  };
};

// node_modules/hono/dist/compose.js
var compose = (middleware, onError, onNotFound) => {
  return (context2, next) => {
    let index = -1;
    const isContext = context2 instanceof Context;
    return dispatch(0);
    async function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      index = i;
      let res;
      let isError = false;
      let handler;
      if (middleware[i]) {
        handler = middleware[i][0][0];
        if (isContext) {
          context2.req.routeIndex = i;
        }
      } else {
        handler = i === middleware.length && next || undefined;
      }
      if (!handler) {
        if (isContext && context2.finalized === false && onNotFound) {
          res = await onNotFound(context2);
        }
      } else {
        try {
          res = await handler(context2, () => {
            return dispatch(i + 1);
          });
        } catch (err) {
          if (err instanceof Error && isContext && onError) {
            context2.error = err;
            res = await onError(err, context2);
            isError = true;
          } else {
            throw err;
          }
        }
      }
      if (res && (context2.finalized === false || isError)) {
        context2.res = res;
      }
      return context2;
    }
  };
};

// node_modules/hono/dist/router.js
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "options", "patch"];
var MESSAGE_MATCHER_IS_ALREADY_BUILT = "Can not add a route since the matcher is already built.";
var UnsupportedPathError = class extends Error {
};

// node_modules/hono/dist/hono-base.js
var COMPOSED_HANDLER = Symbol("composedHandler");
var notFoundHandler = (c) => {
  return c.text("404 Not Found", 404);
};
var errorHandler = (err, c) => {
  if ("getResponse" in err) {
    return err.getResponse();
  }
  console.error(err);
  return c.text("Internal Server Error", 500);
};
var Hono = class {
  get;
  post;
  put;
  delete;
  options;
  patch;
  all;
  on;
  use;
  router;
  getPath;
  _basePath = "/";
  #path = "/";
  routes = [];
  constructor(options = {}) {
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.forEach((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          this.#path = args1;
        } else {
          this.#addRoute(method, this.#path, args1);
        }
        args.forEach((handler) => {
          this.#addRoute(method, this.#path, handler);
        });
        return this;
      };
    });
    this.on = (method, path, ...handlers) => {
      for (const p of [path].flat()) {
        this.#path = p;
        for (const m of [method].flat()) {
          handlers.map((handler) => {
            this.#addRoute(m.toUpperCase(), this.#path, handler);
          });
        }
      }
      return this;
    };
    this.use = (arg1, ...handlers) => {
      if (typeof arg1 === "string") {
        this.#path = arg1;
      } else {
        this.#path = "*";
        handlers.unshift(arg1);
      }
      handlers.forEach((handler) => {
        this.#addRoute(METHOD_NAME_ALL, this.#path, handler);
      });
      return this;
    };
    const strict = options.strict ?? true;
    delete options.strict;
    Object.assign(this, options);
    this.getPath = strict ? options.getPath ?? getPath : getPathNoStrict;
  }
  #clone() {
    const clone = new Hono({
      router: this.router,
      getPath: this.getPath
    });
    clone.routes = this.routes;
    return clone;
  }
  #notFoundHandler = notFoundHandler;
  #errorHandler = errorHandler;
  route(path, app) {
    const subApp = this.basePath(path);
    app.routes.map((r) => {
      let handler;
      if (app.#errorHandler === errorHandler) {
        handler = r.handler;
      } else {
        handler = async (c, next) => (await compose([], app.#errorHandler)(c, () => r.handler(c, next))).res;
        handler[COMPOSED_HANDLER] = r.handler;
      }
      subApp.#addRoute(r.method, r.path, handler);
    });
    return this;
  }
  basePath(path) {
    const subApp = this.#clone();
    subApp._basePath = mergePath(this._basePath, path);
    return subApp;
  }
  onError = (handler) => {
    this.#errorHandler = handler;
    return this;
  };
  notFound = (handler) => {
    this.#notFoundHandler = handler;
    return this;
  };
  mount(path, applicationHandler, options) {
    let replaceRequest;
    let optionHandler;
    if (options) {
      if (typeof options === "function") {
        optionHandler = options;
      } else {
        optionHandler = options.optionHandler;
        replaceRequest = options.replaceRequest;
      }
    }
    const getOptions = optionHandler ? (c) => {
      const options2 = optionHandler(c);
      return Array.isArray(options2) ? options2 : [options2];
    } : (c) => {
      let executionContext = undefined;
      try {
        executionContext = c.executionCtx;
      } catch {
      }
      return [c.env, executionContext];
    };
    replaceRequest ||= (() => {
      const mergedPath = mergePath(this._basePath, path);
      const pathPrefixLength = mergedPath === "/" ? 0 : mergedPath.length;
      return (request3) => {
        const url3 = new URL(request3.url);
        url3.pathname = url3.pathname.slice(pathPrefixLength) || "/";
        return new Request(url3, request3);
      };
    })();
    const handler = async (c, next) => {
      const res = await applicationHandler(replaceRequest(c.req.raw), ...getOptions(c));
      if (res) {
        return res;
      }
      await next();
    };
    this.#addRoute(METHOD_NAME_ALL, mergePath(path, "*"), handler);
    return this;
  }
  #addRoute(method, path, handler) {
    method = method.toUpperCase();
    path = mergePath(this._basePath, path);
    const r = { path, method, handler };
    this.router.add(method, path, [handler, r]);
    this.routes.push(r);
  }
  #handleError(err, c) {
    if (err instanceof Error) {
      return this.#errorHandler(err, c);
    }
    throw err;
  }
  #dispatch(request3, executionCtx, env, method) {
    if (method === "HEAD") {
      return (async () => new Response(null, await this.#dispatch(request3, executionCtx, env, "GET")))();
    }
    const path = this.getPath(request3, { env });
    const matchResult = this.router.match(method, path);
    const c = new Context(request3, {
      path,
      matchResult,
      env,
      executionCtx,
      notFoundHandler: this.#notFoundHandler
    });
    if (matchResult[0].length === 1) {
      let res;
      try {
        res = matchResult[0][0][0][0](c, async () => {
          c.res = await this.#notFoundHandler(c);
        });
      } catch (err) {
        return this.#handleError(err, c);
      }
      return res instanceof Promise ? res.then((resolved) => resolved || (c.finalized ? c.res : this.#notFoundHandler(c))).catch((err) => this.#handleError(err, c)) : res ?? this.#notFoundHandler(c);
    }
    const composed = compose(matchResult[0], this.#errorHandler, this.#notFoundHandler);
    return (async () => {
      try {
        const context3 = await composed(c);
        if (!context3.finalized) {
          throw new Error("Context is not finalized. Did you forget to return a Response object or `await next()`?");
        }
        return context3.res;
      } catch (err) {
        return this.#handleError(err, c);
      }
    })();
  }
  fetch = (request3, ...rest) => {
    return this.#dispatch(request3, rest[1], rest[0], request3.method);
  };
  request = (input, requestInit, Env, executionCtx) => {
    if (input instanceof Request) {
      return this.fetch(requestInit ? new Request(input, requestInit) : input, Env, executionCtx);
    }
    input = input.toString();
    return this.fetch(new Request(/^https?:\/\//.test(input) ? input : `http://localhost${mergePath("/", input)}`, requestInit), Env, executionCtx);
  };
  fire = () => {
    addEventListener("fetch", (event) => {
      event.respondWith(this.#dispatch(event.request, event, undefined, event.request.method));
    });
  };
};

// node_modules/hono/dist/router/reg-exp-router/node.js
var compareKey = function(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
};
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
var regExpMetaChars = new Set(".\\+*[^]$()");
var Node = class {
  #index;
  #varIndex;
  #children = Object.create(null);
  insert(tokens, index, paramMap, context3, pathErrorCheckOnly) {
    if (tokens.length === 0) {
      if (this.#index !== undefined) {
        throw PATH_ERROR;
      }
      if (pathErrorCheckOnly) {
        return;
      }
      this.#index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      let regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      if (name && pattern[2]) {
        regexpStr = regexpStr.replace(/^\((?!\?:)(?=[^)]+\)$)/, "(?:");
        if (/\((?!\?:)/.test(regexpStr)) {
          throw PATH_ERROR;
        }
      }
      node = this.#children[regexpStr];
      if (!node) {
        if (Object.keys(this.#children).some((k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR)) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[regexpStr] = new Node;
        if (name !== "") {
          node.#varIndex = context3.varIndex++;
        }
      }
      if (!pathErrorCheckOnly && name !== "") {
        paramMap.push([name, node.#varIndex]);
      }
    } else {
      node = this.#children[token];
      if (!node) {
        if (Object.keys(this.#children).some((k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR)) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[token] = new Node;
      }
    }
    node.insert(restTokens, index, paramMap, context3, pathErrorCheckOnly);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.#children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.#children[k];
      return (typeof c.#varIndex === "number" ? `(${k})@${c.#varIndex}` : regExpMetaChars.has(k) ? `\\${k}` : k) + c.buildRegExpStr();
    });
    if (typeof this.#index === "number") {
      strList.unshift(`#${this.#index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
};

// node_modules/hono/dist/router/reg-exp-router/trie.js
var Trie = class {
  #context = { varIndex: 0 };
  #root = new Node;
  insert(path, index, pathErrorCheckOnly) {
    const paramAssoc = [];
    const groups = [];
    for (let i = 0;; ) {
      let replaced = false;
      path = path.replace(/\{[^}]+\}/g, (m) => {
        const mark = `@\\${i}`;
        groups[i] = [mark, m];
        i++;
        replaced = true;
        return mark;
      });
      if (!replaced) {
        break;
      }
    }
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g) || [];
    for (let i = groups.length - 1;i >= 0; i--) {
      const [mark] = groups[i];
      for (let j = tokens.length - 1;j >= 0; j--) {
        if (tokens[j].indexOf(mark) !== -1) {
          tokens[j] = tokens[j].replace(mark, groups[i][1]);
          break;
        }
      }
    }
    this.#root.insert(tokens, index, paramAssoc, this.#context, pathErrorCheckOnly);
    return paramAssoc;
  }
  buildRegExp() {
    let regexp = this.#root.buildRegExpStr();
    if (regexp === "") {
      return [/^$/, [], []];
    }
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (handlerIndex !== undefined) {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (paramIndex !== undefined) {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
};

// node_modules/hono/dist/router/reg-exp-router/router.js
var buildWildcardRegExp = function(path) {
  return wildcardRegExpCache[path] ??= new RegExp(path === "*" ? "" : `^${path.replace(/\/\*$|([.\\+*[^\]$()])/g, (_, metaChar) => metaChar ? `\\${metaChar}` : "(?:|/.*)")}\$`);
};
var clearWildcardRegExpCache = function() {
  wildcardRegExpCache = Object.create(null);
};
var buildMatcherFromPreprocessedRoutes = function(routes) {
  const trie2 = new Trie;
  const handlerData = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  const routesWithStaticPathFlag = routes.map((route) => [!/\*|\/:/.test(route[0]), ...route]).sort(([isStaticA, pathA], [isStaticB, pathB]) => isStaticA ? 1 : isStaticB ? -1 : pathA.length - pathB.length);
  const staticMap = Object.create(null);
  for (let i = 0, j = -1, len = routesWithStaticPathFlag.length;i < len; i++) {
    const [pathErrorCheckOnly, path, handlers] = routesWithStaticPathFlag[i];
    if (pathErrorCheckOnly) {
      staticMap[path] = [handlers.map(([h]) => [h, Object.create(null)]), emptyParam];
    } else {
      j++;
    }
    let paramAssoc;
    try {
      paramAssoc = trie2.insert(path, j, pathErrorCheckOnly);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(path) : e;
    }
    if (pathErrorCheckOnly) {
      continue;
    }
    handlerData[j] = handlers.map(([h, paramCount]) => {
      const paramIndexMap = Object.create(null);
      paramCount -= 1;
      for (;paramCount >= 0; paramCount--) {
        const [key, value] = paramAssoc[paramCount];
        paramIndexMap[key] = value;
      }
      return [h, paramIndexMap];
    });
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie2.buildRegExp();
  for (let i = 0, len = handlerData.length;i < len; i++) {
    for (let j = 0, len2 = handlerData[i].length;j < len2; j++) {
      const map = handlerData[i][j]?.[1];
      if (!map) {
        continue;
      }
      const keys = Object.keys(map);
      for (let k = 0, len3 = keys.length;k < len3; k++) {
        map[keys[k]] = paramReplacementMap[map[keys[k]]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlerData[indexReplacementMap[i]];
  }
  return [regexp, handlerMap, staticMap];
};
var findMiddleware = function(middleware, path) {
  if (!middleware) {
    return;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return;
};
var emptyParam = [];
var nullMatcher = [/^$/, [], Object.create(null)];
var wildcardRegExpCache = Object.create(null);
var RegExpRouter = class {
  name = "RegExpRouter";
  #middleware;
  #routes;
  constructor() {
    this.#middleware = { [METHOD_NAME_ALL]: Object.create(null) };
    this.#routes = { [METHOD_NAME_ALL]: Object.create(null) };
  }
  add(method, path, handler) {
    const middleware = this.#middleware;
    const routes = this.#routes;
    if (!middleware || !routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    if (!middleware[method]) {
      [middleware, routes].forEach((handlerMap) => {
        handlerMap[method] = Object.create(null);
        Object.keys(handlerMap[METHOD_NAME_ALL]).forEach((p) => {
          handlerMap[method][p] = [...handlerMap[METHOD_NAME_ALL][p]];
        });
      });
    }
    if (path === "/*") {
      path = "*";
    }
    const paramCount = (path.match(/\/:/g) || []).length;
    if (/\*$/.test(path)) {
      const re = buildWildcardRegExp(path);
      if (method === METHOD_NAME_ALL) {
        Object.keys(middleware).forEach((m) => {
          middleware[m][path] ||= findMiddleware(middleware[m], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
        });
      } else {
        middleware[method][path] ||= findMiddleware(middleware[method], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
      }
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            re.test(p) && middleware[m][p].push([handler, paramCount]);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach((p) => re.test(p) && routes[m][p].push([handler, paramCount]));
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length;i < len; i++) {
      const path2 = paths[i];
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          routes[m][path2] ||= [
            ...findMiddleware(middleware[m], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ];
          routes[m][path2].push([handler, paramCount - len + i + 1]);
        }
      });
    }
  }
  match(method, path) {
    clearWildcardRegExpCache();
    const matchers = this.#buildAllMatchers();
    this.match = (method2, path2) => {
      const matcher = matchers[method2] || matchers[METHOD_NAME_ALL];
      const staticMatch = matcher[2][path2];
      if (staticMatch) {
        return staticMatch;
      }
      const match = path2.match(matcher[0]);
      if (!match) {
        return [[], emptyParam];
      }
      const index = match.indexOf("", 1);
      return [matcher[1][index], match];
    };
    return this.match(method, path);
  }
  #buildAllMatchers() {
    const matchers = Object.create(null);
    Object.keys(this.#routes).concat(Object.keys(this.#middleware)).forEach((method) => {
      matchers[method] ||= this.#buildMatcher(method);
    });
    this.#middleware = this.#routes = undefined;
    return matchers;
  }
  #buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.#middleware, this.#routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute ||= true;
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]]));
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
};

// node_modules/hono/dist/router/smart-router/router.js
var SmartRouter = class {
  name = "SmartRouter";
  #routers = [];
  #routes = [];
  constructor(init) {
    this.#routers = init.routers;
  }
  add(method, path, handler) {
    if (!this.#routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    this.#routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.#routes) {
      throw new Error("Fatal error");
    }
    const routers = this.#routers;
    const routes = this.#routes;
    const len = routers.length;
    let i = 0;
    let res;
    for (;i < len; i++) {
      const router5 = routers[i];
      try {
        for (let i2 = 0, len2 = routes.length;i2 < len2; i2++) {
          router5.add(...routes[i2]);
        }
        res = router5.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router5.match.bind(router5);
      this.#routers = [router5];
      this.#routes = undefined;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    this.name = `SmartRouter + ${this.activeRouter.name}`;
    return res;
  }
  get activeRouter() {
    if (this.#routes || this.#routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.#routers[0];
  }
};

// node_modules/hono/dist/router/trie-router/node.js
var Node2 = class {
  #methods;
  #children;
  #patterns;
  #order = 0;
  #params = Object.create(null);
  constructor(method, handler, children) {
    this.#children = children || Object.create(null);
    this.#methods = [];
    if (method && handler) {
      const m = Object.create(null);
      m[method] = { handler, possibleKeys: [], score: 0 };
      this.#methods = [m];
    }
    this.#patterns = [];
  }
  insert(method, path, handler) {
    this.#order = ++this.#order;
    let curNode = this;
    const parts = splitRoutingPath(path);
    const possibleKeys = [];
    for (let i = 0, len = parts.length;i < len; i++) {
      const p = parts[i];
      if (Object.keys(curNode.#children).includes(p)) {
        curNode = curNode.#children[p];
        const pattern2 = getPattern(p);
        if (pattern2) {
          possibleKeys.push(pattern2[1]);
        }
        continue;
      }
      curNode.#children[p] = new Node2;
      const pattern = getPattern(p);
      if (pattern) {
        curNode.#patterns.push(pattern);
        possibleKeys.push(pattern[1]);
      }
      curNode = curNode.#children[p];
    }
    const m = Object.create(null);
    const handlerSet = {
      handler,
      possibleKeys: possibleKeys.filter((v, i, a) => a.indexOf(v) === i),
      score: this.#order
    };
    m[method] = handlerSet;
    curNode.#methods.push(m);
    return curNode;
  }
  #getHandlerSets(node3, method, nodeParams, params) {
    const handlerSets = [];
    for (let i = 0, len = node3.#methods.length;i < len; i++) {
      const m = node3.#methods[i];
      const handlerSet = m[method] || m[METHOD_NAME_ALL];
      const processedSet = {};
      if (handlerSet !== undefined) {
        handlerSet.params = Object.create(null);
        for (let i2 = 0, len2 = handlerSet.possibleKeys.length;i2 < len2; i2++) {
          const key = handlerSet.possibleKeys[i2];
          const processed = processedSet[handlerSet.score];
          handlerSet.params[key] = params[key] && !processed ? params[key] : nodeParams[key] ?? params[key];
          processedSet[handlerSet.score] = true;
        }
        handlerSets.push(handlerSet);
      }
    }
    return handlerSets;
  }
  search(method, path) {
    const handlerSets = [];
    this.#params = Object.create(null);
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    for (let i = 0, len = parts.length;i < len; i++) {
      const part = parts[i];
      const isLast = i === len - 1;
      const tempNodes = [];
      for (let j = 0, len2 = curNodes.length;j < len2; j++) {
        const node3 = curNodes[j];
        const nextNode = node3.#children[part];
        if (nextNode) {
          nextNode.#params = node3.#params;
          if (isLast) {
            if (nextNode.#children["*"]) {
              handlerSets.push(...this.#getHandlerSets(nextNode.#children["*"], method, node3.#params, Object.create(null)));
            }
            handlerSets.push(...this.#getHandlerSets(nextNode, method, node3.#params, Object.create(null)));
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node3.#patterns.length;k < len3; k++) {
          const pattern = node3.#patterns[k];
          const params = { ...node3.#params };
          if (pattern === "*") {
            const astNode = node3.#children["*"];
            if (astNode) {
              handlerSets.push(...this.#getHandlerSets(astNode, method, node3.#params, Object.create(null)));
              tempNodes.push(astNode);
            }
            continue;
          }
          if (part === "") {
            continue;
          }
          const [key, name, matcher] = pattern;
          const child = node3.#children[key];
          const restPathString = parts.slice(i).join("/");
          if (matcher instanceof RegExp && matcher.test(restPathString)) {
            params[name] = restPathString;
            handlerSets.push(...this.#getHandlerSets(child, method, node3.#params, params));
            continue;
          }
          if (matcher === true || matcher.test(part)) {
            params[name] = part;
            if (isLast) {
              handlerSets.push(...this.#getHandlerSets(child, method, params, node3.#params));
              if (child.#children["*"]) {
                handlerSets.push(...this.#getHandlerSets(child.#children["*"], method, params, node3.#params));
              }
            } else {
              child.#params = params;
              tempNodes.push(child);
            }
          }
        }
      }
      curNodes = tempNodes;
    }
    const results = handlerSets.sort((a, b) => {
      return a.score - b.score;
    });
    return [results.map(({ handler, params }) => [handler, params])];
  }
};

// node_modules/hono/dist/router/trie-router/router.js
var TrieRouter = class {
  name = "TrieRouter";
  #node;
  constructor() {
    this.#node = new Node2;
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (let i = 0, len = results.length;i < len; i++) {
        this.#node.insert(method, results[i], handler);
      }
      return;
    }
    this.#node.insert(method, path, handler);
  }
  match(method, path) {
    return this.#node.search(method, path);
  }
};

// node_modules/hono/dist/hono.js
var Hono2 = class extends Hono {
  constructor(options = {}) {
    super(options);
    this.router = options.router ?? new SmartRouter({
      routers: [new RegExpRouter, new TrieRouter]
    });
  }
};

// node_modules/viem/_esm/accounts/privateKeyToAccount.js
init_secp256k1();
init_toHex();

// node_modules/viem/_esm/accounts/toAccount.js
init_address();
init_isAddress();
function toAccount(source) {
  if (typeof source === "string") {
    if (!isAddress2(source, { strict: false }))
      throw new InvalidAddressError({ address: source });
    return {
      address: source,
      type: "json-rpc"
    };
  }
  if (!isAddress2(source.address, { strict: false }))
    throw new InvalidAddressError({ address: source.address });
  return {
    address: source.address,
    nonceManager: source.nonceManager,
    sign: source.sign,
    experimental_signAuthorization: source.experimental_signAuthorization,
    signMessage: source.signMessage,
    signTransaction: source.signTransaction,
    signTypedData: source.signTypedData,
    source: "custom",
    type: "local"
  };
}

// node_modules/viem/_esm/accounts/utils/publicKeyToAddress.js
init_getAddress();
init_keccak256();
function publicKeyToAddress(publicKey) {
  const address3 = keccak256(`0x${publicKey.substring(4)}`).substring(26);
  return checksumAddress(`0x${address3}`);
}

// node_modules/viem/_esm/accounts/utils/sign.js
init_secp256k1();
init_toHex();

// node_modules/viem/_esm/utils/signature/serializeSignature.js
init_secp256k1();
init_fromHex();
init_toBytes();
function serializeSignature({ r, s, to = "hex", v, yParity }) {
  const yParity_ = (() => {
    if (yParity === 0 || yParity === 1)
      return yParity;
    if (v && (v === 27n || v === 28n || v >= 35n))
      return v % 2n === 0n ? 1 : 0;
    throw new Error("Invalid `v` or `yParity` value");
  })();
  const signature = `0x${new secp256k1.Signature(hexToBigInt(r), hexToBigInt(s)).toCompactHex()}${yParity_ === 0 ? "1b" : "1c"}`;
  if (to === "hex")
    return signature;
  return hexToBytes2(signature);
}

// node_modules/viem/_esm/accounts/utils/sign.js
async function sign({ hash: hash2, privateKey, to = "object" }) {
  const { r, s, recovery } = secp256k1.sign(hash2.slice(2), privateKey.slice(2));
  const signature = {
    r: numberToHex(r, { size: 32 }),
    s: numberToHex(s, { size: 32 }),
    v: recovery ? 28n : 27n,
    yParity: recovery
  };
  return (() => {
    if (to === "bytes" || to === "hex")
      return serializeSignature({ ...signature, to });
    return signature;
  })();
}

// node_modules/viem/_esm/experimental/eip7702/utils/hashAuthorization.js
init_concat();
init_toBytes();
init_toHex();

// node_modules/viem/_esm/utils/encoding/toRlp.js
init_base();
init_cursor2();
init_toBytes();
init_toHex();
function toRlp(bytes2, to = "hex") {
  const encodable = getEncodable(bytes2);
  const cursor3 = createCursor(new Uint8Array(encodable.length));
  encodable.encode(cursor3);
  if (to === "hex")
    return bytesToHex2(cursor3.bytes);
  return cursor3.bytes;
}
var getEncodable = function(bytes2) {
  if (Array.isArray(bytes2))
    return getEncodableList(bytes2.map((x) => getEncodable(x)));
  return getEncodableBytes(bytes2);
};
var getEncodableList = function(list) {
  const bodyLength = list.reduce((acc, x) => acc + x.length, 0);
  const sizeOfBodyLength = getSizeOfLength(bodyLength);
  const length = (() => {
    if (bodyLength <= 55)
      return 1 + bodyLength;
    return 1 + sizeOfBodyLength + bodyLength;
  })();
  return {
    length,
    encode(cursor3) {
      if (bodyLength <= 55) {
        cursor3.pushByte(192 + bodyLength);
      } else {
        cursor3.pushByte(192 + 55 + sizeOfBodyLength);
        if (sizeOfBodyLength === 1)
          cursor3.pushUint8(bodyLength);
        else if (sizeOfBodyLength === 2)
          cursor3.pushUint16(bodyLength);
        else if (sizeOfBodyLength === 3)
          cursor3.pushUint24(bodyLength);
        else
          cursor3.pushUint32(bodyLength);
      }
      for (const { encode } of list) {
        encode(cursor3);
      }
    }
  };
};
var getEncodableBytes = function(bytesOrHex) {
  const bytes2 = typeof bytesOrHex === "string" ? hexToBytes2(bytesOrHex) : bytesOrHex;
  const sizeOfBytesLength = getSizeOfLength(bytes2.length);
  const length = (() => {
    if (bytes2.length === 1 && bytes2[0] < 128)
      return 1;
    if (bytes2.length <= 55)
      return 1 + bytes2.length;
    return 1 + sizeOfBytesLength + bytes2.length;
  })();
  return {
    length,
    encode(cursor3) {
      if (bytes2.length === 1 && bytes2[0] < 128) {
        cursor3.pushBytes(bytes2);
      } else if (bytes2.length <= 55) {
        cursor3.pushByte(128 + bytes2.length);
        cursor3.pushBytes(bytes2);
      } else {
        cursor3.pushByte(128 + 55 + sizeOfBytesLength);
        if (sizeOfBytesLength === 1)
          cursor3.pushUint8(bytes2.length);
        else if (sizeOfBytesLength === 2)
          cursor3.pushUint16(bytes2.length);
        else if (sizeOfBytesLength === 3)
          cursor3.pushUint24(bytes2.length);
        else
          cursor3.pushUint32(bytes2.length);
        cursor3.pushBytes(bytes2);
      }
    }
  };
};
var getSizeOfLength = function(length) {
  if (length < 2 ** 8)
    return 1;
  if (length < 2 ** 16)
    return 2;
  if (length < 2 ** 24)
    return 3;
  if (length < 2 ** 32)
    return 4;
  throw new BaseError("Length is too large.");
};

// node_modules/viem/_esm/experimental/eip7702/utils/hashAuthorization.js
init_keccak256();
function hashAuthorization(parameters) {
  const { chainId, contractAddress, nonce, to } = parameters;
  const hash2 = keccak256(concatHex([
    "0x05",
    toRlp([
      chainId ? numberToHex(chainId) : "0x",
      contractAddress,
      nonce ? numberToHex(nonce) : "0x"
    ])
  ]));
  if (to === "bytes")
    return hexToBytes2(hash2);
  return hash2;
}

// node_modules/viem/_esm/accounts/utils/signAuthorization.js
async function experimental_signAuthorization(parameters) {
  const { contractAddress, chainId, nonce, privateKey, to = "object" } = parameters;
  const signature = await sign({
    hash: hashAuthorization({ contractAddress, chainId, nonce }),
    privateKey,
    to
  });
  if (to === "object")
    return {
      contractAddress,
      chainId,
      nonce,
      ...signature
    };
  return signature;
}

// node_modules/viem/_esm/utils/signature/hashMessage.js
init_keccak256();

// node_modules/viem/_esm/constants/strings.js
var presignMessagePrefix = `\x19Ethereum Signed Message:
`;

// node_modules/viem/_esm/utils/signature/toPrefixedMessage.js
init_concat();
init_size();
init_toHex();
function toPrefixedMessage(message_) {
  const message = (() => {
    if (typeof message_ === "string")
      return stringToHex(message_);
    if (typeof message_.raw === "string")
      return message_.raw;
    return bytesToHex2(message_.raw);
  })();
  const prefix = stringToHex(`${presignMessagePrefix}${size(message)}`);
  return concat([prefix, message]);
}

// node_modules/viem/_esm/utils/signature/hashMessage.js
function hashMessage(message, to_) {
  return keccak256(toPrefixedMessage(message), to_);
}

// node_modules/viem/_esm/accounts/utils/signMessage.js
async function signMessage({ message, privateKey }) {
  return await sign({ hash: hashMessage(message), privateKey, to: "hex" });
}

// node_modules/viem/_esm/accounts/utils/signTransaction.js
init_keccak256();

// node_modules/viem/_esm/utils/transaction/serializeTransaction.js
init_transaction();

// node_modules/viem/_esm/utils/blob/blobsToCommitments.js
init_toBytes();
init_toHex();
function blobsToCommitments(parameters) {
  const { kzg } = parameters;
  const to = parameters.to ?? (typeof parameters.blobs[0] === "string" ? "hex" : "bytes");
  const blobs = typeof parameters.blobs[0] === "string" ? parameters.blobs.map((x) => hexToBytes2(x)) : parameters.blobs;
  const commitments = [];
  for (const blob of blobs)
    commitments.push(Uint8Array.from(kzg.blobToKzgCommitment(blob)));
  return to === "bytes" ? commitments : commitments.map((x) => bytesToHex2(x));
}

// node_modules/viem/_esm/utils/blob/blobsToProofs.js
init_toBytes();
init_toHex();
function blobsToProofs(parameters) {
  const { kzg } = parameters;
  const to = parameters.to ?? (typeof parameters.blobs[0] === "string" ? "hex" : "bytes");
  const blobs = typeof parameters.blobs[0] === "string" ? parameters.blobs.map((x) => hexToBytes2(x)) : parameters.blobs;
  const commitments = typeof parameters.commitments[0] === "string" ? parameters.commitments.map((x) => hexToBytes2(x)) : parameters.commitments;
  const proofs = [];
  for (let i = 0;i < blobs.length; i++) {
    const blob = blobs[i];
    const commitment = commitments[i];
    proofs.push(Uint8Array.from(kzg.computeBlobKzgProof(blob, commitment)));
  }
  return to === "bytes" ? proofs : proofs.map((x) => bytesToHex2(x));
}

// node_modules/viem/_esm/utils/blob/commitmentToVersionedHash.js
init_toHex();

// node_modules/viem/_esm/utils/hash/sha256.js
init_sha256();
init_isHex();
init_toBytes();
init_toHex();
function sha2564(value, to_) {
  const to = to_ || "hex";
  const bytes2 = sha256(isHex(value, { strict: false }) ? toBytes2(value) : value);
  if (to === "bytes")
    return bytes2;
  return toHex2(bytes2);
}

// node_modules/viem/_esm/utils/blob/commitmentToVersionedHash.js
function commitmentToVersionedHash(parameters) {
  const { commitment, version: version3 = 1 } = parameters;
  const to = parameters.to ?? (typeof commitment === "string" ? "hex" : "bytes");
  const versionedHash = sha2564(commitment, "bytes");
  versionedHash.set([version3], 0);
  return to === "bytes" ? versionedHash : bytesToHex2(versionedHash);
}

// node_modules/viem/_esm/utils/blob/commitmentsToVersionedHashes.js
function commitmentsToVersionedHashes(parameters) {
  const { commitments, version: version3 } = parameters;
  const to = parameters.to ?? (typeof commitments[0] === "string" ? "hex" : "bytes");
  const hashes = [];
  for (const commitment of commitments) {
    hashes.push(commitmentToVersionedHash({
      commitment,
      to,
      version: version3
    }));
  }
  return hashes;
}

// node_modules/viem/_esm/constants/blob.js
var blobsPerTransaction = 6;
var bytesPerFieldElement = 32;
var fieldElementsPerBlob = 4096;
var bytesPerBlob = bytesPerFieldElement * fieldElementsPerBlob;
var maxBytesPerTransaction = bytesPerBlob * blobsPerTransaction - 1 - 1 * fieldElementsPerBlob * blobsPerTransaction;

// node_modules/viem/_esm/constants/kzg.js
var versionedHashVersionKzg = 1;

// node_modules/viem/_esm/errors/blob.js
init_base();

class BlobSizeTooLargeError extends BaseError {
  constructor({ maxSize, size: size4 }) {
    super("Blob size is too large.", {
      metaMessages: [`Max: ${maxSize} bytes`, `Given: ${size4} bytes`],
      name: "BlobSizeTooLargeError"
    });
  }
}

class EmptyBlobError extends BaseError {
  constructor() {
    super("Blob data must not be empty.", { name: "EmptyBlobError" });
  }
}

class InvalidVersionedHashSizeError extends BaseError {
  constructor({ hash: hash2, size: size4 }) {
    super(`Versioned hash "${hash2}" size is invalid.`, {
      metaMessages: ["Expected: 32", `Received: ${size4}`],
      name: "InvalidVersionedHashSizeError"
    });
  }
}

class InvalidVersionedHashVersionError extends BaseError {
  constructor({ hash: hash2, version: version3 }) {
    super(`Versioned hash "${hash2}" version is invalid.`, {
      metaMessages: [
        `Expected: ${versionedHashVersionKzg}`,
        `Received: ${version3}`
      ],
      name: "InvalidVersionedHashVersionError"
    });
  }
}

// node_modules/viem/_esm/utils/blob/toBlobs.js
init_cursor2();
init_size();
init_toBytes();
init_toHex();
function toBlobs(parameters) {
  const to = parameters.to ?? (typeof parameters.data === "string" ? "hex" : "bytes");
  const data2 = typeof parameters.data === "string" ? hexToBytes2(parameters.data) : parameters.data;
  const size_ = size(data2);
  if (!size_)
    throw new EmptyBlobError;
  if (size_ > maxBytesPerTransaction)
    throw new BlobSizeTooLargeError({
      maxSize: maxBytesPerTransaction,
      size: size_
    });
  const blobs = [];
  let active = true;
  let position = 0;
  while (active) {
    const blob3 = createCursor(new Uint8Array(bytesPerBlob));
    let size5 = 0;
    while (size5 < fieldElementsPerBlob) {
      const bytes2 = data2.slice(position, position + (bytesPerFieldElement - 1));
      blob3.pushByte(0);
      blob3.pushBytes(bytes2);
      if (bytes2.length < 31) {
        blob3.pushByte(128);
        active = false;
        break;
      }
      size5++;
      position += 31;
    }
    blobs.push(blob3);
  }
  return to === "bytes" ? blobs.map((x) => x.bytes) : blobs.map((x) => bytesToHex2(x.bytes));
}

// node_modules/viem/_esm/utils/blob/toBlobSidecars.js
function toBlobSidecars(parameters) {
  const { data: data2, kzg: kzg2, to } = parameters;
  const blobs = parameters.blobs ?? toBlobs({ data: data2, to });
  const commitments = parameters.commitments ?? blobsToCommitments({ blobs, kzg: kzg2, to });
  const proofs = parameters.proofs ?? blobsToProofs({ blobs, commitments, kzg: kzg2, to });
  const sidecars = [];
  for (let i = 0;i < blobs.length; i++)
    sidecars.push({
      blob: blobs[i],
      commitment: commitments[i],
      proof: proofs[i]
    });
  return sidecars;
}

// node_modules/viem/_esm/utils/transaction/serializeTransaction.js
init_concat();
init_trim();
init_toHex();

// node_modules/viem/_esm/experimental/eip7702/utils/serializeAuthorizationList.js
init_toHex();
function serializeAuthorizationList(authorizationList) {
  if (!authorizationList || authorizationList.length === 0)
    return [];
  const serializedAuthorizationList = [];
  for (const authorization of authorizationList) {
    const { contractAddress, chainId, nonce, ...signature } = authorization;
    serializedAuthorizationList.push([
      chainId ? toHex2(chainId) : "0x",
      contractAddress,
      nonce ? toHex2(nonce) : "0x",
      ...toYParitySignatureArray({}, signature)
    ]);
  }
  return serializedAuthorizationList;
}

// node_modules/viem/_esm/utils/transaction/assertTransaction.js
init_number();
init_address();
init_base();
init_chain();
init_node();
init_isAddress();
init_size();
init_slice();
init_fromHex();
function assertTransactionEIP7702(transaction) {
  const { authorizationList } = transaction;
  if (authorizationList) {
    for (const authorization of authorizationList) {
      const { contractAddress, chainId } = authorization;
      if (!isAddress2(contractAddress))
        throw new InvalidAddressError({ address: contractAddress });
      if (chainId < 0)
        throw new InvalidChainIdError({ chainId });
    }
  }
  assertTransactionEIP1559(transaction);
}
function assertTransactionEIP4844(transaction) {
  const { blobVersionedHashes } = transaction;
  if (blobVersionedHashes) {
    if (blobVersionedHashes.length === 0)
      throw new EmptyBlobError;
    for (const hash2 of blobVersionedHashes) {
      const size_ = size(hash2);
      const version3 = hexToNumber2(slice(hash2, 0, 1));
      if (size_ !== 32)
        throw new InvalidVersionedHashSizeError({ hash: hash2, size: size_ });
      if (version3 !== versionedHashVersionKzg)
        throw new InvalidVersionedHashVersionError({
          hash: hash2,
          version: version3
        });
    }
  }
  assertTransactionEIP1559(transaction);
}
function assertTransactionEIP1559(transaction) {
  const { chainId, maxPriorityFeePerGas, maxFeePerGas, to } = transaction;
  if (chainId <= 0)
    throw new InvalidChainIdError({ chainId });
  if (to && !isAddress2(to))
    throw new InvalidAddressError({ address: to });
  if (maxFeePerGas && maxFeePerGas > maxUint256)
    throw new FeeCapTooHighError({ maxFeePerGas });
  if (maxPriorityFeePerGas && maxFeePerGas && maxPriorityFeePerGas > maxFeePerGas)
    throw new TipAboveFeeCapError({ maxFeePerGas, maxPriorityFeePerGas });
}
function assertTransactionEIP2930(transaction) {
  const { chainId, maxPriorityFeePerGas, gasPrice, maxFeePerGas, to } = transaction;
  if (chainId <= 0)
    throw new InvalidChainIdError({ chainId });
  if (to && !isAddress2(to))
    throw new InvalidAddressError({ address: to });
  if (maxPriorityFeePerGas || maxFeePerGas)
    throw new BaseError("`maxFeePerGas`/`maxPriorityFeePerGas` is not a valid EIP-2930 Transaction attribute.");
  if (gasPrice && gasPrice > maxUint256)
    throw new FeeCapTooHighError({ maxFeePerGas: gasPrice });
}
function assertTransactionLegacy(transaction) {
  const { chainId, maxPriorityFeePerGas, gasPrice, maxFeePerGas, to } = transaction;
  if (to && !isAddress2(to))
    throw new InvalidAddressError({ address: to });
  if (typeof chainId !== "undefined" && chainId <= 0)
    throw new InvalidChainIdError({ chainId });
  if (maxPriorityFeePerGas || maxFeePerGas)
    throw new BaseError("`maxFeePerGas`/`maxPriorityFeePerGas` is not a valid Legacy Transaction attribute.");
  if (gasPrice && gasPrice > maxUint256)
    throw new FeeCapTooHighError({ maxFeePerGas: gasPrice });
}

// node_modules/viem/_esm/utils/transaction/getTransactionType.js
init_transaction();
function getTransactionType(transaction2) {
  if (transaction2.type)
    return transaction2.type;
  if (typeof transaction2.authorizationList !== "undefined")
    return "eip7702";
  if (typeof transaction2.blobs !== "undefined" || typeof transaction2.blobVersionedHashes !== "undefined" || typeof transaction2.maxFeePerBlobGas !== "undefined" || typeof transaction2.sidecars !== "undefined")
    return "eip4844";
  if (typeof transaction2.maxFeePerGas !== "undefined" || typeof transaction2.maxPriorityFeePerGas !== "undefined") {
    return "eip1559";
  }
  if (typeof transaction2.gasPrice !== "undefined") {
    if (typeof transaction2.accessList !== "undefined")
      return "eip2930";
    return "legacy";
  }
  throw new InvalidSerializableTransactionError({ transaction: transaction2 });
}

// node_modules/viem/_esm/utils/transaction/serializeAccessList.js
init_address();
init_transaction();
init_isAddress();
function serializeAccessList(accessList) {
  if (!accessList || accessList.length === 0)
    return [];
  const serializedAccessList = [];
  for (let i = 0;i < accessList.length; i++) {
    const { address: address5, storageKeys } = accessList[i];
    for (let j = 0;j < storageKeys.length; j++) {
      if (storageKeys[j].length - 2 !== 64) {
        throw new InvalidStorageKeySizeError({ storageKey: storageKeys[j] });
      }
    }
    if (!isAddress2(address5, { strict: false })) {
      throw new InvalidAddressError({ address: address5 });
    }
    serializedAccessList.push([address5, storageKeys]);
  }
  return serializedAccessList;
}

// node_modules/viem/_esm/utils/transaction/serializeTransaction.js
function serializeTransaction2(transaction4, signature) {
  const type = getTransactionType(transaction4);
  if (type === "eip1559")
    return serializeTransactionEIP1559(transaction4, signature);
  if (type === "eip2930")
    return serializeTransactionEIP2930(transaction4, signature);
  if (type === "eip4844")
    return serializeTransactionEIP4844(transaction4, signature);
  if (type === "eip7702")
    return serializeTransactionEIP7702(transaction4, signature);
  return serializeTransactionLegacy(transaction4, signature);
}
var serializeTransactionEIP7702 = function(transaction4, signature) {
  const { authorizationList, chainId, gas, nonce, to, value, maxFeePerGas, maxPriorityFeePerGas, accessList, data: data3 } = transaction4;
  assertTransactionEIP7702(transaction4);
  const serializedAccessList = serializeAccessList(accessList);
  const serializedAuthorizationList = serializeAuthorizationList(authorizationList);
  return concatHex([
    "0x04",
    toRlp([
      toHex2(chainId),
      nonce ? toHex2(nonce) : "0x",
      maxPriorityFeePerGas ? toHex2(maxPriorityFeePerGas) : "0x",
      maxFeePerGas ? toHex2(maxFeePerGas) : "0x",
      gas ? toHex2(gas) : "0x",
      to ?? "0x",
      value ? toHex2(value) : "0x",
      data3 ?? "0x",
      serializedAccessList,
      serializedAuthorizationList,
      ...toYParitySignatureArray(transaction4, signature)
    ])
  ]);
};
var serializeTransactionEIP4844 = function(transaction4, signature) {
  const { chainId, gas, nonce, to, value, maxFeePerBlobGas, maxFeePerGas, maxPriorityFeePerGas, accessList, data: data3 } = transaction4;
  assertTransactionEIP4844(transaction4);
  let blobVersionedHashes = transaction4.blobVersionedHashes;
  let sidecars = transaction4.sidecars;
  if (transaction4.blobs && (typeof blobVersionedHashes === "undefined" || typeof sidecars === "undefined")) {
    const blobs2 = typeof transaction4.blobs[0] === "string" ? transaction4.blobs : transaction4.blobs.map((x) => bytesToHex2(x));
    const kzg3 = transaction4.kzg;
    const commitments2 = blobsToCommitments({
      blobs: blobs2,
      kzg: kzg3
    });
    if (typeof blobVersionedHashes === "undefined")
      blobVersionedHashes = commitmentsToVersionedHashes({
        commitments: commitments2
      });
    if (typeof sidecars === "undefined") {
      const proofs2 = blobsToProofs({ blobs: blobs2, commitments: commitments2, kzg: kzg3 });
      sidecars = toBlobSidecars({ blobs: blobs2, commitments: commitments2, proofs: proofs2 });
    }
  }
  const serializedAccessList = serializeAccessList(accessList);
  const serializedTransaction = [
    toHex2(chainId),
    nonce ? toHex2(nonce) : "0x",
    maxPriorityFeePerGas ? toHex2(maxPriorityFeePerGas) : "0x",
    maxFeePerGas ? toHex2(maxFeePerGas) : "0x",
    gas ? toHex2(gas) : "0x",
    to ?? "0x",
    value ? toHex2(value) : "0x",
    data3 ?? "0x",
    serializedAccessList,
    maxFeePerBlobGas ? toHex2(maxFeePerBlobGas) : "0x",
    blobVersionedHashes ?? [],
    ...toYParitySignatureArray(transaction4, signature)
  ];
  const blobs = [];
  const commitments = [];
  const proofs = [];
  if (sidecars)
    for (let i = 0;i < sidecars.length; i++) {
      const { blob: blob4, commitment, proof } = sidecars[i];
      blobs.push(blob4);
      commitments.push(commitment);
      proofs.push(proof);
    }
  return concatHex([
    "0x03",
    sidecars ? toRlp([serializedTransaction, blobs, commitments, proofs]) : toRlp(serializedTransaction)
  ]);
};
var serializeTransactionEIP1559 = function(transaction4, signature) {
  const { chainId, gas, nonce, to, value, maxFeePerGas, maxPriorityFeePerGas, accessList, data: data3 } = transaction4;
  assertTransactionEIP1559(transaction4);
  const serializedAccessList = serializeAccessList(accessList);
  const serializedTransaction = [
    toHex2(chainId),
    nonce ? toHex2(nonce) : "0x",
    maxPriorityFeePerGas ? toHex2(maxPriorityFeePerGas) : "0x",
    maxFeePerGas ? toHex2(maxFeePerGas) : "0x",
    gas ? toHex2(gas) : "0x",
    to ?? "0x",
    value ? toHex2(value) : "0x",
    data3 ?? "0x",
    serializedAccessList,
    ...toYParitySignatureArray(transaction4, signature)
  ];
  return concatHex([
    "0x02",
    toRlp(serializedTransaction)
  ]);
};
var serializeTransactionEIP2930 = function(transaction4, signature) {
  const { chainId, gas, data: data3, nonce, to, value, accessList, gasPrice } = transaction4;
  assertTransactionEIP2930(transaction4);
  const serializedAccessList = serializeAccessList(accessList);
  const serializedTransaction = [
    toHex2(chainId),
    nonce ? toHex2(nonce) : "0x",
    gasPrice ? toHex2(gasPrice) : "0x",
    gas ? toHex2(gas) : "0x",
    to ?? "0x",
    value ? toHex2(value) : "0x",
    data3 ?? "0x",
    serializedAccessList,
    ...toYParitySignatureArray(transaction4, signature)
  ];
  return concatHex([
    "0x01",
    toRlp(serializedTransaction)
  ]);
};
var serializeTransactionLegacy = function(transaction4, signature) {
  const { chainId = 0, gas, data: data3, nonce, to, value, gasPrice } = transaction4;
  assertTransactionLegacy(transaction4);
  let serializedTransaction = [
    nonce ? toHex2(nonce) : "0x",
    gasPrice ? toHex2(gasPrice) : "0x",
    gas ? toHex2(gas) : "0x",
    to ?? "0x",
    value ? toHex2(value) : "0x",
    data3 ?? "0x"
  ];
  if (signature) {
    const v = (() => {
      if (signature.v >= 35n) {
        const inferredChainId = (signature.v - 35n) / 2n;
        if (inferredChainId > 0)
          return signature.v;
        return 27n + (signature.v === 35n ? 0n : 1n);
      }
      if (chainId > 0)
        return BigInt(chainId * 2) + BigInt(35n + signature.v - 27n);
      const v2 = 27n + (signature.v === 27n ? 0n : 1n);
      if (signature.v !== v2)
        throw new InvalidLegacyVError({ v: signature.v });
      return v2;
    })();
    const r = trim(signature.r);
    const s = trim(signature.s);
    serializedTransaction = [
      ...serializedTransaction,
      toHex2(v),
      r === "0x00" ? "0x" : r,
      s === "0x00" ? "0x" : s
    ];
  } else if (chainId > 0) {
    serializedTransaction = [
      ...serializedTransaction,
      toHex2(chainId),
      "0x",
      "0x"
    ];
  }
  return toRlp(serializedTransaction);
};
function toYParitySignatureArray(transaction4, signature_) {
  const signature = signature_ ?? transaction4;
  const { v, yParity } = signature;
  if (typeof signature.r === "undefined")
    return [];
  if (typeof signature.s === "undefined")
    return [];
  if (typeof v === "undefined" && typeof yParity === "undefined")
    return [];
  const r = trim(signature.r);
  const s = trim(signature.s);
  const yParity_ = (() => {
    if (typeof yParity === "number")
      return yParity ? toHex2(1) : "0x";
    if (v === 0n)
      return "0x";
    if (v === 1n)
      return toHex2(1);
    return v === 27n ? "0x" : toHex2(1);
  })();
  return [yParity_, r === "0x00" ? "0x" : r, s === "0x00" ? "0x" : s];
}

// node_modules/viem/_esm/accounts/utils/signTransaction.js
async function signTransaction(parameters) {
  const { privateKey, transaction: transaction4, serializer = serializeTransaction2 } = parameters;
  const signableTransaction = (() => {
    if (transaction4.type === "eip4844")
      return {
        ...transaction4,
        sidecars: false
      };
    return transaction4;
  })();
  const signature = await sign({
    hash: keccak256(serializer(signableTransaction)),
    privateKey
  });
  return serializer(transaction4, signature);
}

// node_modules/viem/_esm/utils/signature/hashTypedData.js
init_encodeAbiParameters();
init_concat();
init_toHex();
init_keccak256();

// node_modules/viem/_esm/utils/typedData.js
init_abi();
init_address();

// node_modules/viem/_esm/errors/typedData.js
init_stringify();
init_base();

class InvalidDomainError extends BaseError {
  constructor({ domain }) {
    super(`Invalid domain "${stringify(domain)}".`, {
      metaMessages: ["Must be a valid EIP-712 domain."]
    });
  }
}

class InvalidPrimaryTypeError extends BaseError {
  constructor({ primaryType, types }) {
    super(`Invalid primary type \`${primaryType}\` must be one of \`${JSON.stringify(Object.keys(types))}\`.`, {
      docsPath: "/api/glossary/Errors#typeddatainvalidprimarytypeerror",
      metaMessages: ["Check that the primary type is a key in `types`."]
    });
  }
}

class InvalidStructTypeError extends BaseError {
  constructor({ type }) {
    super(`Struct type "${type}" is invalid.`, {
      metaMessages: ["Struct type must not be a Solidity type."],
      name: "InvalidStructTypeError"
    });
  }
}

// node_modules/viem/_esm/utils/typedData.js
init_isAddress();
init_size();
init_toHex();

// node_modules/viem/_esm/utils/regex.js
var arrayRegex = /^(.*)\[([0-9]*)\]$/;
var bytesRegex = /^bytes([1-9]|1[0-9]|2[0-9]|3[0-2])?$/;
var integerRegex = /^(u?int)(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/;

// node_modules/viem/_esm/utils/typedData.js
init_stringify();
function serializeTypedData(parameters) {
  const { domain: domain_, message: message_, primaryType, types } = parameters;
  const normalizeData = (struct, data_) => {
    const data3 = { ...data_ };
    for (const param of struct) {
      const { name, type } = param;
      if (type === "address")
        data3[name] = data3[name].toLowerCase();
    }
    return data3;
  };
  const domain = (() => {
    if (!types.EIP712Domain)
      return {};
    if (!domain_)
      return {};
    return normalizeData(types.EIP712Domain, domain_);
  })();
  const message = (() => {
    if (primaryType === "EIP712Domain")
      return;
    return normalizeData(types[primaryType], message_);
  })();
  return stringify({ domain, message, primaryType, types });
}
function validateTypedData(parameters) {
  const { domain, message, primaryType, types } = parameters;
  const validateData = (struct, data3) => {
    for (const param of struct) {
      const { name, type } = param;
      const value = data3[name];
      const integerMatch = type.match(integerRegex);
      if (integerMatch && (typeof value === "number" || typeof value === "bigint")) {
        const [_type, base15, size_] = integerMatch;
        numberToHex(value, {
          signed: base15 === "int",
          size: Number.parseInt(size_) / 8
        });
      }
      if (type === "address" && typeof value === "string" && !isAddress2(value))
        throw new InvalidAddressError({ address: value });
      const bytesMatch = type.match(bytesRegex);
      if (bytesMatch) {
        const [_type, size_] = bytesMatch;
        if (size_ && size(value) !== Number.parseInt(size_))
          throw new BytesSizeMismatchError({
            expectedSize: Number.parseInt(size_),
            givenSize: size(value)
          });
      }
      const struct2 = types[type];
      if (struct2) {
        validateReference(type);
        validateData(struct2, value);
      }
    }
  };
  if (types.EIP712Domain && domain) {
    if (typeof domain !== "object")
      throw new InvalidDomainError({ domain });
    validateData(types.EIP712Domain, domain);
  }
  if (primaryType !== "EIP712Domain") {
    if (types[primaryType])
      validateData(types[primaryType], message);
    else
      throw new InvalidPrimaryTypeError({ primaryType, types });
  }
}
function getTypesForEIP712Domain({ domain }) {
  return [
    typeof domain?.name === "string" && { name: "name", type: "string" },
    domain?.version && { name: "version", type: "string" },
    typeof domain?.chainId === "number" && {
      name: "chainId",
      type: "uint256"
    },
    domain?.verifyingContract && {
      name: "verifyingContract",
      type: "address"
    },
    domain?.salt && { name: "salt", type: "bytes32" }
  ].filter(Boolean);
}
function domainSeparator({ domain }) {
  return hashDomain({
    domain,
    types: {
      EIP712Domain: getTypesForEIP712Domain({ domain })
    }
  });
}
var validateReference = function(type) {
  if (type === "address" || type === "bool" || type === "string" || type.startsWith("bytes") || type.startsWith("uint") || type.startsWith("int"))
    throw new InvalidStructTypeError({ type });
};

// node_modules/viem/_esm/utils/signature/hashTypedData.js
function hashTypedData2(parameters) {
  const { domain = {}, message, primaryType } = parameters;
  const types = {
    EIP712Domain: getTypesForEIP712Domain({ domain }),
    ...parameters.types
  };
  validateTypedData({
    domain,
    message,
    primaryType,
    types
  });
  const parts = ["0x1901"];
  if (domain)
    parts.push(hashDomain({
      domain,
      types
    }));
  if (primaryType !== "EIP712Domain")
    parts.push(hashStruct({
      data: message,
      primaryType,
      types
    }));
  return keccak256(concat(parts));
}
function hashDomain({ domain, types }) {
  return hashStruct({
    data: domain,
    primaryType: "EIP712Domain",
    types
  });
}
function hashStruct({ data: data3, primaryType, types }) {
  const encoded = encodeData({
    data: data3,
    primaryType,
    types
  });
  return keccak256(encoded);
}
var encodeData = function({ data: data3, primaryType, types }) {
  const encodedTypes = [{ type: "bytes32" }];
  const encodedValues = [hashType({ primaryType, types })];
  for (const field of types[primaryType]) {
    const [type, value] = encodeField({
      types,
      name: field.name,
      type: field.type,
      value: data3[field.name]
    });
    encodedTypes.push(type);
    encodedValues.push(value);
  }
  return encodeAbiParameters(encodedTypes, encodedValues);
};
var hashType = function({ primaryType, types }) {
  const encodedHashType = toHex2(encodeType({ primaryType, types }));
  return keccak256(encodedHashType);
};
function encodeType({ primaryType, types }) {
  let result = "";
  const unsortedDeps = findTypeDependencies({ primaryType, types });
  unsortedDeps.delete(primaryType);
  const deps = [primaryType, ...Array.from(unsortedDeps).sort()];
  for (const type of deps) {
    result += `${type}(${types[type].map(({ name, type: t }) => `${t} ${name}`).join(",")})`;
  }
  return result;
}
var findTypeDependencies = function({ primaryType: primaryType_, types }, results = new Set) {
  const match = primaryType_.match(/^\w*/u);
  const primaryType = match?.[0];
  if (results.has(primaryType) || types[primaryType] === undefined) {
    return results;
  }
  results.add(primaryType);
  for (const field of types[primaryType]) {
    findTypeDependencies({ primaryType: field.type, types }, results);
  }
  return results;
};
var encodeField = function({ types, name, type, value }) {
  if (types[type] !== undefined) {
    return [
      { type: "bytes32" },
      keccak256(encodeData({ data: value, primaryType: type, types }))
    ];
  }
  if (type === "bytes") {
    const prepend = value.length % 2 ? "0" : "";
    value = `0x${prepend + value.slice(2)}`;
    return [{ type: "bytes32" }, keccak256(value)];
  }
  if (type === "string")
    return [{ type: "bytes32" }, keccak256(toHex2(value))];
  if (type.lastIndexOf("]") === type.length - 1) {
    const parsedType = type.slice(0, type.lastIndexOf("["));
    const typeValuePairs = value.map((item) => encodeField({
      name,
      type: parsedType,
      types,
      value: item
    }));
    return [
      { type: "bytes32" },
      keccak256(encodeAbiParameters(typeValuePairs.map(([t]) => t), typeValuePairs.map(([, v]) => v)))
    ];
  }
  return [{ type }, value];
};

// node_modules/viem/_esm/accounts/utils/signTypedData.js
async function signTypedData(parameters) {
  const { privateKey, ...typedData3 } = parameters;
  return await sign({
    hash: hashTypedData2(typedData3),
    privateKey,
    to: "hex"
  });
}

// node_modules/viem/_esm/accounts/privateKeyToAccount.js
function privateKeyToAccount(privateKey, options = {}) {
  const { nonceManager } = options;
  const publicKey = toHex2(secp256k1.getPublicKey(privateKey.slice(2), false));
  const address7 = publicKeyToAddress(publicKey);
  const account = toAccount({
    address: address7,
    nonceManager,
    async sign({ hash: hash2 }) {
      return sign({ hash: hash2, privateKey, to: "hex" });
    },
    async experimental_signAuthorization(authorization) {
      return experimental_signAuthorization({ ...authorization, privateKey });
    },
    async signMessage({ message }) {
      return signMessage({ message, privateKey });
    },
    async signTransaction(transaction4, { serializer } = {}) {
      return signTransaction({ privateKey, transaction: transaction4, serializer });
    },
    async signTypedData(typedData3) {
      return signTypedData({ ...typedData3, privateKey });
    }
  });
  return {
    ...account,
    publicKey,
    source: "privateKey"
  };
}
// node_modules/viem/_esm/actions/public/getTransactionCount.js
init_fromHex();
init_toHex();
async function getTransactionCount(client, { address: address7, blockTag = "latest", blockNumber }) {
  const count = await client.request({
    method: "eth_getTransactionCount",
    params: [address7, blockNumber ? numberToHex(blockNumber) : blockTag]
  }, { dedupe: Boolean(blockNumber) });
  return hexToNumber2(count);
}

// node_modules/viem/_esm/utils/nonceManager.js
init_lru();
function createNonceManager(parameters) {
  const { source } = parameters;
  const deltaMap = new Map;
  const nonceMap = new LruMap(8192);
  const promiseMap = new Map;
  const getKey = ({ address: address7, chainId }) => `${address7}.${chainId}`;
  return {
    async consume({ address: address7, chainId, client }) {
      const key = getKey({ address: address7, chainId });
      const promise = this.get({ address: address7, chainId, client });
      this.increment({ address: address7, chainId });
      const nonce = await promise;
      await source.set({ address: address7, chainId }, nonce);
      nonceMap.set(key, nonce);
      return nonce;
    },
    async increment({ address: address7, chainId }) {
      const key = getKey({ address: address7, chainId });
      const delta = deltaMap.get(key) ?? 0;
      deltaMap.set(key, delta + 1);
    },
    async get({ address: address7, chainId, client }) {
      const key = getKey({ address: address7, chainId });
      let promise = promiseMap.get(key);
      if (!promise) {
        promise = (async () => {
          try {
            const nonce = await source.get({ address: address7, chainId, client });
            const previousNonce = nonceMap.get(key) ?? 0;
            if (previousNonce > 0 && nonce <= previousNonce)
              return previousNonce + 1;
            nonceMap.delete(key);
            return nonce;
          } finally {
            this.reset({ address: address7, chainId });
          }
        })();
        promiseMap.set(key, promise);
      }
      const delta = deltaMap.get(key) ?? 0;
      return delta + await promise;
    },
    reset({ address: address7, chainId }) {
      const key = getKey({ address: address7, chainId });
      deltaMap.delete(key);
      promiseMap.delete(key);
    }
  };
}
function jsonRpc() {
  return {
    async get(parameters) {
      const { address: address7, client } = parameters;
      return getTransactionCount(client, {
        address: address7,
        blockTag: "pending"
      });
    },
    set() {
    }
  };
}
var nonceManager = createNonceManager({
  source: jsonRpc()
});

// node_modules/viem/_esm/index.js
init_exports();

// node_modules/viem/_esm/utils/getAction.js
function getAction(client, actionFn, name) {
  const action_implicit = client[actionFn.name];
  if (typeof action_implicit === "function")
    return action_implicit;
  const action_explicit = client[name];
  if (typeof action_explicit === "function")
    return action_explicit;
  return (params) => actionFn(client, params);
}

// node_modules/viem/_esm/utils/abi/encodeEventTopics.js
init_abi();

// node_modules/viem/_esm/errors/log.js
init_base();

class FilterTypeNotSupportedError extends BaseError {
  constructor(type) {
    super(`Filter type "${type}" is not supported.`, {
      name: "FilterTypeNotSupportedError"
    });
  }
}

// node_modules/viem/_esm/utils/abi/encodeEventTopics.js
init_toBytes();
init_keccak256();
init_toEventSelector();
init_encodeAbiParameters();
init_formatAbiItem();
init_getAbiItem();
function encodeEventTopics(parameters) {
  const { abi: abi6, eventName, args } = parameters;
  let abiItem3 = abi6[0];
  if (eventName) {
    const item = getAbiItem({ abi: abi6, name: eventName });
    if (!item)
      throw new AbiEventNotFoundError(eventName, { docsPath });
    abiItem3 = item;
  }
  if (abiItem3.type !== "event")
    throw new AbiEventNotFoundError(undefined, { docsPath });
  const definition = formatAbiItem(abiItem3);
  const signature3 = toEventSelector(definition);
  let topics = [];
  if (args && ("inputs" in abiItem3)) {
    const indexedInputs = abiItem3.inputs?.filter((param) => ("indexed" in param) && param.indexed);
    const args_ = Array.isArray(args) ? args : Object.values(args).length > 0 ? indexedInputs?.map((x) => args[x.name]) ?? [] : [];
    if (args_.length > 0) {
      topics = indexedInputs?.map((param, i) => {
        if (Array.isArray(args_[i]))
          return args_[i].map((_, j) => encodeArg({ param, value: args_[i][j] }));
        return args_[i] ? encodeArg({ param, value: args_[i] }) : null;
      }) ?? [];
    }
  }
  return [signature3, ...topics];
}
var encodeArg = function({ param, value }) {
  if (param.type === "string" || param.type === "bytes")
    return keccak256(toBytes2(value));
  if (param.type === "tuple" || param.type.match(/^(.*)\[(\d+)?\]$/))
    throw new FilterTypeNotSupportedError(param.type);
  return encodeAbiParameters([param], [value]);
};
var docsPath = "/docs/contract/encodeEventTopics";

// node_modules/viem/_esm/actions/public/createContractEventFilter.js
init_toHex();

// node_modules/viem/_esm/utils/filters/createFilterRequestScope.js
function createFilterRequestScope(client, { method }) {
  const requestMap = {};
  if (client.transport.type === "fallback")
    client.transport.onResponse?.(({ method: method_, response: id, status, transport }) => {
      if (status === "success" && method === method_)
        requestMap[id] = transport.request;
    });
  return (id) => requestMap[id] || client.request;
}

// node_modules/viem/_esm/actions/public/createContractEventFilter.js
async function createContractEventFilter(client, parameters) {
  const { address: address7, abi: abi6, args, eventName, fromBlock, strict, toBlock } = parameters;
  const getRequest = createFilterRequestScope(client, {
    method: "eth_newFilter"
  });
  const topics = eventName ? encodeEventTopics({
    abi: abi6,
    args,
    eventName
  }) : undefined;
  const id = await client.request({
    method: "eth_newFilter",
    params: [
      {
        address: address7,
        fromBlock: typeof fromBlock === "bigint" ? numberToHex(fromBlock) : fromBlock,
        toBlock: typeof toBlock === "bigint" ? numberToHex(toBlock) : toBlock,
        topics
      }
    ]
  });
  return {
    abi: abi6,
    args,
    eventName,
    id,
    request: getRequest(id),
    strict: Boolean(strict),
    type: "event"
  };
}

// node_modules/viem/_esm/actions/public/estimateContractGas.js
init_parseAccount();
init_encodeFunctionData();

// node_modules/viem/_esm/utils/errors/getContractError.js
init_abi();
init_base();
init_contract();
init_rpc();
function getContractError(err, { abi: abi11, address: address7, args, docsPath: docsPath3, functionName, sender }) {
  const { code, data: data3, message, shortMessage } = err instanceof RawContractError ? err : err instanceof BaseError ? err.walk((err2) => ("data" in err2)) || err.walk() : {};
  const cause = (() => {
    if (err instanceof AbiDecodingZeroDataError)
      return new ContractFunctionZeroDataError({ functionName });
    if ([EXECUTION_REVERTED_ERROR_CODE, InternalRpcError.code].includes(code) && (data3 || message || shortMessage)) {
      return new ContractFunctionRevertedError({
        abi: abi11,
        data: typeof data3 === "object" ? data3.data : data3,
        functionName,
        message: shortMessage ?? message
      });
    }
    return err;
  })();
  return new ContractFunctionExecutionError(cause, {
    abi: abi11,
    args,
    contractAddress: address7,
    docsPath: docsPath3,
    functionName,
    sender
  });
}
var EXECUTION_REVERTED_ERROR_CODE = 3;

// node_modules/viem/_esm/actions/public/estimateGas.js
init_parseAccount();
init_base();

// node_modules/viem/_esm/utils/signature/recoverPublicKey.js
init_isHex();
init_fromHex();
init_toHex();
async function recoverPublicKey({ hash: hash3, signature: signature3 }) {
  const hashHex = isHex(hash3) ? hash3 : toHex2(hash3);
  const { secp256k1: secp256k15 } = await Promise.resolve().then(() => (init_secp256k1(), exports_secp256k1));
  const signature_ = (() => {
    if (typeof signature3 === "object" && ("r" in signature3) && ("s" in signature3)) {
      const { r, s, v, yParity } = signature3;
      const yParityOrV2 = Number(yParity ?? v);
      const recoveryBit2 = toRecoveryBit(yParityOrV2);
      return new secp256k15.Signature(hexToBigInt(r), hexToBigInt(s)).addRecoveryBit(recoveryBit2);
    }
    const signatureHex = isHex(signature3) ? signature3 : toHex2(signature3);
    const yParityOrV = hexToNumber2(`0x${signatureHex.slice(130)}`);
    const recoveryBit = toRecoveryBit(yParityOrV);
    return secp256k15.Signature.fromCompact(signatureHex.substring(2, 130)).addRecoveryBit(recoveryBit);
  })();
  const publicKey = signature_.recoverPublicKey(hashHex.substring(2)).toHex(false);
  return `0x${publicKey}`;
}
var toRecoveryBit = function(yParityOrV) {
  if (yParityOrV === 0 || yParityOrV === 1)
    return yParityOrV;
  if (yParityOrV === 27)
    return 0;
  if (yParityOrV === 28)
    return 1;
  throw new Error("Invalid yParityOrV value");
};

// node_modules/viem/_esm/utils/signature/recoverAddress.js
async function recoverAddress({ hash: hash3, signature: signature3 }) {
  return publicKeyToAddress(await recoverPublicKey({ hash: hash3, signature: signature3 }));
}

// node_modules/viem/_esm/experimental/eip7702/utils/recoverAuthorizationAddress.js
async function recoverAuthorizationAddress(parameters) {
  const { authorization, signature: signature3 } = parameters;
  return recoverAddress({
    hash: hashAuthorization(authorization),
    signature: signature3 ?? authorization
  });
}

// node_modules/viem/_esm/actions/public/estimateGas.js
init_toHex();

// node_modules/viem/_esm/errors/estimateGas.js
init_formatEther();
init_formatGwei();
init_base();
init_transaction();

class EstimateGasExecutionError extends BaseError {
  constructor(cause, { account, docsPath: docsPath3, chain: chain2, data: data3, gas, gasPrice, maxFeePerGas, maxPriorityFeePerGas, nonce, to, value }) {
    const prettyArgs = prettyPrint({
      from: account?.address,
      to,
      value: typeof value !== "undefined" && `${formatEther(value)} ${chain2?.nativeCurrency?.symbol || "ETH"}`,
      data: data3,
      gas,
      gasPrice: typeof gasPrice !== "undefined" && `${formatGwei(gasPrice)} gwei`,
      maxFeePerGas: typeof maxFeePerGas !== "undefined" && `${formatGwei(maxFeePerGas)} gwei`,
      maxPriorityFeePerGas: typeof maxPriorityFeePerGas !== "undefined" && `${formatGwei(maxPriorityFeePerGas)} gwei`,
      nonce
    });
    super(cause.shortMessage, {
      cause,
      docsPath: docsPath3,
      metaMessages: [
        ...cause.metaMessages ? [...cause.metaMessages, " "] : [],
        "Estimate Gas Arguments:",
        prettyArgs
      ].filter(Boolean),
      name: "EstimateGasExecutionError"
    });
    Object.defineProperty(this, "cause", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.cause = cause;
  }
}

// node_modules/viem/_esm/utils/errors/getEstimateGasError.js
init_node();
init_getNodeError();
function getEstimateGasError(err, { docsPath: docsPath3, ...args }) {
  const cause = (() => {
    const cause2 = getNodeError(err, args);
    if (cause2 instanceof UnknownNodeError)
      return err;
    return cause2;
  })();
  return new EstimateGasExecutionError(cause, {
    docsPath: docsPath3,
    ...args
  });
}

// node_modules/viem/_esm/actions/public/estimateGas.js
init_extract();
init_transactionRequest();
init_stateOverride2();
init_assertRequest();

// node_modules/viem/_esm/actions/wallet/prepareTransactionRequest.js
init_parseAccount();

// node_modules/viem/_esm/errors/fee.js
init_formatGwei();
init_base();

class BaseFeeScalarError extends BaseError {
  constructor() {
    super("`baseFeeMultiplier` must be greater than 1.", {
      name: "BaseFeeScalarError"
    });
  }
}

class Eip1559FeesNotSupportedError extends BaseError {
  constructor() {
    super("Chain does not support EIP-1559 fees.", {
      name: "Eip1559FeesNotSupportedError"
    });
  }
}

class MaxFeePerGasTooLowError extends BaseError {
  constructor({ maxPriorityFeePerGas }) {
    super(`\`maxFeePerGas\` cannot be less than the \`maxPriorityFeePerGas\` (${formatGwei(maxPriorityFeePerGas)} gwei).`, { name: "MaxFeePerGasTooLowError" });
  }
}

// node_modules/viem/_esm/actions/public/estimateMaxPriorityFeePerGas.js
init_fromHex();

// node_modules/viem/_esm/errors/block.js
init_base();

class BlockNotFoundError extends BaseError {
  constructor({ blockHash, blockNumber }) {
    let identifier = "Block";
    if (blockHash)
      identifier = `Block at hash "${blockHash}"`;
    if (blockNumber)
      identifier = `Block at number "${blockNumber}"`;
    super(`${identifier} could not be found.`, { name: "BlockNotFoundError" });
  }
}

// node_modules/viem/_esm/actions/public/getBlock.js
init_toHex();

// node_modules/viem/_esm/utils/formatters/block.js
init_formatter();

// node_modules/viem/_esm/utils/formatters/transaction.js
init_fromHex();
init_formatter();
function formatTransaction(transaction7) {
  const transaction_ = {
    ...transaction7,
    blockHash: transaction7.blockHash ? transaction7.blockHash : null,
    blockNumber: transaction7.blockNumber ? BigInt(transaction7.blockNumber) : null,
    chainId: transaction7.chainId ? hexToNumber2(transaction7.chainId) : undefined,
    gas: transaction7.gas ? BigInt(transaction7.gas) : undefined,
    gasPrice: transaction7.gasPrice ? BigInt(transaction7.gasPrice) : undefined,
    maxFeePerBlobGas: transaction7.maxFeePerBlobGas ? BigInt(transaction7.maxFeePerBlobGas) : undefined,
    maxFeePerGas: transaction7.maxFeePerGas ? BigInt(transaction7.maxFeePerGas) : undefined,
    maxPriorityFeePerGas: transaction7.maxPriorityFeePerGas ? BigInt(transaction7.maxPriorityFeePerGas) : undefined,
    nonce: transaction7.nonce ? hexToNumber2(transaction7.nonce) : undefined,
    to: transaction7.to ? transaction7.to : null,
    transactionIndex: transaction7.transactionIndex ? Number(transaction7.transactionIndex) : null,
    type: transaction7.type ? transactionType[transaction7.type] : undefined,
    typeHex: transaction7.type ? transaction7.type : undefined,
    value: transaction7.value ? BigInt(transaction7.value) : undefined,
    v: transaction7.v ? BigInt(transaction7.v) : undefined
  };
  if (transaction7.authorizationList)
    transaction_.authorizationList = formatAuthorizationList2(transaction7.authorizationList);
  transaction_.yParity = (() => {
    if (transaction7.yParity)
      return Number(transaction7.yParity);
    if (typeof transaction_.v === "bigint") {
      if (transaction_.v === 0n || transaction_.v === 27n)
        return 0;
      if (transaction_.v === 1n || transaction_.v === 28n)
        return 1;
      if (transaction_.v >= 35n)
        return transaction_.v % 2n === 0n ? 1 : 0;
    }
    return;
  })();
  if (transaction_.type === "legacy") {
    delete transaction_.accessList;
    delete transaction_.maxFeePerBlobGas;
    delete transaction_.maxFeePerGas;
    delete transaction_.maxPriorityFeePerGas;
    delete transaction_.yParity;
  }
  if (transaction_.type === "eip2930") {
    delete transaction_.maxFeePerBlobGas;
    delete transaction_.maxFeePerGas;
    delete transaction_.maxPriorityFeePerGas;
  }
  if (transaction_.type === "eip1559") {
    delete transaction_.maxFeePerBlobGas;
  }
  return transaction_;
}
var formatAuthorizationList2 = function(authorizationList) {
  return authorizationList.map((authorization) => ({
    contractAddress: authorization.address,
    chainId: Number(authorization.chainId),
    nonce: Number(authorization.nonce),
    r: authorization.r,
    s: authorization.s,
    yParity: Number(authorization.yParity)
  }));
};
var transactionType = {
  "0x0": "legacy",
  "0x1": "eip2930",
  "0x2": "eip1559",
  "0x3": "eip4844",
  "0x4": "eip7702"
};
var defineTransaction = defineFormatter("transaction", formatTransaction);

// node_modules/viem/_esm/utils/formatters/block.js
function formatBlock(block) {
  const transactions = (block.transactions ?? []).map((transaction8) => {
    if (typeof transaction8 === "string")
      return transaction8;
    return formatTransaction(transaction8);
  });
  return {
    ...block,
    baseFeePerGas: block.baseFeePerGas ? BigInt(block.baseFeePerGas) : null,
    blobGasUsed: block.blobGasUsed ? BigInt(block.blobGasUsed) : undefined,
    difficulty: block.difficulty ? BigInt(block.difficulty) : undefined,
    excessBlobGas: block.excessBlobGas ? BigInt(block.excessBlobGas) : undefined,
    gasLimit: block.gasLimit ? BigInt(block.gasLimit) : undefined,
    gasUsed: block.gasUsed ? BigInt(block.gasUsed) : undefined,
    hash: block.hash ? block.hash : null,
    logsBloom: block.logsBloom ? block.logsBloom : null,
    nonce: block.nonce ? block.nonce : null,
    number: block.number ? BigInt(block.number) : null,
    size: block.size ? BigInt(block.size) : undefined,
    timestamp: block.timestamp ? BigInt(block.timestamp) : undefined,
    transactions,
    totalDifficulty: block.totalDifficulty ? BigInt(block.totalDifficulty) : null
  };
}
var defineBlock = defineFormatter("block", formatBlock);

// node_modules/viem/_esm/actions/public/getBlock.js
async function getBlock(client, { blockHash, blockNumber, blockTag: blockTag_, includeTransactions: includeTransactions_ } = {}) {
  const blockTag = blockTag_ ?? "latest";
  const includeTransactions = includeTransactions_ ?? false;
  const blockNumberHex = blockNumber !== undefined ? numberToHex(blockNumber) : undefined;
  let block3 = null;
  if (blockHash) {
    block3 = await client.request({
      method: "eth_getBlockByHash",
      params: [blockHash, includeTransactions]
    }, { dedupe: true });
  } else {
    block3 = await client.request({
      method: "eth_getBlockByNumber",
      params: [blockNumberHex || blockTag, includeTransactions]
    }, { dedupe: Boolean(blockNumberHex) });
  }
  if (!block3)
    throw new BlockNotFoundError({ blockHash, blockNumber });
  const format = client.chain?.formatters?.block?.format || formatBlock;
  return format(block3);
}

// node_modules/viem/_esm/actions/public/getGasPrice.js
async function getGasPrice(client) {
  const gasPrice = await client.request({
    method: "eth_gasPrice"
  });
  return BigInt(gasPrice);
}

// node_modules/viem/_esm/actions/public/estimateMaxPriorityFeePerGas.js
async function estimateMaxPriorityFeePerGas(client, args) {
  return internal_estimateMaxPriorityFeePerGas(client, args);
}
async function internal_estimateMaxPriorityFeePerGas(client, args) {
  const { block: block_, chain: chain2 = client.chain, request: request4 } = args || {};
  try {
    const maxPriorityFeePerGas = chain2?.fees?.maxPriorityFeePerGas ?? chain2?.fees?.defaultPriorityFee;
    if (typeof maxPriorityFeePerGas === "function") {
      const block3 = block_ || await getAction(client, getBlock, "getBlock")({});
      const maxPriorityFeePerGas_ = await maxPriorityFeePerGas({
        block: block3,
        client,
        request: request4
      });
      if (maxPriorityFeePerGas_ === null)
        throw new Error;
      return maxPriorityFeePerGas_;
    }
    if (typeof maxPriorityFeePerGas !== "undefined")
      return maxPriorityFeePerGas;
    const maxPriorityFeePerGasHex = await client.request({
      method: "eth_maxPriorityFeePerGas"
    });
    return hexToBigInt(maxPriorityFeePerGasHex);
  } catch {
    const [block3, gasPrice] = await Promise.all([
      block_ ? Promise.resolve(block_) : getAction(client, getBlock, "getBlock")({}),
      getAction(client, getGasPrice, "getGasPrice")({})
    ]);
    if (typeof block3.baseFeePerGas !== "bigint")
      throw new Eip1559FeesNotSupportedError;
    const maxPriorityFeePerGas = gasPrice - block3.baseFeePerGas;
    if (maxPriorityFeePerGas < 0n)
      return 0n;
    return maxPriorityFeePerGas;
  }
}

// node_modules/viem/_esm/actions/public/estimateFeesPerGas.js
async function estimateFeesPerGas(client, args) {
  return internal_estimateFeesPerGas(client, args);
}
async function internal_estimateFeesPerGas(client, args) {
  const { block: block_, chain: chain2 = client.chain, request: request4, type = "eip1559" } = args || {};
  const baseFeeMultiplier = await (async () => {
    if (typeof chain2?.fees?.baseFeeMultiplier === "function")
      return chain2.fees.baseFeeMultiplier({
        block: block_,
        client,
        request: request4
      });
    return chain2?.fees?.baseFeeMultiplier ?? 1.2;
  })();
  if (baseFeeMultiplier < 1)
    throw new BaseFeeScalarError;
  const decimals = baseFeeMultiplier.toString().split(".")[1]?.length ?? 0;
  const denominator = 10 ** decimals;
  const multiply = (base26) => base26 * BigInt(Math.ceil(baseFeeMultiplier * denominator)) / BigInt(denominator);
  const block3 = block_ ? block_ : await getAction(client, getBlock, "getBlock")({});
  if (typeof chain2?.fees?.estimateFeesPerGas === "function") {
    const fees = await chain2.fees.estimateFeesPerGas({
      block: block_,
      client,
      multiply,
      request: request4,
      type
    });
    if (fees !== null)
      return fees;
  }
  if (type === "eip1559") {
    if (typeof block3.baseFeePerGas !== "bigint")
      throw new Eip1559FeesNotSupportedError;
    const maxPriorityFeePerGas = typeof request4?.maxPriorityFeePerGas === "bigint" ? request4.maxPriorityFeePerGas : await internal_estimateMaxPriorityFeePerGas(client, {
      block: block3,
      chain: chain2,
      request: request4
    });
    const baseFeePerGas = multiply(block3.baseFeePerGas);
    const maxFeePerGas = request4?.maxFeePerGas ?? baseFeePerGas + maxPriorityFeePerGas;
    return {
      maxFeePerGas,
      maxPriorityFeePerGas
    };
  }
  const gasPrice = request4?.gasPrice ?? multiply(await getAction(client, getGasPrice, "getGasPrice")({}));
  return {
    gasPrice
  };
}

// node_modules/viem/_esm/actions/wallet/prepareTransactionRequest.js
init_assertRequest();

// node_modules/viem/_esm/actions/public/getChainId.js
init_fromHex();
async function getChainId(client) {
  const chainIdHex = await client.request({
    method: "eth_chainId"
  }, { dedupe: true });
  return hexToNumber2(chainIdHex);
}

// node_modules/viem/_esm/actions/wallet/prepareTransactionRequest.js
async function prepareTransactionRequest(client, args) {
  const { account: account_ = client.account, blobs, chain: chain2, gas, kzg: kzg3, nonce, nonceManager: nonceManager2, parameters = defaultParameters, type } = args;
  const account = account_ ? parseAccount(account_) : account_;
  const request4 = { ...args, ...account ? { from: account?.address } : {} };
  let block3;
  async function getBlock5() {
    if (block3)
      return block3;
    block3 = await getAction(client, getBlock, "getBlock")({ blockTag: "latest" });
    return block3;
  }
  let chainId;
  async function getChainId3() {
    if (chainId)
      return chainId;
    if (chain2)
      return chain2.id;
    if (typeof args.chainId !== "undefined")
      return args.chainId;
    const chainId_ = await getAction(client, getChainId, "getChainId")({});
    chainId = chainId_;
    return chainId;
  }
  if ((parameters.includes("blobVersionedHashes") || parameters.includes("sidecars")) && blobs && kzg3) {
    const commitments = blobsToCommitments({ blobs, kzg: kzg3 });
    if (parameters.includes("blobVersionedHashes")) {
      const versionedHashes = commitmentsToVersionedHashes({
        commitments,
        to: "hex"
      });
      request4.blobVersionedHashes = versionedHashes;
    }
    if (parameters.includes("sidecars")) {
      const proofs = blobsToProofs({ blobs, commitments, kzg: kzg3 });
      const sidecars = toBlobSidecars({
        blobs,
        commitments,
        proofs,
        to: "hex"
      });
      request4.sidecars = sidecars;
    }
  }
  if (parameters.includes("chainId"))
    request4.chainId = await getChainId3();
  if (parameters.includes("nonce") && typeof nonce === "undefined" && account) {
    if (nonceManager2) {
      const chainId2 = await getChainId3();
      request4.nonce = await nonceManager2.consume({
        address: account.address,
        chainId: chainId2,
        client
      });
    } else {
      request4.nonce = await getAction(client, getTransactionCount, "getTransactionCount")({
        address: account.address,
        blockTag: "pending"
      });
    }
  }
  if ((parameters.includes("fees") || parameters.includes("type")) && typeof type === "undefined") {
    try {
      request4.type = getTransactionType(request4);
    } catch {
      const block4 = await getBlock5();
      request4.type = typeof block4?.baseFeePerGas === "bigint" ? "eip1559" : "legacy";
    }
  }
  if (parameters.includes("fees")) {
    if (request4.type !== "legacy" && request4.type !== "eip2930") {
      if (typeof request4.maxFeePerGas === "undefined" || typeof request4.maxPriorityFeePerGas === "undefined") {
        const block4 = await getBlock5();
        const { maxFeePerGas, maxPriorityFeePerGas } = await internal_estimateFeesPerGas(client, {
          block: block4,
          chain: chain2,
          request: request4
        });
        if (typeof args.maxPriorityFeePerGas === "undefined" && args.maxFeePerGas && args.maxFeePerGas < maxPriorityFeePerGas)
          throw new MaxFeePerGasTooLowError({
            maxPriorityFeePerGas
          });
        request4.maxPriorityFeePerGas = maxPriorityFeePerGas;
        request4.maxFeePerGas = maxFeePerGas;
      }
    } else {
      if (typeof args.maxFeePerGas !== "undefined" || typeof args.maxPriorityFeePerGas !== "undefined")
        throw new Eip1559FeesNotSupportedError;
      const block4 = await getBlock5();
      const { gasPrice: gasPrice_ } = await internal_estimateFeesPerGas(client, {
        block: block4,
        chain: chain2,
        request: request4,
        type: "legacy"
      });
      request4.gasPrice = gasPrice_;
    }
  }
  if (parameters.includes("gas") && typeof gas === "undefined")
    request4.gas = await getAction(client, estimateGas3, "estimateGas")({
      ...request4,
      account: account ? { address: account.address, type: "json-rpc" } : account
    });
  assertRequest(request4);
  delete request4.parameters;
  return request4;
}
var defaultParameters = [
  "blobVersionedHashes",
  "chainId",
  "fees",
  "gas",
  "nonce",
  "type"
];

// node_modules/viem/_esm/actions/public/getBalance.js
init_toHex();
async function getBalance(client, { address: address9, blockNumber, blockTag = "latest" }) {
  const blockNumberHex = blockNumber ? numberToHex(blockNumber) : undefined;
  const balance = await client.request({
    method: "eth_getBalance",
    params: [address9, blockNumberHex || blockTag]
  });
  return BigInt(balance);
}

// node_modules/viem/_esm/actions/public/estimateGas.js
async function estimateGas3(client, args) {
  const { account: account_ = client.account } = args;
  const account = account_ ? parseAccount(account_) : undefined;
  try {
    let estimateGas_rpc = function(parameters) {
      const { block: block4, request: request5, rpcStateOverride: rpcStateOverride2 } = parameters;
      return client.request({
        method: "eth_estimateGas",
        params: rpcStateOverride2 ? [request5, block4 ?? "latest", rpcStateOverride2] : block4 ? [request5, block4] : [request5]
      });
    };
    const { accessList, authorizationList, blobs, blobVersionedHashes, blockNumber, blockTag, data: data4, gas, gasPrice, maxFeePerBlobGas, maxFeePerGas, maxPriorityFeePerGas, nonce, value, stateOverride: stateOverride4, ...rest } = await prepareTransactionRequest(client, {
      ...args,
      parameters: account?.type === "local" ? undefined : ["blobVersionedHashes"]
    });
    const blockNumberHex = blockNumber ? numberToHex(blockNumber) : undefined;
    const block3 = blockNumberHex || blockTag;
    const rpcStateOverride = serializeStateOverride(stateOverride4);
    const to = await (async () => {
      if (rest.to)
        return rest.to;
      if (authorizationList && authorizationList.length > 0)
        return await recoverAuthorizationAddress({
          authorization: authorizationList[0]
        }).catch(() => {
          throw new BaseError("`to` is required. Could not infer from `authorizationList`");
        });
      return;
    })();
    assertRequest(args);
    const chainFormat = client.chain?.formatters?.transactionRequest?.format;
    const format = chainFormat || formatTransactionRequest;
    const request4 = format({
      ...extract(rest, { format: chainFormat }),
      from: account?.address,
      accessList,
      authorizationList,
      blobs,
      blobVersionedHashes,
      data: data4,
      gas,
      gasPrice,
      maxFeePerBlobGas,
      maxFeePerGas,
      maxPriorityFeePerGas,
      nonce,
      to,
      value
    });
    let estimate = BigInt(await estimateGas_rpc({ block: block3, request: request4, rpcStateOverride }));
    if (authorizationList) {
      const value2 = await getBalance(client, { address: request4.from });
      const estimates = await Promise.all(authorizationList.map(async (authorization) => {
        const { contractAddress } = authorization;
        const estimate2 = await estimateGas_rpc({
          block: block3,
          request: {
            authorizationList: undefined,
            data: data4,
            from: account?.address,
            to: contractAddress,
            value: numberToHex(value2)
          },
          rpcStateOverride
        }).catch(() => 100000n);
        return 2n * BigInt(estimate2);
      }));
      estimate += estimates.reduce((acc, curr) => acc + curr, 0n);
    }
    return estimate;
  } catch (err) {
    throw getEstimateGasError(err, {
      ...args,
      account,
      chain: client.chain
    });
  }
}

// node_modules/viem/_esm/actions/public/estimateContractGas.js
async function estimateContractGas(client, parameters) {
  const { abi: abi11, address: address9, args, functionName, ...request4 } = parameters;
  const data4 = encodeFunctionData({
    abi: abi11,
    args,
    functionName
  });
  try {
    const gas = await getAction(client, estimateGas3, "estimateGas")({
      data: data4,
      to: address9,
      ...request4
    });
    return gas;
  } catch (error) {
    const account = request4.account ? parseAccount(request4.account) : undefined;
    throw getContractError(error, {
      abi: abi11,
      address: address9,
      args,
      docsPath: "/docs/contract/estimateContractGas",
      functionName,
      sender: account?.address
    });
  }
}

// node_modules/viem/_esm/actions/public/getContractEvents.js
init_getAbiItem();

// node_modules/viem/_esm/utils/abi/parseEventLogs.js
init_abi();
init_isAddressEqual();
init_toBytes();
init_keccak256();
init_toEventSelector();

// node_modules/viem/_esm/utils/abi/decodeEventLog.js
init_abi();
init_size();
init_toEventSelector();
init_cursor();
init_decodeAbiParameters();
init_formatAbiItem();
function decodeEventLog(parameters) {
  const { abi: abi12, data: data4, strict: strict_, topics } = parameters;
  const strict = strict_ ?? true;
  const [signature3, ...argTopics] = topics;
  if (!signature3)
    throw new AbiEventSignatureEmptyTopicsError({ docsPath: docsPath3 });
  const abiItem3 = (() => {
    if (abi12.length === 1)
      return abi12[0];
    return abi12.find((x) => x.type === "event" && signature3 === toEventSelector(formatAbiItem(x)));
  })();
  if (!(abiItem3 && ("name" in abiItem3)) || abiItem3.type !== "event")
    throw new AbiEventSignatureNotFoundError(signature3, { docsPath: docsPath3 });
  const { name, inputs } = abiItem3;
  const isUnnamed = inputs?.some((x) => !(("name" in x) && x.name));
  let args = isUnnamed ? [] : {};
  const indexedInputs = inputs.filter((x) => ("indexed" in x) && x.indexed);
  for (let i = 0;i < indexedInputs.length; i++) {
    const param = indexedInputs[i];
    const topic = argTopics[i];
    if (!topic)
      throw new DecodeLogTopicsMismatch({
        abiItem: abiItem3,
        param
      });
    args[isUnnamed ? i : param.name || i] = decodeTopic({ param, value: topic });
  }
  const nonIndexedInputs = inputs.filter((x) => !(("indexed" in x) && x.indexed));
  if (nonIndexedInputs.length > 0) {
    if (data4 && data4 !== "0x") {
      try {
        const decodedData = decodeAbiParameters(nonIndexedInputs, data4);
        if (decodedData) {
          if (isUnnamed)
            args = [...args, ...decodedData];
          else {
            for (let i = 0;i < nonIndexedInputs.length; i++) {
              args[nonIndexedInputs[i].name] = decodedData[i];
            }
          }
        }
      } catch (err) {
        if (strict) {
          if (err instanceof AbiDecodingDataSizeTooSmallError || err instanceof PositionOutOfBoundsError)
            throw new DecodeLogDataMismatch({
              abiItem: abiItem3,
              data: data4,
              params: nonIndexedInputs,
              size: size(data4)
            });
          throw err;
        }
      }
    } else if (strict) {
      throw new DecodeLogDataMismatch({
        abiItem: abiItem3,
        data: "0x",
        params: nonIndexedInputs,
        size: 0
      });
    }
  }
  return {
    eventName: name,
    args: Object.values(args).length > 0 ? args : undefined
  };
}
var decodeTopic = function({ param, value }) {
  if (param.type === "string" || param.type === "bytes" || param.type === "tuple" || param.type.match(/^(.*)\[(\d+)?\]$/))
    return value;
  const decodedArg = decodeAbiParameters([param], value) || [];
  return decodedArg[0];
};
var docsPath3 = "/docs/contract/decodeEventLog";

// node_modules/viem/_esm/utils/abi/parseEventLogs.js
function parseEventLogs(parameters) {
  const { abi: abi13, args, logs, strict = true } = parameters;
  const eventName = (() => {
    if (!parameters.eventName)
      return;
    if (Array.isArray(parameters.eventName))
      return parameters.eventName;
    return [parameters.eventName];
  })();
  return logs.map((log2) => {
    try {
      const abiItem3 = abi13.find((abiItem4) => abiItem4.type === "event" && log2.topics[0] === toEventSelector(abiItem4));
      if (!abiItem3)
        return null;
      const event = decodeEventLog({
        ...log2,
        abi: [abiItem3],
        strict
      });
      if (eventName && !eventName.includes(event.eventName))
        return null;
      if (!includesArgs({
        args: event.args,
        inputs: abiItem3.inputs,
        matchArgs: args
      }))
        return null;
      return { ...event, ...log2 };
    } catch (err) {
      let eventName2;
      let isUnnamed;
      if (err instanceof AbiEventSignatureNotFoundError)
        return null;
      if (err instanceof DecodeLogDataMismatch || err instanceof DecodeLogTopicsMismatch) {
        if (strict)
          return null;
        eventName2 = err.abiItem.name;
        isUnnamed = err.abiItem.inputs?.some((x) => !(("name" in x) && x.name));
      }
      return { ...log2, args: isUnnamed ? [] : {}, eventName: eventName2 };
    }
  }).filter(Boolean);
}
var includesArgs = function(parameters) {
  const { args, inputs, matchArgs } = parameters;
  if (!matchArgs)
    return true;
  if (!args)
    return false;
  function isEqual(input, value, arg) {
    try {
      if (input.type === "address")
        return isAddressEqual(value, arg);
      if (input.type === "string" || input.type === "bytes")
        return keccak256(toBytes2(value)) === arg;
      return value === arg;
    } catch {
      return false;
    }
  }
  if (Array.isArray(args) && Array.isArray(matchArgs)) {
    return matchArgs.every((value, index) => {
      if (value === null || value === undefined)
        return true;
      const input = inputs[index];
      if (!input)
        return false;
      const value_ = Array.isArray(value) ? value : [value];
      return value_.some((value2) => isEqual(input, value2, args[index]));
    });
  }
  if (typeof args === "object" && !Array.isArray(args) && typeof matchArgs === "object" && !Array.isArray(matchArgs))
    return Object.entries(matchArgs).every(([key, value]) => {
      if (value === null || value === undefined)
        return true;
      const input = inputs.find((input2) => input2.name === key);
      if (!input)
        return false;
      const value_ = Array.isArray(value) ? value : [value];
      return value_.some((value2) => isEqual(input, value2, args[key]));
    });
  return false;
};

// node_modules/viem/_esm/actions/public/getLogs.js
init_toHex();

// node_modules/viem/_esm/utils/formatters/log.js
function formatLog(log2, { args, eventName } = {}) {
  return {
    ...log2,
    blockHash: log2.blockHash ? log2.blockHash : null,
    blockNumber: log2.blockNumber ? BigInt(log2.blockNumber) : null,
    logIndex: log2.logIndex ? Number(log2.logIndex) : null,
    transactionHash: log2.transactionHash ? log2.transactionHash : null,
    transactionIndex: log2.transactionIndex ? Number(log2.transactionIndex) : null,
    ...eventName ? { args, eventName } : {}
  };
}

// node_modules/viem/_esm/actions/public/getLogs.js
async function getLogs(client, { address: address10, blockHash, fromBlock, toBlock, event, events: events_, args, strict: strict_ } = {}) {
  const strict = strict_ ?? false;
  const events = events_ ?? (event ? [event] : undefined);
  let topics = [];
  if (events) {
    const encoded = events.flatMap((event2) => encodeEventTopics({
      abi: [event2],
      eventName: event2.name,
      args: events_ ? undefined : args
    }));
    topics = [encoded];
    if (event)
      topics = topics[0];
  }
  let logs;
  if (blockHash) {
    logs = await client.request({
      method: "eth_getLogs",
      params: [{ address: address10, topics, blockHash }]
    });
  } else {
    logs = await client.request({
      method: "eth_getLogs",
      params: [
        {
          address: address10,
          topics,
          fromBlock: typeof fromBlock === "bigint" ? numberToHex(fromBlock) : fromBlock,
          toBlock: typeof toBlock === "bigint" ? numberToHex(toBlock) : toBlock
        }
      ]
    });
  }
  const formattedLogs = logs.map((log3) => formatLog(log3));
  if (!events)
    return formattedLogs;
  return parseEventLogs({
    abi: events,
    args,
    logs: formattedLogs,
    strict
  });
}

// node_modules/viem/_esm/actions/public/getContractEvents.js
async function getContractEvents(client, parameters) {
  const { abi: abi13, address: address10, args, blockHash, eventName, fromBlock, toBlock, strict } = parameters;
  const event = eventName ? getAbiItem({ abi: abi13, name: eventName }) : undefined;
  const events = !event ? abi13.filter((x) => x.type === "event") : undefined;
  return getAction(client, getLogs, "getLogs")({
    address: address10,
    args,
    blockHash,
    event,
    events,
    fromBlock,
    toBlock,
    strict
  });
}

// node_modules/viem/_esm/actions/public/readContract.js
init_decodeFunctionResult();
init_encodeFunctionData();
init_call();
async function readContract(client, parameters) {
  const { abi: abi15, address: address10, args, functionName, ...rest } = parameters;
  const calldata = encodeFunctionData({
    abi: abi15,
    args,
    functionName
  });
  try {
    const { data: data4 } = await getAction(client, call2, "call")({
      ...rest,
      data: calldata,
      to: address10
    });
    return decodeFunctionResult({
      abi: abi15,
      args,
      functionName,
      data: data4 || "0x"
    });
  } catch (error) {
    throw getContractError(error, {
      abi: abi15,
      address: address10,
      args,
      docsPath: "/docs/contract/readContract",
      functionName
    });
  }
}

// node_modules/viem/_esm/actions/public/simulateContract.js
init_parseAccount();
init_decodeFunctionResult();
init_encodeFunctionData();
init_call();
async function simulateContract(client, parameters) {
  const { abi: abi15, address: address10, args, dataSuffix, functionName, ...callRequest } = parameters;
  const account = callRequest.account ? parseAccount(callRequest.account) : client.account;
  const calldata = encodeFunctionData({ abi: abi15, args, functionName });
  try {
    const { data: data4 } = await getAction(client, call2, "call")({
      batch: false,
      data: `${calldata}${dataSuffix ? dataSuffix.replace("0x", "") : ""}`,
      to: address10,
      ...callRequest,
      account
    });
    const result = decodeFunctionResult({
      abi: abi15,
      args,
      functionName,
      data: data4 || "0x"
    });
    const minimizedAbi = abi15.filter((abiItem3) => ("name" in abiItem3) && abiItem3.name === parameters.functionName);
    return {
      result,
      request: {
        abi: minimizedAbi,
        address: address10,
        args,
        dataSuffix,
        functionName,
        ...callRequest,
        account
      }
    };
  } catch (error) {
    throw getContractError(error, {
      abi: abi15,
      address: address10,
      args,
      docsPath: "/docs/contract/simulateContract",
      functionName,
      sender: account?.address
    });
  }
}

// node_modules/viem/_esm/actions/public/watchContractEvent.js
init_abi();
init_rpc();

// node_modules/viem/_esm/utils/observe.js
function observe(observerId, callbacks, fn) {
  const callbackId = ++callbackCount;
  const getListeners = () => listenersCache.get(observerId) || [];
  const unsubscribe = () => {
    const listeners2 = getListeners();
    listenersCache.set(observerId, listeners2.filter((cb) => cb.id !== callbackId));
  };
  const unwatch = () => {
    const cleanup2 = cleanupCache.get(observerId);
    if (getListeners().length === 1 && cleanup2)
      cleanup2();
    unsubscribe();
  };
  const listeners = getListeners();
  listenersCache.set(observerId, [
    ...listeners,
    { id: callbackId, fns: callbacks }
  ]);
  if (listeners && listeners.length > 0)
    return unwatch;
  const emit = {};
  for (const key in callbacks) {
    emit[key] = (...args) => {
      const listeners2 = getListeners();
      if (listeners2.length === 0)
        return;
      for (const listener of listeners2)
        listener.fns[key]?.(...args);
    };
  }
  const cleanup = fn(emit);
  if (typeof cleanup === "function")
    cleanupCache.set(observerId, cleanup);
  return unwatch;
}
var listenersCache = new Map;
var cleanupCache = new Map;
var callbackCount = 0;

// node_modules/viem/_esm/utils/wait.js
async function wait(time) {
  return new Promise((res) => setTimeout(res, time));
}

// node_modules/viem/_esm/utils/poll.js
function poll(fn, { emitOnBegin, initialWaitTime, interval }) {
  let active = true;
  const unwatch = () => active = false;
  const watch = async () => {
    let data4 = undefined;
    if (emitOnBegin)
      data4 = await fn({ unpoll: unwatch });
    const initialWait = await initialWaitTime?.(data4) ?? interval;
    await wait(initialWait);
    const poll2 = async () => {
      if (!active)
        return;
      await fn({ unpoll: unwatch });
      await wait(interval);
      poll2();
    };
    poll2();
  };
  watch();
  return unwatch;
}

// node_modules/viem/_esm/actions/public/watchContractEvent.js
init_stringify();

// node_modules/viem/_esm/utils/promise/withCache.js
function getCache(cacheKey) {
  const buildCache = (cacheKey2, cache2) => ({
    clear: () => cache2.delete(cacheKey2),
    get: () => cache2.get(cacheKey2),
    set: (data4) => cache2.set(cacheKey2, data4)
  });
  const promise = buildCache(cacheKey, promiseCache);
  const response = buildCache(cacheKey, responseCache);
  return {
    clear: () => {
      promise.clear();
      response.clear();
    },
    promise,
    response
  };
}
async function withCache(fn, { cacheKey, cacheTime = Number.POSITIVE_INFINITY }) {
  const cache2 = getCache(cacheKey);
  const response = cache2.response.get();
  if (response && cacheTime > 0) {
    const age = new Date().getTime() - response.created.getTime();
    if (age < cacheTime)
      return response.data;
  }
  let promise = cache2.promise.get();
  if (!promise) {
    promise = fn();
    cache2.promise.set(promise);
  }
  try {
    const data4 = await promise;
    cache2.response.set({ created: new Date, data: data4 });
    return data4;
  } finally {
    cache2.promise.clear();
  }
}
var promiseCache = new Map;
var responseCache = new Map;

// node_modules/viem/_esm/actions/public/getBlockNumber.js
async function getBlockNumber(client, { cacheTime = client.cacheTime } = {}) {
  const blockNumberHex = await withCache(() => client.request({
    method: "eth_blockNumber"
  }), { cacheKey: cacheKey(client.uid), cacheTime });
  return BigInt(blockNumberHex);
}
var cacheKey = (id) => `blockNumber.${id}`;

// node_modules/viem/_esm/actions/public/getFilterChanges.js
async function getFilterChanges(_client, { filter }) {
  const strict = ("strict" in filter) && filter.strict;
  const logs = await filter.request({
    method: "eth_getFilterChanges",
    params: [filter.id]
  });
  if (typeof logs[0] === "string")
    return logs;
  const formattedLogs = logs.map((log4) => formatLog(log4));
  if (!("abi" in filter) || !filter.abi)
    return formattedLogs;
  return parseEventLogs({
    abi: filter.abi,
    logs: formattedLogs,
    strict
  });
}

// node_modules/viem/_esm/actions/public/uninstallFilter.js
async function uninstallFilter(_client, { filter }) {
  return filter.request({
    method: "eth_uninstallFilter",
    params: [filter.id]
  });
}

// node_modules/viem/_esm/actions/public/watchContractEvent.js
function watchContractEvent(client, parameters) {
  const { abi: abi16, address: address10, args, batch = true, eventName, fromBlock, onError, onLogs, poll: poll_, pollingInterval = client.pollingInterval, strict: strict_ } = parameters;
  const enablePolling = (() => {
    if (typeof poll_ !== "undefined")
      return poll_;
    if (typeof fromBlock === "bigint")
      return true;
    if (client.transport.type === "webSocket")
      return false;
    if (client.transport.type === "fallback" && client.transport.transports[0].config.type === "webSocket")
      return false;
    return true;
  })();
  const pollContractEvent = () => {
    const strict = strict_ ?? false;
    const observerId = stringify([
      "watchContractEvent",
      address10,
      args,
      batch,
      client.uid,
      eventName,
      pollingInterval,
      strict,
      fromBlock
    ]);
    return observe(observerId, { onLogs, onError }, (emit) => {
      let previousBlockNumber;
      if (fromBlock !== undefined)
        previousBlockNumber = fromBlock - 1n;
      let filter;
      let initialized = false;
      const unwatch = poll(async () => {
        if (!initialized) {
          try {
            filter = await getAction(client, createContractEventFilter, "createContractEventFilter")({
              abi: abi16,
              address: address10,
              args,
              eventName,
              strict,
              fromBlock
            });
          } catch {
          }
          initialized = true;
          return;
        }
        try {
          let logs;
          if (filter) {
            logs = await getAction(client, getFilterChanges, "getFilterChanges")({ filter });
          } else {
            const blockNumber = await getAction(client, getBlockNumber, "getBlockNumber")({});
            if (previousBlockNumber && previousBlockNumber < blockNumber) {
              logs = await getAction(client, getContractEvents, "getContractEvents")({
                abi: abi16,
                address: address10,
                args,
                eventName,
                fromBlock: previousBlockNumber + 1n,
                toBlock: blockNumber,
                strict
              });
            } else {
              logs = [];
            }
            previousBlockNumber = blockNumber;
          }
          if (logs.length === 0)
            return;
          if (batch)
            emit.onLogs(logs);
          else
            for (const log5 of logs)
              emit.onLogs([log5]);
        } catch (err) {
          if (filter && err instanceof InvalidInputRpcError)
            initialized = false;
          emit.onError?.(err);
        }
      }, {
        emitOnBegin: true,
        interval: pollingInterval
      });
      return async () => {
        if (filter)
          await getAction(client, uninstallFilter, "uninstallFilter")({ filter });
        unwatch();
      };
    });
  };
  const subscribeContractEvent = () => {
    const strict = strict_ ?? false;
    const observerId = stringify([
      "watchContractEvent",
      address10,
      args,
      batch,
      client.uid,
      eventName,
      pollingInterval,
      strict
    ]);
    let active = true;
    let unsubscribe = () => active = false;
    return observe(observerId, { onLogs, onError }, (emit) => {
      (async () => {
        try {
          const transport = (() => {
            if (client.transport.type === "fallback") {
              const transport2 = client.transport.transports.find((transport3) => transport3.config.type === "webSocket");
              if (!transport2)
                return client.transport;
              return transport2.value;
            }
            return client.transport;
          })();
          const topics = eventName ? encodeEventTopics({
            abi: abi16,
            eventName,
            args
          }) : [];
          const { unsubscribe: unsubscribe_ } = await transport.subscribe({
            params: ["logs", { address: address10, topics }],
            onData(data4) {
              if (!active)
                return;
              const log5 = data4.result;
              try {
                const { eventName: eventName2, args: args2 } = decodeEventLog({
                  abi: abi16,
                  data: log5.data,
                  topics: log5.topics,
                  strict: strict_
                });
                const formatted = formatLog(log5, {
                  args: args2,
                  eventName: eventName2
                });
                emit.onLogs([formatted]);
              } catch (err) {
                let eventName2;
                let isUnnamed;
                if (err instanceof DecodeLogDataMismatch || err instanceof DecodeLogTopicsMismatch) {
                  if (strict_)
                    return;
                  eventName2 = err.abiItem.name;
                  isUnnamed = err.abiItem.inputs?.some((x) => !(("name" in x) && x.name));
                }
                const formatted = formatLog(log5, {
                  args: isUnnamed ? [] : {},
                  eventName: eventName2
                });
                emit.onLogs([formatted]);
              }
            },
            onError(error) {
              emit.onError?.(error);
            }
          });
          unsubscribe = unsubscribe_;
          if (!active)
            unsubscribe();
        } catch (err) {
          onError?.(err);
        }
      })();
      return () => unsubscribe();
    });
  };
  return enablePolling ? pollContractEvent() : subscribeContractEvent();
}

// node_modules/viem/_esm/actions/wallet/writeContract.js
init_parseAccount();

// node_modules/viem/_esm/errors/account.js
init_base();

class AccountNotFoundError extends BaseError {
  constructor({ docsPath: docsPath6 } = {}) {
    super([
      "Could not find an Account to execute with this Action.",
      "Please provide an Account with the `account` argument on the Action, or by supplying an `account` to the Client."
    ].join("\n"), {
      docsPath: docsPath6,
      docsSlug: "account",
      name: "AccountNotFoundError"
    });
  }
}

class AccountTypeNotSupportedError extends BaseError {
  constructor({ docsPath: docsPath6, metaMessages, type }) {
    super(`Account type "${type}" is not supported.`, {
      docsPath: docsPath6,
      metaMessages,
      name: "AccountTypeNotSupportedError"
    });
  }
}

// node_modules/viem/_esm/actions/wallet/writeContract.js
init_encodeFunctionData();

// node_modules/viem/_esm/actions/wallet/sendTransaction.js
init_parseAccount();
init_base();

// node_modules/viem/_esm/utils/chain/assertCurrentChain.js
init_chain();
function assertCurrentChain({ chain: chain5, currentChainId }) {
  if (!chain5)
    throw new ChainNotFoundError;
  if (currentChainId !== chain5.id)
    throw new ChainMismatchError({ chain: chain5, currentChainId });
}

// node_modules/viem/_esm/utils/errors/getTransactionError.js
init_node();
init_transaction();
init_getNodeError();
function getTransactionError(err, { docsPath: docsPath6, ...args }) {
  const cause = (() => {
    const cause2 = getNodeError(err, args);
    if (cause2 instanceof UnknownNodeError)
      return err;
    return cause2;
  })();
  return new TransactionExecutionError(cause, {
    docsPath: docsPath6,
    ...args
  });
}

// node_modules/viem/_esm/actions/wallet/sendTransaction.js
init_extract();
init_transactionRequest();
init_lru();
init_assertRequest();

// node_modules/viem/_esm/actions/wallet/sendRawTransaction.js
async function sendRawTransaction(client, { serializedTransaction }) {
  return client.request({
    method: "eth_sendRawTransaction",
    params: [serializedTransaction]
  }, { retryCount: 0 });
}

// node_modules/viem/_esm/actions/wallet/sendTransaction.js
async function sendTransaction(client, parameters) {
  const { account: account_ = client.account, chain: chain5 = client.chain, accessList, authorizationList, blobs, data: data4, gas, gasPrice, maxFeePerBlobGas, maxFeePerGas, maxPriorityFeePerGas, nonce, value, ...rest } = parameters;
  if (typeof account_ === "undefined")
    throw new AccountNotFoundError({
      docsPath: "/docs/actions/wallet/sendTransaction"
    });
  const account2 = account_ ? parseAccount(account_) : null;
  try {
    assertRequest(parameters);
    const to = await (async () => {
      if (parameters.to)
        return parameters.to;
      if (authorizationList && authorizationList.length > 0)
        return await recoverAuthorizationAddress({
          authorization: authorizationList[0]
        }).catch(() => {
          throw new BaseError("`to` is required. Could not infer from `authorizationList`.");
        });
      return;
    })();
    if (account2?.type === "json-rpc" || account2 === null) {
      let chainId;
      if (chain5 !== null) {
        chainId = await getAction(client, getChainId, "getChainId")({});
        assertCurrentChain({
          currentChainId: chainId,
          chain: chain5
        });
      }
      const chainFormat = client.chain?.formatters?.transactionRequest?.format;
      const format = chainFormat || formatTransactionRequest;
      const request5 = format({
        ...extract(rest, { format: chainFormat }),
        accessList,
        authorizationList,
        blobs,
        chainId,
        data: data4,
        from: account2?.address,
        gas,
        gasPrice,
        maxFeePerBlobGas,
        maxFeePerGas,
        maxPriorityFeePerGas,
        nonce,
        to,
        value
      });
      const isWalletNamespaceSupported = supportsWalletNamespace.get(client.uid);
      const method = isWalletNamespaceSupported ? "wallet_sendTransaction" : "eth_sendTransaction";
      try {
        return await client.request({
          method,
          params: [request5]
        }, { retryCount: 0 });
      } catch (e) {
        if (isWalletNamespaceSupported === false)
          throw e;
        const error = e;
        if (error.name === "InvalidInputRpcError" || error.name === "InvalidParamsRpcError" || error.name === "MethodNotFoundRpcError" || error.name === "MethodNotSupportedRpcError") {
          return await client.request({
            method: "wallet_sendTransaction",
            params: [request5]
          }, { retryCount: 0 }).then((hash3) => {
            supportsWalletNamespace.set(client.uid, true);
            return hash3;
          }).catch((e2) => {
            const walletNamespaceError = e2;
            if (walletNamespaceError.name === "MethodNotFoundRpcError" || walletNamespaceError.name === "MethodNotSupportedRpcError") {
              supportsWalletNamespace.set(client.uid, false);
              throw error;
            }
            throw walletNamespaceError;
          });
        }
        throw error;
      }
    }
    if (account2?.type === "local") {
      const request5 = await getAction(client, prepareTransactionRequest, "prepareTransactionRequest")({
        account: account2,
        accessList,
        authorizationList,
        blobs,
        chain: chain5,
        data: data4,
        gas,
        gasPrice,
        maxFeePerBlobGas,
        maxFeePerGas,
        maxPriorityFeePerGas,
        nonce,
        nonceManager: account2.nonceManager,
        parameters: [...defaultParameters, "sidecars"],
        value,
        ...rest,
        to
      });
      const serializer = chain5?.serializers?.transaction;
      const serializedTransaction = await account2.signTransaction(request5, {
        serializer
      });
      return await getAction(client, sendRawTransaction, "sendRawTransaction")({
        serializedTransaction
      });
    }
    if (account2?.type === "smart")
      throw new AccountTypeNotSupportedError({
        metaMessages: [
          "Consider using the `sendUserOperation` Action instead."
        ],
        docsPath: "/docs/actions/bundler/sendUserOperation",
        type: "smart"
      });
    throw new AccountTypeNotSupportedError({
      docsPath: "/docs/actions/wallet/sendTransaction",
      type: account2?.type
    });
  } catch (err) {
    if (err instanceof AccountTypeNotSupportedError)
      throw err;
    throw getTransactionError(err, {
      ...parameters,
      account: account2,
      chain: parameters.chain || undefined
    });
  }
}
var supportsWalletNamespace = new LruMap(128);

// node_modules/viem/_esm/actions/wallet/writeContract.js
async function writeContract(client, parameters) {
  const { abi: abi16, account: account_ = client.account, address: address10, args, dataSuffix, functionName, ...request5 } = parameters;
  if (typeof account_ === "undefined")
    throw new AccountNotFoundError({
      docsPath: "/docs/contract/writeContract"
    });
  const account3 = account_ ? parseAccount(account_) : null;
  const data4 = encodeFunctionData({
    abi: abi16,
    args,
    functionName
  });
  try {
    return await getAction(client, sendTransaction, "sendTransaction")({
      data: `${data4}${dataSuffix ? dataSuffix.replace("0x", "") : ""}`,
      to: address10,
      account: account3,
      ...request5
    });
  } catch (error) {
    throw getContractError(error, {
      abi: abi16,
      address: address10,
      args,
      docsPath: "/docs/contract/writeContract",
      functionName,
      sender: account3?.address
    });
  }
}

// node_modules/viem/_esm/actions/getContract.js
function getContract({ abi: abi16, address: address10, client: client_ }) {
  const client = client_;
  const [publicClient, walletClient] = (() => {
    if (!client)
      return [undefined, undefined];
    if (("public" in client) && ("wallet" in client))
      return [client.public, client.wallet];
    if ("public" in client)
      return [client.public, undefined];
    if ("wallet" in client)
      return [undefined, client.wallet];
    return [client, client];
  })();
  const hasPublicClient = publicClient !== undefined && publicClient !== null;
  const hasWalletClient = walletClient !== undefined && walletClient !== null;
  const contract5 = {};
  let hasReadFunction = false;
  let hasWriteFunction = false;
  let hasEvent = false;
  for (const item of abi16) {
    if (item.type === "function")
      if (item.stateMutability === "view" || item.stateMutability === "pure")
        hasReadFunction = true;
      else
        hasWriteFunction = true;
    else if (item.type === "event")
      hasEvent = true;
    if (hasReadFunction && hasWriteFunction && hasEvent)
      break;
  }
  if (hasPublicClient) {
    if (hasReadFunction)
      contract5.read = new Proxy({}, {
        get(_, functionName) {
          return (...parameters) => {
            const { args, options } = getFunctionParameters(parameters);
            return getAction(publicClient, readContract, "readContract")({
              abi: abi16,
              address: address10,
              functionName,
              args,
              ...options
            });
          };
        }
      });
    if (hasWriteFunction)
      contract5.simulate = new Proxy({}, {
        get(_, functionName) {
          return (...parameters) => {
            const { args, options } = getFunctionParameters(parameters);
            return getAction(publicClient, simulateContract, "simulateContract")({
              abi: abi16,
              address: address10,
              functionName,
              args,
              ...options
            });
          };
        }
      });
    if (hasEvent) {
      contract5.createEventFilter = new Proxy({}, {
        get(_, eventName) {
          return (...parameters) => {
            const abiEvent = abi16.find((x) => x.type === "event" && x.name === eventName);
            const { args, options } = getEventParameters(parameters, abiEvent);
            return getAction(publicClient, createContractEventFilter, "createContractEventFilter")({
              abi: abi16,
              address: address10,
              eventName,
              args,
              ...options
            });
          };
        }
      });
      contract5.getEvents = new Proxy({}, {
        get(_, eventName) {
          return (...parameters) => {
            const abiEvent = abi16.find((x) => x.type === "event" && x.name === eventName);
            const { args, options } = getEventParameters(parameters, abiEvent);
            return getAction(publicClient, getContractEvents, "getContractEvents")({
              abi: abi16,
              address: address10,
              eventName,
              args,
              ...options
            });
          };
        }
      });
      contract5.watchEvent = new Proxy({}, {
        get(_, eventName) {
          return (...parameters) => {
            const abiEvent = abi16.find((x) => x.type === "event" && x.name === eventName);
            const { args, options } = getEventParameters(parameters, abiEvent);
            return getAction(publicClient, watchContractEvent, "watchContractEvent")({
              abi: abi16,
              address: address10,
              eventName,
              args,
              ...options
            });
          };
        }
      });
    }
  }
  if (hasWalletClient) {
    if (hasWriteFunction)
      contract5.write = new Proxy({}, {
        get(_, functionName) {
          return (...parameters) => {
            const { args, options } = getFunctionParameters(parameters);
            return getAction(walletClient, writeContract, "writeContract")({
              abi: abi16,
              address: address10,
              functionName,
              args,
              ...options
            });
          };
        }
      });
  }
  if (hasPublicClient || hasWalletClient) {
    if (hasWriteFunction)
      contract5.estimateGas = new Proxy({}, {
        get(_, functionName) {
          return (...parameters) => {
            const { args, options } = getFunctionParameters(parameters);
            const client2 = publicClient ?? walletClient;
            return getAction(client2, estimateContractGas, "estimateContractGas")({
              abi: abi16,
              address: address10,
              functionName,
              args,
              ...options,
              account: options.account ?? walletClient.account
            });
          };
        }
      });
  }
  contract5.address = address10;
  contract5.abi = abi16;
  return contract5;
}
function getFunctionParameters(values) {
  const hasArgs = values.length && Array.isArray(values[0]);
  const args = hasArgs ? values[0] : [];
  const options = (hasArgs ? values[1] : values[0]) ?? {};
  return { args, options };
}
function getEventParameters(values, abiEvent) {
  let hasArgs = false;
  if (Array.isArray(values[0]))
    hasArgs = true;
  else if (values.length === 1) {
    hasArgs = abiEvent.inputs.some((x) => x.indexed);
  } else if (values.length === 2) {
    hasArgs = true;
  }
  const args = hasArgs ? values[0] : undefined;
  const options = (hasArgs ? values[1] : values[0]) ?? {};
  return { args, options };
}
// node_modules/viem/_esm/errors/eip712.js
init_base();

class Eip712DomainNotFoundError extends BaseError {
  constructor({ address: address10 }) {
    super(`No EIP-712 domain found on contract "${address10}".`, {
      metaMessages: [
        "Ensure that:",
        `- The contract is deployed at the address "${address10}".`,
        "- `eip712Domain()` function exists on the contract.",
        "- `eip712Domain()` function matches signature to ERC-5267 specification."
      ],
      name: "Eip712DomainNotFoundError"
    });
  }
}

// node_modules/viem/_esm/actions/public/getEip712Domain.js
async function getEip712Domain(client, parameters) {
  const { address: address10, factory, factoryData } = parameters;
  try {
    const [fields, name, version5, chainId, verifyingContract, salt, extensions] = await getAction(client, readContract, "readContract")({
      abi: abi16,
      address: address10,
      functionName: "eip712Domain",
      factory,
      factoryData
    });
    return {
      domain: {
        name,
        version: version5,
        chainId: Number(chainId),
        verifyingContract,
        salt
      },
      extensions,
      fields
    };
  } catch (e) {
    const error = e;
    if (error.name === "ContractFunctionExecutionError" && error.cause.name === "ContractFunctionZeroDataError") {
      throw new Eip712DomainNotFoundError({ address: address10 });
    }
    throw error;
  }
}
var abi16 = [
  {
    inputs: [],
    name: "eip712Domain",
    outputs: [
      { name: "fields", type: "bytes1" },
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
      { name: "salt", type: "bytes32" },
      { name: "extensions", type: "uint256[]" }
    ],
    stateMutability: "view",
    type: "function"
  }
];

// node_modules/viem/_esm/actions/wallet/addChain.js
init_toHex();
async function addChain(client, { chain: chain5 }) {
  const { id, name, nativeCurrency, rpcUrls, blockExplorers } = chain5;
  await client.request({
    method: "wallet_addEthereumChain",
    params: [
      {
        chainId: numberToHex(id),
        chainName: name,
        nativeCurrency,
        rpcUrls: rpcUrls.default.http,
        blockExplorerUrls: blockExplorers ? Object.values(blockExplorers).map(({ url: url6 }) => url6) : undefined
      }
    ]
  }, { dedupe: true, retryCount: 0 });
}

// node_modules/viem/_esm/clients/createClient.js
init_parseAccount();

// node_modules/viem/_esm/utils/uid.js
function uid(length = 11) {
  if (!buffer || index + length > size12 * 2) {
    buffer = "";
    index = 0;
    for (let i = 0;i < size12; i++) {
      buffer += (256 + Math.random() * 256 | 0).toString(16).substring(1);
    }
  }
  return buffer.substring(index, index++ + length);
}
var size12 = 256;
var index = size12;
var buffer;

// node_modules/viem/_esm/clients/createClient.js
function createClient(parameters) {
  const { batch, cacheTime = parameters.pollingInterval ?? 4000, ccipRead, key = "base", name = "Base Client", pollingInterval = 4000, type = "base" } = parameters;
  const chain5 = parameters.chain;
  const account3 = parameters.account ? parseAccount(parameters.account) : undefined;
  const { config, request: request5, value } = parameters.transport({
    chain: chain5,
    pollingInterval
  });
  const transport = { ...config, ...value };
  const client = {
    account: account3,
    batch,
    cacheTime,
    ccipRead,
    chain: chain5,
    key,
    name,
    pollingInterval,
    request: request5,
    transport,
    type,
    uid: uid()
  };
  function extend(base32) {
    return (extendFn) => {
      const extended = extendFn(base32);
      for (const key2 in client)
        delete extended[key2];
      const combined = { ...base32, ...extended };
      return Object.assign(combined, { extend: extend(combined) });
    };
  }
  return Object.assign(client, { extend: extend(client) });
}

// node_modules/viem/_esm/utils/buildRequest.js
init_base();
init_request();
init_rpc();
init_toHex();
init_keccak256();

// node_modules/viem/_esm/utils/promise/withDedupe.js
init_lru();
function withDedupe(fn, { enabled = true, id }) {
  if (!enabled || !id)
    return fn();
  if (promiseCache2.get(id))
    return promiseCache2.get(id);
  const promise = fn().finally(() => promiseCache2.delete(id));
  promiseCache2.set(id, promise);
  return promise;
}
var promiseCache2 = new LruMap(8192);

// node_modules/viem/_esm/utils/promise/withRetry.js
function withRetry(fn, { delay: delay_ = 100, retryCount = 2, shouldRetry = () => true } = {}) {
  return new Promise((resolve, reject) => {
    const attemptRetry = async ({ count = 0 } = {}) => {
      const retry = async ({ error }) => {
        const delay = typeof delay_ === "function" ? delay_({ count, error }) : delay_;
        if (delay)
          await wait(delay);
        attemptRetry({ count: count + 1 });
      };
      try {
        const data4 = await fn();
        resolve(data4);
      } catch (err) {
        if (count < retryCount && await shouldRetry({ count, error: err }))
          return retry({ error: err });
        reject(err);
      }
    };
    attemptRetry();
  });
}

// node_modules/viem/_esm/utils/buildRequest.js
init_stringify();
function buildRequest(request6, options = {}) {
  return async (args, overrideOptions = {}) => {
    const { dedupe = false, retryDelay = 150, retryCount = 3, uid: uid3 } = {
      ...options,
      ...overrideOptions
    };
    const requestId = dedupe ? keccak256(stringToHex(`${uid3}.${stringify(args)}`)) : undefined;
    return withDedupe(() => withRetry(async () => {
      try {
        return await request6(args);
      } catch (err_) {
        const err = err_;
        switch (err.code) {
          case ParseRpcError.code:
            throw new ParseRpcError(err);
          case InvalidRequestRpcError.code:
            throw new InvalidRequestRpcError(err);
          case MethodNotFoundRpcError.code:
            throw new MethodNotFoundRpcError(err, { method: args.method });
          case InvalidParamsRpcError.code:
            throw new InvalidParamsRpcError(err);
          case InternalRpcError.code:
            throw new InternalRpcError(err);
          case InvalidInputRpcError.code:
            throw new InvalidInputRpcError(err);
          case ResourceNotFoundRpcError.code:
            throw new ResourceNotFoundRpcError(err);
          case ResourceUnavailableRpcError.code:
            throw new ResourceUnavailableRpcError(err);
          case TransactionRejectedRpcError.code:
            throw new TransactionRejectedRpcError(err);
          case MethodNotSupportedRpcError.code:
            throw new MethodNotSupportedRpcError(err, {
              method: args.method
            });
          case LimitExceededRpcError.code:
            throw new LimitExceededRpcError(err);
          case JsonRpcVersionUnsupportedError.code:
            throw new JsonRpcVersionUnsupportedError(err);
          case UserRejectedRequestError.code:
            throw new UserRejectedRequestError(err);
          case UnauthorizedProviderError.code:
            throw new UnauthorizedProviderError(err);
          case UnsupportedProviderMethodError.code:
            throw new UnsupportedProviderMethodError(err);
          case ProviderDisconnectedError.code:
            throw new ProviderDisconnectedError(err);
          case ChainDisconnectedError.code:
            throw new ChainDisconnectedError(err);
          case SwitchChainError.code:
            throw new SwitchChainError(err);
          case 5000:
            throw new UserRejectedRequestError(err);
          default:
            if (err_ instanceof BaseError)
              throw err_;
            throw new UnknownRpcError(err);
        }
      }
    }, {
      delay: ({ count, error }) => {
        if (error && error instanceof HttpRequestError) {
          const retryAfter = error?.headers?.get("Retry-After");
          if (retryAfter?.match(/\d/))
            return Number.parseInt(retryAfter) * 1000;
        }
        return ~~(1 << count) * retryDelay;
      },
      retryCount,
      shouldRetry: ({ error }) => shouldRetry(error)
    }), { enabled: dedupe, id: requestId });
  };
}
function shouldRetry(error) {
  if (("code" in error) && typeof error.code === "number") {
    if (error.code === -1)
      return true;
    if (error.code === LimitExceededRpcError.code)
      return true;
    if (error.code === InternalRpcError.code)
      return true;
    return false;
  }
  if (error instanceof HttpRequestError && error.status) {
    if (error.status === 403)
      return true;
    if (error.status === 408)
      return true;
    if (error.status === 413)
      return true;
    if (error.status === 429)
      return true;
    if (error.status === 500)
      return true;
    if (error.status === 502)
      return true;
    if (error.status === 503)
      return true;
    if (error.status === 504)
      return true;
    return false;
  }
  return true;
}

// node_modules/viem/_esm/clients/transports/createTransport.js
function createTransport({ key, name, request: request6, retryCount = 3, retryDelay = 150, timeout, type }, value) {
  const uid4 = uid();
  return {
    config: {
      key,
      name,
      request: request6,
      retryCount,
      retryDelay,
      timeout,
      type
    },
    request: buildRequest(request6, { retryCount, retryDelay, uid: uid4 }),
    value
  };
}

// node_modules/viem/_esm/clients/transports/custom.js
function custom(provider, config = {}) {
  const { key = "custom", name = "Custom Provider", retryDelay } = config;
  return ({ retryCount: defaultRetryCount }) => createTransport({
    key,
    name,
    request: provider.request.bind(provider),
    retryCount: config.retryCount ?? defaultRetryCount,
    retryDelay,
    type: "custom"
  });
}
// node_modules/viem/_esm/clients/transports/http.js
init_request();

// node_modules/viem/_esm/errors/transport.js
init_base();

class UrlRequiredError extends BaseError {
  constructor() {
    super("No URL was provided to the Transport. Please provide a valid RPC URL to the Transport.", {
      docsPath: "/docs/clients/intro",
      name: "UrlRequiredError"
    });
  }
}

// node_modules/viem/_esm/clients/transports/http.js
init_createBatchScheduler();

// node_modules/viem/_esm/utils/rpc/http.js
init_request();

// node_modules/viem/_esm/utils/promise/withTimeout.js
function withTimeout(fn, { errorInstance = new Error("timed out"), timeout, signal }) {
  return new Promise((resolve, reject) => {
    (async () => {
      let timeoutId;
      try {
        const controller = new AbortController;
        if (timeout > 0) {
          timeoutId = setTimeout(() => {
            if (signal) {
              controller.abort();
            } else {
              reject(errorInstance);
            }
          }, timeout);
        }
        resolve(await fn({ signal: controller?.signal || null }));
      } catch (err) {
        if (err?.name === "AbortError")
          reject(errorInstance);
        reject(err);
      } finally {
        clearTimeout(timeoutId);
      }
    })();
  });
}

// node_modules/viem/_esm/utils/rpc/http.js
init_stringify();

// node_modules/viem/_esm/utils/rpc/id.js
var createIdStore = function() {
  return {
    current: 0,
    take() {
      return this.current++;
    },
    reset() {
      this.current = 0;
    }
  };
};
var idCache = createIdStore();

// node_modules/viem/_esm/utils/rpc/http.js
function getHttpRpcClient(url6, options = {}) {
  return {
    async request(params) {
      const { body: body2, onRequest = options.onRequest, onResponse = options.onResponse, timeout = options.timeout ?? 1e4 } = params;
      const fetchOptions = {
        ...options.fetchOptions ?? {},
        ...params.fetchOptions ?? {}
      };
      const { headers, method, signal: signal_ } = fetchOptions;
      try {
        const response = await withTimeout(async ({ signal }) => {
          const init = {
            ...fetchOptions,
            body: Array.isArray(body2) ? stringify(body2.map((body3) => ({
              jsonrpc: "2.0",
              id: body3.id ?? idCache.take(),
              ...body3
            }))) : stringify({
              jsonrpc: "2.0",
              id: body2.id ?? idCache.take(),
              ...body2
            }),
            headers: {
              "Content-Type": "application/json",
              ...headers
            },
            method: method || "POST",
            signal: signal_ || (timeout > 0 ? signal : null)
          };
          const request7 = new Request(url6, init);
          const args = await onRequest?.(request7, init) ?? { ...init, url: url6 };
          const response2 = await fetch(args.url ?? url6, args);
          return response2;
        }, {
          errorInstance: new TimeoutError({ body: body2, url: url6 }),
          timeout,
          signal: true
        });
        if (onResponse)
          await onResponse(response);
        let data4;
        if (response.headers.get("Content-Type")?.startsWith("application/json"))
          data4 = await response.json();
        else {
          data4 = await response.text();
          try {
            data4 = JSON.parse(data4 || "{}");
          } catch (err) {
            if (response.ok)
              throw err;
            data4 = { error: data4 };
          }
        }
        if (!response.ok) {
          throw new HttpRequestError({
            body: body2,
            details: stringify(data4.error) || response.statusText,
            headers: response.headers,
            status: response.status,
            url: url6
          });
        }
        return data4;
      } catch (err) {
        if (err instanceof HttpRequestError)
          throw err;
        if (err instanceof TimeoutError)
          throw err;
        throw new HttpRequestError({
          body: body2,
          cause: err,
          url: url6
        });
      }
    }
  };
}

// node_modules/viem/_esm/clients/transports/http.js
function http2(url6, config = {}) {
  const { batch, fetchOptions, key = "http", name = "HTTP JSON-RPC", onFetchRequest, onFetchResponse, retryDelay } = config;
  return ({ chain: chain5, retryCount: retryCount_, timeout: timeout_ }) => {
    const { batchSize = 1000, wait: wait4 = 0 } = typeof batch === "object" ? batch : {};
    const retryCount = config.retryCount ?? retryCount_;
    const timeout = timeout_ ?? config.timeout ?? 1e4;
    const url_ = url6 || chain5?.rpcUrls.default.http[0];
    if (!url_)
      throw new UrlRequiredError;
    const rpcClient = getHttpRpcClient(url_, {
      fetchOptions,
      onRequest: onFetchRequest,
      onResponse: onFetchResponse,
      timeout
    });
    return createTransport({
      key,
      name,
      async request({ method, params }) {
        const body2 = { method, params };
        const { schedule } = createBatchScheduler({
          id: url_,
          wait: wait4,
          shouldSplitBatch(requests) {
            return requests.length > batchSize;
          },
          fn: (body3) => rpcClient.request({
            body: body3
          }),
          sort: (a, b) => a.id - b.id
        });
        const fn = async (body3) => batch ? schedule(body3) : [
          await rpcClient.request({
            body: body3
          })
        ];
        const [{ error, result }] = await fn(body2);
        if (error)
          throw new RpcRequestError({
            body: body2,
            error,
            url: url_
          });
        return result;
      },
      retryCount,
      retryDelay,
      timeout,
      type: "http"
    }, {
      fetchOptions,
      url: url_
    });
  };
}
// node_modules/viem/_esm/actions/ens/getEnsAddress.js
init_abis();
init_decodeFunctionResult();
init_encodeFunctionData();
init_getChainContractAddress();
init_trim();
init_toHex();

// node_modules/viem/_esm/utils/ens/errors.js
init_solidity();
init_base();
init_contract();
function isNullUniversalResolverError(err, callType) {
  if (!(err instanceof BaseError))
    return false;
  const cause = err.walk((e) => e instanceof ContractFunctionRevertedError);
  if (!(cause instanceof ContractFunctionRevertedError))
    return false;
  if (cause.data?.errorName === "ResolverNotFound")
    return true;
  if (cause.data?.errorName === "ResolverWildcardNotSupported")
    return true;
  if (cause.data?.errorName === "ResolverNotContract")
    return true;
  if (cause.data?.errorName === "ResolverError")
    return true;
  if (cause.data?.errorName === "HttpError")
    return true;
  if (cause.reason?.includes("Wildcard on non-extended resolvers is not supported"))
    return true;
  if (callType === "reverse" && cause.reason === panicReasons[50])
    return true;
  return false;
}

// node_modules/viem/_esm/utils/ens/namehash.js
init_concat();
init_toBytes();
init_toHex();
init_keccak256();

// node_modules/viem/_esm/utils/ens/encodedLabelToLabelhash.js
init_isHex();
function encodedLabelToLabelhash(label) {
  if (label.length !== 66)
    return null;
  if (label.indexOf("[") !== 0)
    return null;
  if (label.indexOf("]") !== 65)
    return null;
  const hash3 = `0x${label.slice(1, 65)}`;
  if (!isHex(hash3))
    return null;
  return hash3;
}

// node_modules/viem/_esm/utils/ens/namehash.js
function namehash(name) {
  let result = new Uint8Array(32).fill(0);
  if (!name)
    return bytesToHex2(result);
  const labels = name.split(".");
  for (let i = labels.length - 1;i >= 0; i -= 1) {
    const hashFromEncodedLabel = encodedLabelToLabelhash(labels[i]);
    const hashed = hashFromEncodedLabel ? toBytes2(hashFromEncodedLabel) : keccak256(stringToBytes(labels[i]), "bytes");
    result = keccak256(concat([result, hashed]), "bytes");
  }
  return bytesToHex2(result);
}

// node_modules/viem/_esm/utils/ens/packetToBytes.js
init_toBytes();

// node_modules/viem/_esm/utils/ens/encodeLabelhash.js
function encodeLabelhash(hash3) {
  return `[${hash3.slice(2)}]`;
}

// node_modules/viem/_esm/utils/ens/labelhash.js
init_toBytes();
init_toHex();
init_keccak256();
function labelhash(label) {
  const result = new Uint8Array(32).fill(0);
  if (!label)
    return bytesToHex2(result);
  return encodedLabelToLabelhash(label) || keccak256(stringToBytes(label));
}

// node_modules/viem/_esm/utils/ens/packetToBytes.js
function packetToBytes(packet) {
  const value = packet.replace(/^\.|\.$/gm, "");
  if (value.length === 0)
    return new Uint8Array(1);
  const bytes2 = new Uint8Array(stringToBytes(value).byteLength + 2);
  let offset = 0;
  const list = value.split(".");
  for (let i = 0;i < list.length; i++) {
    let encoded = stringToBytes(list[i]);
    if (encoded.byteLength > 255)
      encoded = stringToBytes(encodeLabelhash(labelhash(list[i])));
    bytes2[offset] = encoded.length;
    bytes2.set(encoded, offset + 1);
    offset += encoded.length + 1;
  }
  if (bytes2.byteLength !== offset + 1)
    return bytes2.slice(0, offset + 1);
  return bytes2;
}

// node_modules/viem/_esm/actions/ens/getEnsAddress.js
async function getEnsAddress(client, { blockNumber, blockTag, coinType, name, gatewayUrls, strict, universalResolverAddress: universalResolverAddress_ }) {
  let universalResolverAddress = universalResolverAddress_;
  if (!universalResolverAddress) {
    if (!client.chain)
      throw new Error("client chain not configured. universalResolverAddress is required.");
    universalResolverAddress = getChainContractAddress({
      blockNumber,
      chain: client.chain,
      contract: "ensUniversalResolver"
    });
  }
  try {
    const functionData = encodeFunctionData({
      abi: addressResolverAbi,
      functionName: "addr",
      ...coinType != null ? { args: [namehash(name), BigInt(coinType)] } : { args: [namehash(name)] }
    });
    const readContractParameters = {
      address: universalResolverAddress,
      abi: universalResolverResolveAbi,
      functionName: "resolve",
      args: [toHex2(packetToBytes(name)), functionData],
      blockNumber,
      blockTag
    };
    const readContractAction = getAction(client, readContract, "readContract");
    const res = gatewayUrls ? await readContractAction({
      ...readContractParameters,
      args: [...readContractParameters.args, gatewayUrls]
    }) : await readContractAction(readContractParameters);
    if (res[0] === "0x")
      return null;
    const address10 = decodeFunctionResult({
      abi: addressResolverAbi,
      args: coinType != null ? [namehash(name), BigInt(coinType)] : undefined,
      functionName: "addr",
      data: res[0]
    });
    if (address10 === "0x")
      return null;
    if (trim(address10) === "0x00")
      return null;
    return address10;
  } catch (err) {
    if (strict)
      throw err;
    if (isNullUniversalResolverError(err, "resolve"))
      return null;
    throw err;
  }
}

// node_modules/viem/_esm/errors/ens.js
init_base();

class EnsAvatarInvalidMetadataError extends BaseError {
  constructor({ data: data4 }) {
    super("Unable to extract image from metadata. The metadata may be malformed or invalid.", {
      metaMessages: [
        "- Metadata must be a JSON object with at least an `image`, `image_url` or `image_data` property.",
        "",
        `Provided data: ${JSON.stringify(data4)}`
      ],
      name: "EnsAvatarInvalidMetadataError"
    });
  }
}

class EnsAvatarInvalidNftUriError extends BaseError {
  constructor({ reason }) {
    super(`ENS NFT avatar URI is invalid. ${reason}`, {
      name: "EnsAvatarInvalidNftUriError"
    });
  }
}

class EnsAvatarUriResolutionError extends BaseError {
  constructor({ uri }) {
    super(`Unable to resolve ENS avatar URI "${uri}". The URI may be malformed, invalid, or does not respond with a valid image.`, { name: "EnsAvatarUriResolutionError" });
  }
}

class EnsAvatarUnsupportedNamespaceError extends BaseError {
  constructor({ namespace }) {
    super(`ENS NFT avatar namespace "${namespace}" is not supported. Must be "erc721" or "erc1155".`, { name: "EnsAvatarUnsupportedNamespaceError" });
  }
}

// node_modules/viem/_esm/utils/ens/avatar/utils.js
async function isImageUri(uri) {
  try {
    const res = await fetch(uri, { method: "HEAD" });
    if (res.status === 200) {
      const contentType = res.headers.get("content-type");
      return contentType?.startsWith("image/");
    }
    return false;
  } catch (error) {
    if (typeof error === "object" && typeof error.response !== "undefined") {
      return false;
    }
    if (!globalThis.hasOwnProperty("Image"))
      return false;
    return new Promise((resolve) => {
      const img = new Image;
      img.onload = () => {
        resolve(true);
      };
      img.onerror = () => {
        resolve(false);
      };
      img.src = uri;
    });
  }
}
function getGateway(custom2, defaultGateway) {
  if (!custom2)
    return defaultGateway;
  if (custom2.endsWith("/"))
    return custom2.slice(0, -1);
  return custom2;
}
function resolveAvatarUri({ uri, gatewayUrls }) {
  const isEncoded = base64Regex.test(uri);
  if (isEncoded)
    return { uri, isOnChain: true, isEncoded };
  const ipfsGateway = getGateway(gatewayUrls?.ipfs, "https://ipfs.io");
  const arweaveGateway = getGateway(gatewayUrls?.arweave, "https://arweave.net");
  const networkRegexMatch = uri.match(networkRegex);
  const { protocol, subpath, target, subtarget = "" } = networkRegexMatch?.groups || {};
  const isIPNS = protocol === "ipns:/" || subpath === "ipns/";
  const isIPFS = protocol === "ipfs:/" || subpath === "ipfs/" || ipfsHashRegex.test(uri);
  if (uri.startsWith("http") && !isIPNS && !isIPFS) {
    let replacedUri = uri;
    if (gatewayUrls?.arweave)
      replacedUri = uri.replace(/https:\/\/arweave.net/g, gatewayUrls?.arweave);
    return { uri: replacedUri, isOnChain: false, isEncoded: false };
  }
  if ((isIPNS || isIPFS) && target) {
    return {
      uri: `${ipfsGateway}/${isIPNS ? "ipns" : "ipfs"}/${target}${subtarget}`,
      isOnChain: false,
      isEncoded: false
    };
  }
  if (protocol === "ar:/" && target) {
    return {
      uri: `${arweaveGateway}/${target}${subtarget || ""}`,
      isOnChain: false,
      isEncoded: false
    };
  }
  let parsedUri = uri.replace(dataURIRegex, "");
  if (parsedUri.startsWith("<svg")) {
    parsedUri = `data:image/svg+xml;base64,${btoa(parsedUri)}`;
  }
  if (parsedUri.startsWith("data:") || parsedUri.startsWith("{")) {
    return {
      uri: parsedUri,
      isOnChain: true,
      isEncoded: false
    };
  }
  throw new EnsAvatarUriResolutionError({ uri });
}
function getJsonImage(data4) {
  if (typeof data4 !== "object" || !("image" in data4) && !("image_url" in data4) && !("image_data" in data4)) {
    throw new EnsAvatarInvalidMetadataError({ data: data4 });
  }
  return data4.image || data4.image_url || data4.image_data;
}
async function getMetadataAvatarUri({ gatewayUrls, uri }) {
  try {
    const res = await fetch(uri).then((res2) => res2.json());
    const image = await parseAvatarUri({
      gatewayUrls,
      uri: getJsonImage(res)
    });
    return image;
  } catch {
    throw new EnsAvatarUriResolutionError({ uri });
  }
}
async function parseAvatarUri({ gatewayUrls, uri }) {
  const { uri: resolvedURI, isOnChain } = resolveAvatarUri({ uri, gatewayUrls });
  if (isOnChain)
    return resolvedURI;
  const isImage = await isImageUri(resolvedURI);
  if (isImage)
    return resolvedURI;
  throw new EnsAvatarUriResolutionError({ uri });
}
function parseNftUri(uri_) {
  let uri = uri_;
  if (uri.startsWith("did:nft:")) {
    uri = uri.replace("did:nft:", "").replace(/_/g, "/");
  }
  const [reference, asset_namespace, tokenID] = uri.split("/");
  const [eip_namespace, chainID] = reference.split(":");
  const [erc_namespace, contractAddress] = asset_namespace.split(":");
  if (!eip_namespace || eip_namespace.toLowerCase() !== "eip155")
    throw new EnsAvatarInvalidNftUriError({ reason: "Only EIP-155 supported" });
  if (!chainID)
    throw new EnsAvatarInvalidNftUriError({ reason: "Chain ID not found" });
  if (!contractAddress)
    throw new EnsAvatarInvalidNftUriError({
      reason: "Contract address not found"
    });
  if (!tokenID)
    throw new EnsAvatarInvalidNftUriError({ reason: "Token ID not found" });
  if (!erc_namespace)
    throw new EnsAvatarInvalidNftUriError({ reason: "ERC namespace not found" });
  return {
    chainID: Number.parseInt(chainID),
    namespace: erc_namespace.toLowerCase(),
    contractAddress,
    tokenID
  };
}
async function getNftTokenUri(client, { nft }) {
  if (nft.namespace === "erc721") {
    return readContract(client, {
      address: nft.contractAddress,
      abi: [
        {
          name: "tokenURI",
          type: "function",
          stateMutability: "view",
          inputs: [{ name: "tokenId", type: "uint256" }],
          outputs: [{ name: "", type: "string" }]
        }
      ],
      functionName: "tokenURI",
      args: [BigInt(nft.tokenID)]
    });
  }
  if (nft.namespace === "erc1155") {
    return readContract(client, {
      address: nft.contractAddress,
      abi: [
        {
          name: "uri",
          type: "function",
          stateMutability: "view",
          inputs: [{ name: "_id", type: "uint256" }],
          outputs: [{ name: "", type: "string" }]
        }
      ],
      functionName: "uri",
      args: [BigInt(nft.tokenID)]
    });
  }
  throw new EnsAvatarUnsupportedNamespaceError({ namespace: nft.namespace });
}
var networkRegex = /(?<protocol>https?:\/\/[^\/]*|ipfs:\/|ipns:\/|ar:\/)?(?<root>\/)?(?<subpath>ipfs\/|ipns\/)?(?<target>[\w\-.]+)(?<subtarget>\/.*)?/;
var ipfsHashRegex = /^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[A-Za-z2-7]{58,}|B[A-Z2-7]{58,}|z[1-9A-HJ-NP-Za-km-z]{48,}|F[0-9A-F]{50,})(\/(?<target>[\w\-.]+))?(?<subtarget>\/.*)?$/;
var base64Regex = /^data:([a-zA-Z\-/+]*);base64,([^"].*)/;
var dataURIRegex = /^data:([a-zA-Z\-/+]*)?(;[a-zA-Z0-9].*?)?(,)/;

// node_modules/viem/_esm/utils/ens/avatar/parseAvatarRecord.js
async function parseAvatarRecord(client, { gatewayUrls, record }) {
  if (/eip155:/i.test(record))
    return parseNftAvatarUri(client, { gatewayUrls, record });
  return parseAvatarUri({ uri: record, gatewayUrls });
}
async function parseNftAvatarUri(client, { gatewayUrls, record }) {
  const nft = parseNftUri(record);
  const nftUri = await getNftTokenUri(client, { nft });
  const { uri: resolvedNftUri, isOnChain, isEncoded } = resolveAvatarUri({ uri: nftUri, gatewayUrls });
  if (isOnChain && (resolvedNftUri.includes("data:application/json;base64,") || resolvedNftUri.startsWith("{"))) {
    const encodedJson = isEncoded ? atob(resolvedNftUri.replace("data:application/json;base64,", "")) : resolvedNftUri;
    const decoded = JSON.parse(encodedJson);
    return parseAvatarUri({ uri: getJsonImage(decoded), gatewayUrls });
  }
  let uriTokenId = nft.tokenID;
  if (nft.namespace === "erc1155")
    uriTokenId = uriTokenId.replace("0x", "").padStart(64, "0");
  return getMetadataAvatarUri({
    gatewayUrls,
    uri: resolvedNftUri.replace(/(?:0x)?{id}/, uriTokenId)
  });
}

// node_modules/viem/_esm/actions/ens/getEnsText.js
init_abis();
init_decodeFunctionResult();
init_encodeFunctionData();
init_getChainContractAddress();
init_toHex();
async function getEnsText(client, { blockNumber, blockTag, name, key, gatewayUrls, strict, universalResolverAddress: universalResolverAddress_ }) {
  let universalResolverAddress = universalResolverAddress_;
  if (!universalResolverAddress) {
    if (!client.chain)
      throw new Error("client chain not configured. universalResolverAddress is required.");
    universalResolverAddress = getChainContractAddress({
      blockNumber,
      chain: client.chain,
      contract: "ensUniversalResolver"
    });
  }
  try {
    const readContractParameters = {
      address: universalResolverAddress,
      abi: universalResolverResolveAbi,
      functionName: "resolve",
      args: [
        toHex2(packetToBytes(name)),
        encodeFunctionData({
          abi: textResolverAbi,
          functionName: "text",
          args: [namehash(name), key]
        })
      ],
      blockNumber,
      blockTag
    };
    const readContractAction = getAction(client, readContract, "readContract");
    const res = gatewayUrls ? await readContractAction({
      ...readContractParameters,
      args: [...readContractParameters.args, gatewayUrls]
    }) : await readContractAction(readContractParameters);
    if (res[0] === "0x")
      return null;
    const record = decodeFunctionResult({
      abi: textResolverAbi,
      functionName: "text",
      data: res[0]
    });
    return record === "" ? null : record;
  } catch (err) {
    if (strict)
      throw err;
    if (isNullUniversalResolverError(err, "resolve"))
      return null;
    throw err;
  }
}

// node_modules/viem/_esm/actions/ens/getEnsAvatar.js
async function getEnsAvatar(client, { blockNumber, blockTag, assetGatewayUrls, name, gatewayUrls, strict, universalResolverAddress }) {
  const record = await getAction(client, getEnsText, "getEnsText")({
    blockNumber,
    blockTag,
    key: "avatar",
    name,
    universalResolverAddress,
    gatewayUrls,
    strict
  });
  if (!record)
    return null;
  try {
    return await parseAvatarRecord(client, {
      record,
      gatewayUrls: assetGatewayUrls
    });
  } catch {
    return null;
  }
}

// node_modules/viem/_esm/actions/ens/getEnsName.js
init_abis();
init_getChainContractAddress();
init_toHex();
async function getEnsName(client, { address: address10, blockNumber, blockTag, gatewayUrls, strict, universalResolverAddress: universalResolverAddress_ }) {
  let universalResolverAddress = universalResolverAddress_;
  if (!universalResolverAddress) {
    if (!client.chain)
      throw new Error("client chain not configured. universalResolverAddress is required.");
    universalResolverAddress = getChainContractAddress({
      blockNumber,
      chain: client.chain,
      contract: "ensUniversalResolver"
    });
  }
  const reverseNode = `${address10.toLowerCase().substring(2)}.addr.reverse`;
  try {
    const readContractParameters = {
      address: universalResolverAddress,
      abi: universalResolverReverseAbi,
      functionName: "reverse",
      args: [toHex2(packetToBytes(reverseNode))],
      blockNumber,
      blockTag
    };
    const readContractAction = getAction(client, readContract, "readContract");
    const [name, resolvedAddress] = gatewayUrls ? await readContractAction({
      ...readContractParameters,
      args: [...readContractParameters.args, gatewayUrls]
    }) : await readContractAction(readContractParameters);
    if (address10.toLowerCase() !== resolvedAddress.toLowerCase())
      return null;
    return name;
  } catch (err) {
    if (strict)
      throw err;
    if (isNullUniversalResolverError(err, "reverse"))
      return null;
    throw err;
  }
}

// node_modules/viem/_esm/actions/ens/getEnsResolver.js
init_getChainContractAddress();
init_toHex();
async function getEnsResolver(client, { blockNumber, blockTag, name, universalResolverAddress: universalResolverAddress_ }) {
  let universalResolverAddress = universalResolverAddress_;
  if (!universalResolverAddress) {
    if (!client.chain)
      throw new Error("client chain not configured. universalResolverAddress is required.");
    universalResolverAddress = getChainContractAddress({
      blockNumber,
      chain: client.chain,
      contract: "ensUniversalResolver"
    });
  }
  const [resolverAddress] = await getAction(client, readContract, "readContract")({
    address: universalResolverAddress,
    abi: [
      {
        inputs: [{ type: "bytes" }],
        name: "findResolver",
        outputs: [{ type: "address" }, { type: "bytes32" }],
        stateMutability: "view",
        type: "function"
      }
    ],
    functionName: "findResolver",
    args: [toHex2(packetToBytes(name))],
    blockNumber,
    blockTag
  });
  return resolverAddress;
}

// node_modules/viem/_esm/clients/decorators/public.js
init_call();

// node_modules/viem/_esm/actions/public/createBlockFilter.js
async function createBlockFilter(client) {
  const getRequest = createFilterRequestScope(client, {
    method: "eth_newBlockFilter"
  });
  const id2 = await client.request({
    method: "eth_newBlockFilter"
  });
  return { id: id2, request: getRequest(id2), type: "block" };
}

// node_modules/viem/_esm/actions/public/createEventFilter.js
init_toHex();
async function createEventFilter(client, { address: address10, args, event, events: events_, fromBlock, strict, toBlock } = {}) {
  const events = events_ ?? (event ? [event] : undefined);
  const getRequest = createFilterRequestScope(client, {
    method: "eth_newFilter"
  });
  let topics = [];
  if (events) {
    const encoded = events.flatMap((event2) => encodeEventTopics({
      abi: [event2],
      eventName: event2.name,
      args
    }));
    topics = [encoded];
    if (event)
      topics = topics[0];
  }
  const id2 = await client.request({
    method: "eth_newFilter",
    params: [
      {
        address: address10,
        fromBlock: typeof fromBlock === "bigint" ? numberToHex(fromBlock) : fromBlock,
        toBlock: typeof toBlock === "bigint" ? numberToHex(toBlock) : toBlock,
        ...topics.length ? { topics } : {}
      }
    ]
  });
  return {
    abi: events,
    args,
    eventName: event ? event.name : undefined,
    fromBlock,
    id: id2,
    request: getRequest(id2),
    strict: Boolean(strict),
    toBlock,
    type: "event"
  };
}

// node_modules/viem/_esm/actions/public/createPendingTransactionFilter.js
async function createPendingTransactionFilter(client) {
  const getRequest = createFilterRequestScope(client, {
    method: "eth_newPendingTransactionFilter"
  });
  const id2 = await client.request({
    method: "eth_newPendingTransactionFilter"
  });
  return { id: id2, request: getRequest(id2), type: "transaction" };
}

// node_modules/viem/_esm/actions/public/getBlobBaseFee.js
async function getBlobBaseFee(client) {
  const baseFee = await client.request({
    method: "eth_blobBaseFee"
  });
  return BigInt(baseFee);
}

// node_modules/viem/_esm/actions/public/getBlockTransactionCount.js
init_fromHex();
init_toHex();
async function getBlockTransactionCount(client, { blockHash, blockNumber, blockTag = "latest" } = {}) {
  const blockNumberHex = blockNumber !== undefined ? numberToHex(blockNumber) : undefined;
  let count;
  if (blockHash) {
    count = await client.request({
      method: "eth_getBlockTransactionCountByHash",
      params: [blockHash]
    }, { dedupe: true });
  } else {
    count = await client.request({
      method: "eth_getBlockTransactionCountByNumber",
      params: [blockNumberHex || blockTag]
    }, { dedupe: Boolean(blockNumberHex) });
  }
  return hexToNumber2(count);
}

// node_modules/viem/_esm/actions/public/getCode.js
init_toHex();
async function getCode(client, { address: address10, blockNumber, blockTag = "latest" }) {
  const blockNumberHex = blockNumber !== undefined ? numberToHex(blockNumber) : undefined;
  const hex = await client.request({
    method: "eth_getCode",
    params: [address10, blockNumberHex || blockTag]
  }, { dedupe: Boolean(blockNumberHex) });
  if (hex === "0x")
    return;
  return hex;
}

// node_modules/viem/_esm/actions/public/getFeeHistory.js
init_toHex();

// node_modules/viem/_esm/utils/formatters/feeHistory.js
function formatFeeHistory(feeHistory) {
  return {
    baseFeePerGas: feeHistory.baseFeePerGas.map((value) => BigInt(value)),
    gasUsedRatio: feeHistory.gasUsedRatio,
    oldestBlock: BigInt(feeHistory.oldestBlock),
    reward: feeHistory.reward?.map((reward) => reward.map((value) => BigInt(value)))
  };
}

// node_modules/viem/_esm/actions/public/getFeeHistory.js
async function getFeeHistory(client, { blockCount, blockNumber, blockTag = "latest", rewardPercentiles }) {
  const blockNumberHex = blockNumber ? numberToHex(blockNumber) : undefined;
  const feeHistory2 = await client.request({
    method: "eth_feeHistory",
    params: [
      numberToHex(blockCount),
      blockNumberHex || blockTag,
      rewardPercentiles
    ]
  }, { dedupe: Boolean(blockNumberHex) });
  return formatFeeHistory(feeHistory2);
}

// node_modules/viem/_esm/actions/public/getFilterLogs.js
async function getFilterLogs(_client, { filter }) {
  const strict = filter.strict ?? false;
  const logs = await filter.request({
    method: "eth_getFilterLogs",
    params: [filter.id]
  });
  const formattedLogs = logs.map((log6) => formatLog(log6));
  if (!filter.abi)
    return formattedLogs;
  return parseEventLogs({
    abi: filter.abi,
    logs: formattedLogs,
    strict
  });
}

// node_modules/viem/_esm/actions/public/getProof.js
init_toHex();

// node_modules/viem/_esm/utils/chain/defineChain.js
function defineChain(chain5) {
  return {
    formatters: undefined,
    fees: undefined,
    serializers: undefined,
    ...chain5
  };
}

// node_modules/viem/_esm/utils/index.js
init_encodeFunctionData();

// node_modules/viem/_esm/utils/abi/encodePacked.js
init_abi();
init_address();
init_isAddress();
init_concat();
init_pad();
init_toHex();
function encodePacked(types, values) {
  if (types.length !== values.length)
    throw new AbiEncodingLengthMismatchError({
      expectedLength: types.length,
      givenLength: values.length
    });
  const data4 = [];
  for (let i = 0;i < types.length; i++) {
    const type = types[i];
    const value = values[i];
    data4.push(encode(type, value));
  }
  return concatHex(data4);
}
var encode = function(type, value, isArray = false) {
  if (type === "address") {
    const address11 = value;
    if (!isAddress2(address11))
      throw new InvalidAddressError({ address: address11 });
    return pad(address11.toLowerCase(), {
      size: isArray ? 32 : null
    });
  }
  if (type === "string")
    return stringToHex(value);
  if (type === "bytes")
    return value;
  if (type === "bool")
    return pad(boolToHex(value), { size: isArray ? 32 : 1 });
  const intMatch = type.match(integerRegex);
  if (intMatch) {
    const [_type, baseType, bits = "256"] = intMatch;
    const size13 = Number.parseInt(bits) / 8;
    return numberToHex(value, {
      size: isArray ? 32 : size13,
      signed: baseType === "int"
    });
  }
  const bytesMatch = type.match(bytesRegex);
  if (bytesMatch) {
    const [_type, size13] = bytesMatch;
    if (Number.parseInt(size13) !== (value.length - 2) / 2)
      throw new BytesSizeMismatchError({
        expectedSize: Number.parseInt(size13),
        givenSize: (value.length - 2) / 2
      });
    return pad(value, { dir: "right", size: isArray ? 32 : null });
  }
  const arrayMatch = type.match(arrayRegex);
  if (arrayMatch && Array.isArray(value)) {
    const [_type, childType] = arrayMatch;
    const data4 = [];
    for (let i = 0;i < value.length; i++) {
      data4.push(encode(childType, value[i], true));
    }
    if (data4.length === 0)
      return "0x";
    return concatHex(data4);
  }
  throw new UnsupportedPackedAbiType(type);
};

// node_modules/viem/_esm/utils/index.js
init_parseAccount();
init_getAddress();

// node_modules/viem/_esm/utils/formatters/transactionReceipt.js
init_fromHex();
init_formatter();
function formatTransactionReceipt(transactionReceipt) {
  const receipt = {
    ...transactionReceipt,
    blockNumber: transactionReceipt.blockNumber ? BigInt(transactionReceipt.blockNumber) : null,
    contractAddress: transactionReceipt.contractAddress ? transactionReceipt.contractAddress : null,
    cumulativeGasUsed: transactionReceipt.cumulativeGasUsed ? BigInt(transactionReceipt.cumulativeGasUsed) : null,
    effectiveGasPrice: transactionReceipt.effectiveGasPrice ? BigInt(transactionReceipt.effectiveGasPrice) : null,
    gasUsed: transactionReceipt.gasUsed ? BigInt(transactionReceipt.gasUsed) : null,
    logs: transactionReceipt.logs ? transactionReceipt.logs.map((log7) => formatLog(log7)) : null,
    to: transactionReceipt.to ? transactionReceipt.to : null,
    transactionIndex: transactionReceipt.transactionIndex ? hexToNumber2(transactionReceipt.transactionIndex) : null,
    status: transactionReceipt.status ? receiptStatuses[transactionReceipt.status] : null,
    type: transactionReceipt.type ? transactionType[transactionReceipt.type] || transactionReceipt.type : null
  };
  if (transactionReceipt.blobGasPrice)
    receipt.blobGasPrice = BigInt(transactionReceipt.blobGasPrice);
  if (transactionReceipt.blobGasUsed)
    receipt.blobGasUsed = BigInt(transactionReceipt.blobGasUsed);
  return receipt;
}
var receiptStatuses = {
  "0x0": "reverted",
  "0x1": "success"
};
var defineTransactionReceipt = defineFormatter("transactionReceipt", formatTransactionReceipt);

// node_modules/viem/_esm/utils/index.js
init_fromHex();
// node_modules/viem/_esm/constants/bytes.js
var erc6492MagicBytes = "0x6492649264926492649264926492649264926492649264926492649264926492";

// node_modules/viem/_esm/utils/signature/isErc6492Signature.js
init_slice();
function isErc6492Signature(signature3) {
  return sliceHex(signature3, -32) === erc6492MagicBytes;
}

// node_modules/viem/_esm/utils/signature/serializeErc6492Signature.js
init_encodeAbiParameters();
init_concat();
init_toBytes();
function serializeErc6492Signature(parameters) {
  const { address: address11, data: data4, signature: signature3, to = "hex" } = parameters;
  const signature_ = concatHex([
    encodeAbiParameters([{ type: "address" }, { type: "bytes" }, { type: "bytes" }], [address11, data4, signature3]),
    erc6492MagicBytes
  ]);
  if (to === "hex")
    return signature_;
  return hexToBytes2(signature_);
}

// node_modules/viem/_esm/utils/index.js
init_formatGwei();

// node_modules/viem/_esm/errors/unit.js
init_base();

class InvalidDecimalNumberError extends BaseError {
  constructor({ value }) {
    super(`Number \`${value}\` is not a valid decimal number.`, {
      name: "InvalidDecimalNumberError"
    });
  }
}

// node_modules/viem/_esm/utils/unit/parseUnits.js
function parseUnits(value, decimals) {
  if (!/^(-?)([0-9]*)\.?([0-9]*)$/.test(value))
    throw new InvalidDecimalNumberError({ value });
  let [integer, fraction = "0"] = value.split(".");
  const negative = integer.startsWith("-");
  if (negative)
    integer = integer.slice(1);
  fraction = fraction.replace(/(0+)$/, "");
  if (decimals === 0) {
    if (Math.round(Number(`.${fraction}`)) === 1)
      integer = `${BigInt(integer) + 1n}`;
    fraction = "";
  } else if (fraction.length > decimals) {
    const [left, unit4, right] = [
      fraction.slice(0, decimals - 1),
      fraction.slice(decimals - 1, decimals),
      fraction.slice(decimals)
    ];
    const rounded = Math.round(Number(`${unit4}.${right}`));
    if (rounded > 9)
      fraction = `${BigInt(left) + BigInt(1)}0`.padStart(left.length + 1, "0");
    else
      fraction = `${left}${rounded}`;
    if (fraction.length > decimals) {
      fraction = fraction.slice(1);
      integer = `${BigInt(integer) + 1n}`;
    }
    fraction = fraction.slice(0, decimals);
  } else {
    fraction = fraction.padEnd(decimals, "0");
  }
  return BigInt(`${negative ? "-" : ""}${integer}${fraction}`);
}

// node_modules/viem/_esm/utils/unit/parseEther.js
init_unit();
function parseEther(ether, unit5 = "wei") {
  return parseUnits(ether, etherUnits[unit5]);
}

// node_modules/viem/_esm/utils/unit/parseGwei.js
init_unit();
function parseGwei(ether, unit6 = "wei") {
  return parseUnits(ether, gweiUnits[unit6]);
}

// node_modules/viem/_esm/utils/formatters/proof.js
var formatStorageProof = function(storageProof) {
  return storageProof.map((proof) => ({
    ...proof,
    value: BigInt(proof.value)
  }));
};
function formatProof(proof) {
  return {
    ...proof,
    balance: proof.balance ? BigInt(proof.balance) : undefined,
    nonce: proof.nonce ? hexToNumber2(proof.nonce) : undefined,
    storageProof: proof.storageProof ? formatStorageProof(proof.storageProof) : undefined
  };
}

// node_modules/viem/_esm/actions/public/getProof.js
async function getProof(client, { address: address11, blockNumber, blockTag: blockTag_, storageKeys }) {
  const blockTag = blockTag_ ?? "latest";
  const blockNumberHex = blockNumber !== undefined ? numberToHex(blockNumber) : undefined;
  const proof2 = await client.request({
    method: "eth_getProof",
    params: [address11, storageKeys, blockNumberHex || blockTag]
  });
  return formatProof(proof2);
}

// node_modules/viem/_esm/actions/public/getStorageAt.js
init_toHex();
async function getStorageAt(client, { address: address11, blockNumber, blockTag = "latest", slot }) {
  const blockNumberHex = blockNumber !== undefined ? numberToHex(blockNumber) : undefined;
  const data4 = await client.request({
    method: "eth_getStorageAt",
    params: [address11, slot, blockNumberHex || blockTag]
  });
  return data4;
}

// node_modules/viem/_esm/actions/public/getTransaction.js
init_transaction();
init_toHex();
async function getTransaction(client, { blockHash, blockNumber, blockTag: blockTag_, hash: hash3, index: index2 }) {
  const blockTag = blockTag_ || "latest";
  const blockNumberHex = blockNumber !== undefined ? numberToHex(blockNumber) : undefined;
  let transaction12 = null;
  if (hash3) {
    transaction12 = await client.request({
      method: "eth_getTransactionByHash",
      params: [hash3]
    }, { dedupe: true });
  } else if (blockHash) {
    transaction12 = await client.request({
      method: "eth_getTransactionByBlockHashAndIndex",
      params: [blockHash, numberToHex(index2)]
    }, { dedupe: true });
  } else if (blockNumberHex || blockTag) {
    transaction12 = await client.request({
      method: "eth_getTransactionByBlockNumberAndIndex",
      params: [blockNumberHex || blockTag, numberToHex(index2)]
    }, { dedupe: Boolean(blockNumberHex) });
  }
  if (!transaction12)
    throw new TransactionNotFoundError({
      blockHash,
      blockNumber,
      blockTag,
      hash: hash3,
      index: index2
    });
  const format = client.chain?.formatters?.transaction?.format || formatTransaction;
  return format(transaction12);
}

// node_modules/viem/_esm/actions/public/getTransactionConfirmations.js
async function getTransactionConfirmations(client, { hash: hash3, transactionReceipt }) {
  const [blockNumber, transaction12] = await Promise.all([
    getAction(client, getBlockNumber, "getBlockNumber")({}),
    hash3 ? getAction(client, getTransaction, "getTransaction")({ hash: hash3 }) : undefined
  ]);
  const transactionBlockNumber = transactionReceipt?.blockNumber || transaction12?.blockNumber;
  if (!transactionBlockNumber)
    return 0n;
  return blockNumber - transactionBlockNumber + 1n;
}

// node_modules/viem/_esm/actions/public/getTransactionReceipt.js
init_transaction();
async function getTransactionReceipt(client, { hash: hash3 }) {
  const receipt = await client.request({
    method: "eth_getTransactionReceipt",
    params: [hash3]
  }, { dedupe: true });
  if (!receipt)
    throw new TransactionReceiptNotFoundError({ hash: hash3 });
  const format = client.chain?.formatters?.transactionReceipt?.format || formatTransactionReceipt;
  return format(receipt);
}

// node_modules/viem/_esm/actions/public/multicall.js
init_abis();
init_abi();
init_base();
init_contract();
init_decodeFunctionResult();
init_encodeFunctionData();
init_getChainContractAddress();
async function multicall(client, parameters) {
  const { allowFailure = true, batchSize: batchSize_, blockNumber, blockTag, multicallAddress: multicallAddress_, stateOverride: stateOverride5 } = parameters;
  const contracts2 = parameters.contracts;
  const batchSize = batchSize_ ?? (typeof client.batch?.multicall === "object" && client.batch.multicall.batchSize || 1024);
  let multicallAddress = multicallAddress_;
  if (!multicallAddress) {
    if (!client.chain)
      throw new Error("client chain not configured. multicallAddress is required.");
    multicallAddress = getChainContractAddress({
      blockNumber,
      chain: client.chain,
      contract: "multicall3"
    });
  }
  const chunkedCalls = [[]];
  let currentChunk = 0;
  let currentChunkSize = 0;
  for (let i = 0;i < contracts2.length; i++) {
    const { abi: abi19, address: address11, args, functionName } = contracts2[i];
    try {
      const callData = encodeFunctionData({ abi: abi19, args, functionName });
      currentChunkSize += (callData.length - 2) / 2;
      if (batchSize > 0 && currentChunkSize > batchSize && chunkedCalls[currentChunk].length > 0) {
        currentChunk++;
        currentChunkSize = (callData.length - 2) / 2;
        chunkedCalls[currentChunk] = [];
      }
      chunkedCalls[currentChunk] = [
        ...chunkedCalls[currentChunk],
        {
          allowFailure: true,
          callData,
          target: address11
        }
      ];
    } catch (err) {
      const error = getContractError(err, {
        abi: abi19,
        address: address11,
        args,
        docsPath: "/docs/contract/multicall",
        functionName
      });
      if (!allowFailure)
        throw error;
      chunkedCalls[currentChunk] = [
        ...chunkedCalls[currentChunk],
        {
          allowFailure: true,
          callData: "0x",
          target: address11
        }
      ];
    }
  }
  const aggregate3Results = await Promise.allSettled(chunkedCalls.map((calls) => getAction(client, readContract, "readContract")({
    abi: multicall3Abi,
    address: multicallAddress,
    args: [calls],
    blockNumber,
    blockTag,
    functionName: "aggregate3",
    stateOverride: stateOverride5
  })));
  const results = [];
  for (let i = 0;i < aggregate3Results.length; i++) {
    const result = aggregate3Results[i];
    if (result.status === "rejected") {
      if (!allowFailure)
        throw result.reason;
      for (let j = 0;j < chunkedCalls[i].length; j++) {
        results.push({
          status: "failure",
          error: result.reason,
          result: undefined
        });
      }
      continue;
    }
    const aggregate3Result = result.value;
    for (let j = 0;j < aggregate3Result.length; j++) {
      const { returnData, success } = aggregate3Result[j];
      const { callData } = chunkedCalls[i][j];
      const { abi: abi19, address: address11, functionName, args } = contracts2[results.length];
      try {
        if (callData === "0x")
          throw new AbiDecodingZeroDataError;
        if (!success)
          throw new RawContractError({ data: returnData });
        const result2 = decodeFunctionResult({
          abi: abi19,
          args,
          data: returnData,
          functionName
        });
        results.push(allowFailure ? { result: result2, status: "success" } : result2);
      } catch (err) {
        const error = getContractError(err, {
          abi: abi19,
          address: address11,
          args,
          docsPath: "/docs/contract/multicall",
          functionName
        });
        if (!allowFailure)
          throw error;
        results.push({ error, result: undefined, status: "failure" });
      }
    }
  }
  if (results.length !== contracts2.length)
    throw new BaseError("multicall results mismatch");
  return results;
}

// node_modules/viem/_esm/actions/public/verifyHash.js
init_abis();
init_contracts();
init_contract();
init_encodeDeployData();
init_getAddress();
init_isAddressEqual();
init_isHex();
init_toHex();
init_call();
async function verifyHash(client, parameters) {
  const { address: address11, factory, factoryData, hash: hash3, signature: signature3, universalSignatureVerifierAddress = client.chain?.contracts?.universalSignatureVerifier?.address, ...rest } = parameters;
  const signatureHex = (() => {
    if (isHex(signature3))
      return signature3;
    if (typeof signature3 === "object" && ("r" in signature3) && ("s" in signature3))
      return serializeSignature(signature3);
    return bytesToHex2(signature3);
  })();
  const wrappedSignature = await (async () => {
    if (!factory && !factoryData)
      return signatureHex;
    if (isErc6492Signature(signatureHex))
      return signatureHex;
    return serializeErc6492Signature({
      address: factory,
      data: factoryData,
      signature: signatureHex
    });
  })();
  try {
    const args = universalSignatureVerifierAddress ? {
      to: universalSignatureVerifierAddress,
      data: encodeFunctionData({
        abi: universalSignatureValidatorAbi,
        functionName: "isValidSig",
        args: [address11, hash3, wrappedSignature]
      }),
      ...rest
    } : {
      data: encodeDeployData({
        abi: universalSignatureValidatorAbi,
        args: [address11, hash3, wrappedSignature],
        bytecode: universalSignatureValidatorByteCode
      }),
      ...rest
    };
    const { data: data4 } = await getAction(client, call2, "call")(args);
    return hexToBool(data4 ?? "0x0");
  } catch (error) {
    try {
      const verified = isAddressEqual(getAddress(address11), await recoverAddress({ hash: hash3, signature: signature3 }));
      if (verified)
        return true;
    } catch {
    }
    if (error instanceof CallExecutionError) {
      return false;
    }
    throw error;
  }
}

// node_modules/viem/_esm/actions/public/verifyMessage.js
async function verifyMessage(client, { address: address11, message, factory, factoryData, signature: signature3, ...callRequest }) {
  const hash3 = hashMessage(message);
  return verifyHash(client, {
    address: address11,
    factory,
    factoryData,
    hash: hash3,
    signature: signature3,
    ...callRequest
  });
}

// node_modules/viem/_esm/actions/public/verifyTypedData.js
async function verifyTypedData(client, parameters) {
  const { address: address11, factory, factoryData, signature: signature3, message, primaryType, types, domain, ...callRequest } = parameters;
  const hash3 = hashTypedData2({ message, primaryType, types, domain });
  return verifyHash(client, {
    address: address11,
    factory,
    factoryData,
    hash: hash3,
    signature: signature3,
    ...callRequest
  });
}

// node_modules/viem/_esm/actions/public/waitForTransactionReceipt.js
init_transaction();
init_withResolvers();
init_stringify();

// node_modules/viem/_esm/actions/public/watchBlockNumber.js
init_fromHex();
init_stringify();
function watchBlockNumber(client, { emitOnBegin = false, emitMissed = false, onBlockNumber, onError, poll: poll_, pollingInterval = client.pollingInterval }) {
  const enablePolling = (() => {
    if (typeof poll_ !== "undefined")
      return poll_;
    if (client.transport.type === "webSocket")
      return false;
    if (client.transport.type === "fallback" && client.transport.transports[0].config.type === "webSocket")
      return false;
    return true;
  })();
  let prevBlockNumber;
  const pollBlockNumber = () => {
    const observerId = stringify([
      "watchBlockNumber",
      client.uid,
      emitOnBegin,
      emitMissed,
      pollingInterval
    ]);
    return observe(observerId, { onBlockNumber, onError }, (emit) => poll(async () => {
      try {
        const blockNumber = await getAction(client, getBlockNumber, "getBlockNumber")({ cacheTime: 0 });
        if (prevBlockNumber) {
          if (blockNumber === prevBlockNumber)
            return;
          if (blockNumber - prevBlockNumber > 1 && emitMissed) {
            for (let i = prevBlockNumber + 1n;i < blockNumber; i++) {
              emit.onBlockNumber(i, prevBlockNumber);
              prevBlockNumber = i;
            }
          }
        }
        if (!prevBlockNumber || blockNumber > prevBlockNumber) {
          emit.onBlockNumber(blockNumber, prevBlockNumber);
          prevBlockNumber = blockNumber;
        }
      } catch (err) {
        emit.onError?.(err);
      }
    }, {
      emitOnBegin,
      interval: pollingInterval
    }));
  };
  const subscribeBlockNumber = () => {
    const observerId = stringify([
      "watchBlockNumber",
      client.uid,
      emitOnBegin,
      emitMissed
    ]);
    return observe(observerId, { onBlockNumber, onError }, (emit) => {
      let active = true;
      let unsubscribe = () => active = false;
      (async () => {
        try {
          const transport2 = (() => {
            if (client.transport.type === "fallback") {
              const transport3 = client.transport.transports.find((transport4) => transport4.config.type === "webSocket");
              if (!transport3)
                return client.transport;
              return transport3.value;
            }
            return client.transport;
          })();
          const { unsubscribe: unsubscribe_ } = await transport2.subscribe({
            params: ["newHeads"],
            onData(data4) {
              if (!active)
                return;
              const blockNumber = hexToBigInt(data4.result?.number);
              emit.onBlockNumber(blockNumber, prevBlockNumber);
              prevBlockNumber = blockNumber;
            },
            onError(error) {
              emit.onError?.(error);
            }
          });
          unsubscribe = unsubscribe_;
          if (!active)
            unsubscribe();
        } catch (err) {
          onError?.(err);
        }
      })();
      return () => unsubscribe();
    });
  };
  return enablePolling ? pollBlockNumber() : subscribeBlockNumber();
}

// node_modules/viem/_esm/actions/public/waitForTransactionReceipt.js
async function waitForTransactionReceipt(client, {
  confirmations = 1,
  hash: hash3,
  onReplaced,
  pollingInterval = client.pollingInterval,
  retryCount = 6,
  retryDelay = ({ count }) => ~~(1 << count) * 200,
  timeout = 180000
}) {
  const observerId = stringify(["waitForTransactionReceipt", client.uid, hash3]);
  let transaction14;
  let replacedTransaction;
  let receipt;
  let retrying = false;
  const { promise, resolve, reject } = withResolvers();
  const timer = timeout ? setTimeout(() => reject(new WaitForTransactionReceiptTimeoutError({ hash: hash3 })), timeout) : undefined;
  const _unobserve = observe(observerId, { onReplaced, resolve, reject }, (emit) => {
    const _unwatch = getAction(client, watchBlockNumber, "watchBlockNumber")({
      emitMissed: true,
      emitOnBegin: true,
      poll: true,
      pollingInterval,
      async onBlockNumber(blockNumber_) {
        const done = (fn) => {
          clearTimeout(timer);
          _unwatch();
          fn();
          _unobserve();
        };
        let blockNumber = blockNumber_;
        if (retrying)
          return;
        try {
          if (receipt) {
            if (confirmations > 1 && (!receipt.blockNumber || blockNumber - receipt.blockNumber + 1n < confirmations))
              return;
            done(() => emit.resolve(receipt));
            return;
          }
          if (!transaction14) {
            retrying = true;
            await withRetry(async () => {
              transaction14 = await getAction(client, getTransaction, "getTransaction")({ hash: hash3 });
              if (transaction14.blockNumber)
                blockNumber = transaction14.blockNumber;
            }, {
              delay: retryDelay,
              retryCount
            });
            retrying = false;
          }
          receipt = await getAction(client, getTransactionReceipt, "getTransactionReceipt")({ hash: hash3 });
          if (confirmations > 1 && (!receipt.blockNumber || blockNumber - receipt.blockNumber + 1n < confirmations))
            return;
          done(() => emit.resolve(receipt));
        } catch (err) {
          if (err instanceof TransactionNotFoundError || err instanceof TransactionReceiptNotFoundError) {
            if (!transaction14) {
              retrying = false;
              return;
            }
            try {
              replacedTransaction = transaction14;
              retrying = true;
              const block4 = await withRetry(() => getAction(client, getBlock, "getBlock")({
                blockNumber,
                includeTransactions: true
              }), {
                delay: retryDelay,
                retryCount,
                shouldRetry: ({ error }) => error instanceof BlockNotFoundError
              });
              retrying = false;
              const replacementTransaction = block4.transactions.find(({ from, nonce }) => from === replacedTransaction.from && nonce === replacedTransaction.nonce);
              if (!replacementTransaction)
                return;
              receipt = await getAction(client, getTransactionReceipt, "getTransactionReceipt")({
                hash: replacementTransaction.hash
              });
              if (confirmations > 1 && (!receipt.blockNumber || blockNumber - receipt.blockNumber + 1n < confirmations))
                return;
              let reason = "replaced";
              if (replacementTransaction.to === replacedTransaction.to && replacementTransaction.value === replacedTransaction.value) {
                reason = "repriced";
              } else if (replacementTransaction.from === replacementTransaction.to && replacementTransaction.value === 0n) {
                reason = "cancelled";
              }
              done(() => {
                emit.onReplaced?.({
                  reason,
                  replacedTransaction,
                  transaction: replacementTransaction,
                  transactionReceipt: receipt
                });
                emit.resolve(receipt);
              });
            } catch (err_) {
              done(() => emit.reject(err_));
            }
          } else {
            done(() => emit.reject(err));
          }
        }
      }
    });
  });
  return promise;
}

// node_modules/viem/_esm/actions/public/watchBlocks.js
init_stringify();
function watchBlocks(client, { blockTag = "latest", emitMissed = false, emitOnBegin = false, onBlock, onError, includeTransactions: includeTransactions_, poll: poll_, pollingInterval = client.pollingInterval }) {
  const enablePolling = (() => {
    if (typeof poll_ !== "undefined")
      return poll_;
    if (client.transport.type === "webSocket")
      return false;
    if (client.transport.type === "fallback" && client.transport.transports[0].config.type === "webSocket")
      return false;
    return true;
  })();
  const includeTransactions = includeTransactions_ ?? false;
  let prevBlock;
  const pollBlocks = () => {
    const observerId = stringify([
      "watchBlocks",
      client.uid,
      blockTag,
      emitMissed,
      emitOnBegin,
      includeTransactions,
      pollingInterval
    ]);
    return observe(observerId, { onBlock, onError }, (emit) => poll(async () => {
      try {
        const block4 = await getAction(client, getBlock, "getBlock")({
          blockTag,
          includeTransactions
        });
        if (block4.number && prevBlock?.number) {
          if (block4.number === prevBlock.number)
            return;
          if (block4.number - prevBlock.number > 1 && emitMissed) {
            for (let i = prevBlock?.number + 1n;i < block4.number; i++) {
              const block5 = await getAction(client, getBlock, "getBlock")({
                blockNumber: i,
                includeTransactions
              });
              emit.onBlock(block5, prevBlock);
              prevBlock = block5;
            }
          }
        }
        if (!prevBlock?.number || blockTag === "pending" && !block4?.number || block4.number && block4.number > prevBlock.number) {
          emit.onBlock(block4, prevBlock);
          prevBlock = block4;
        }
      } catch (err) {
        emit.onError?.(err);
      }
    }, {
      emitOnBegin,
      interval: pollingInterval
    }));
  };
  const subscribeBlocks = () => {
    let active = true;
    let emitFetched = true;
    let unsubscribe = () => active = false;
    (async () => {
      try {
        if (emitOnBegin) {
          getAction(client, getBlock, "getBlock")({
            blockTag,
            includeTransactions
          }).then((block4) => {
            if (!active)
              return;
            if (!emitFetched)
              return;
            onBlock(block4, undefined);
            emitFetched = false;
          });
        }
        const transport2 = (() => {
          if (client.transport.type === "fallback") {
            const transport3 = client.transport.transports.find((transport4) => transport4.config.type === "webSocket");
            if (!transport3)
              return client.transport;
            return transport3.value;
          }
          return client.transport;
        })();
        const { unsubscribe: unsubscribe_ } = await transport2.subscribe({
          params: ["newHeads"],
          async onData(data4) {
            if (!active)
              return;
            const block4 = await getAction(client, getBlock, "getBlock")({
              blockNumber: data4.blockNumber,
              includeTransactions
            }).catch(() => {
            });
            if (!active)
              return;
            onBlock(block4, prevBlock);
            emitFetched = false;
            prevBlock = block4;
          },
          onError(error) {
            onError?.(error);
          }
        });
        unsubscribe = unsubscribe_;
        if (!active)
          unsubscribe();
      } catch (err) {
        onError?.(err);
      }
    })();
    return () => unsubscribe();
  };
  return enablePolling ? pollBlocks() : subscribeBlocks();
}

// node_modules/viem/_esm/actions/public/watchEvent.js
init_stringify();
init_abi();
init_rpc();
function watchEvent(client, { address: address11, args, batch = true, event, events, fromBlock, onError, onLogs, poll: poll_, pollingInterval = client.pollingInterval, strict: strict_ }) {
  const enablePolling = (() => {
    if (typeof poll_ !== "undefined")
      return poll_;
    if (typeof fromBlock === "bigint")
      return true;
    if (client.transport.type === "webSocket")
      return false;
    if (client.transport.type === "fallback" && client.transport.transports[0].config.type === "webSocket")
      return false;
    return true;
  })();
  const strict = strict_ ?? false;
  const pollEvent = () => {
    const observerId = stringify([
      "watchEvent",
      address11,
      args,
      batch,
      client.uid,
      event,
      pollingInterval,
      fromBlock
    ]);
    return observe(observerId, { onLogs, onError }, (emit) => {
      let previousBlockNumber;
      if (fromBlock !== undefined)
        previousBlockNumber = fromBlock - 1n;
      let filter;
      let initialized = false;
      const unwatch = poll(async () => {
        if (!initialized) {
          try {
            filter = await getAction(client, createEventFilter, "createEventFilter")({
              address: address11,
              args,
              event,
              events,
              strict,
              fromBlock
            });
          } catch {
          }
          initialized = true;
          return;
        }
        try {
          let logs;
          if (filter) {
            logs = await getAction(client, getFilterChanges, "getFilterChanges")({ filter });
          } else {
            const blockNumber = await getAction(client, getBlockNumber, "getBlockNumber")({});
            if (previousBlockNumber && previousBlockNumber !== blockNumber) {
              logs = await getAction(client, getLogs, "getLogs")({
                address: address11,
                args,
                event,
                events,
                fromBlock: previousBlockNumber + 1n,
                toBlock: blockNumber
              });
            } else {
              logs = [];
            }
            previousBlockNumber = blockNumber;
          }
          if (logs.length === 0)
            return;
          if (batch)
            emit.onLogs(logs);
          else
            for (const log8 of logs)
              emit.onLogs([log8]);
        } catch (err) {
          if (filter && err instanceof InvalidInputRpcError)
            initialized = false;
          emit.onError?.(err);
        }
      }, {
        emitOnBegin: true,
        interval: pollingInterval
      });
      return async () => {
        if (filter)
          await getAction(client, uninstallFilter, "uninstallFilter")({ filter });
        unwatch();
      };
    });
  };
  const subscribeEvent = () => {
    let active = true;
    let unsubscribe = () => active = false;
    (async () => {
      try {
        const transport2 = (() => {
          if (client.transport.type === "fallback") {
            const transport3 = client.transport.transports.find((transport4) => transport4.config.type === "webSocket");
            if (!transport3)
              return client.transport;
            return transport3.value;
          }
          return client.transport;
        })();
        const events_ = events ?? (event ? [event] : undefined);
        let topics = [];
        if (events_) {
          const encoded = events_.flatMap((event2) => encodeEventTopics({
            abi: [event2],
            eventName: event2.name,
            args
          }));
          topics = [encoded];
          if (event)
            topics = topics[0];
        }
        const { unsubscribe: unsubscribe_ } = await transport2.subscribe({
          params: ["logs", { address: address11, topics }],
          onData(data4) {
            if (!active)
              return;
            const log8 = data4.result;
            try {
              const { eventName, args: args2 } = decodeEventLog({
                abi: events_ ?? [],
                data: log8.data,
                topics: log8.topics,
                strict
              });
              const formatted = formatLog(log8, { args: args2, eventName });
              onLogs([formatted]);
            } catch (err) {
              let eventName;
              let isUnnamed;
              if (err instanceof DecodeLogDataMismatch || err instanceof DecodeLogTopicsMismatch) {
                if (strict_)
                  return;
                eventName = err.abiItem.name;
                isUnnamed = err.abiItem.inputs?.some((x) => !(("name" in x) && x.name));
              }
              const formatted = formatLog(log8, {
                args: isUnnamed ? [] : {},
                eventName
              });
              onLogs([formatted]);
            }
          },
          onError(error) {
            onError?.(error);
          }
        });
        unsubscribe = unsubscribe_;
        if (!active)
          unsubscribe();
      } catch (err) {
        onError?.(err);
      }
    })();
    return () => unsubscribe();
  };
  return enablePolling ? pollEvent() : subscribeEvent();
}

// node_modules/viem/_esm/actions/public/watchPendingTransactions.js
init_stringify();
function watchPendingTransactions(client, { batch = true, onError, onTransactions, poll: poll_, pollingInterval = client.pollingInterval }) {
  const enablePolling = typeof poll_ !== "undefined" ? poll_ : client.transport.type !== "webSocket";
  const pollPendingTransactions = () => {
    const observerId = stringify([
      "watchPendingTransactions",
      client.uid,
      batch,
      pollingInterval
    ]);
    return observe(observerId, { onTransactions, onError }, (emit) => {
      let filter;
      const unwatch = poll(async () => {
        try {
          if (!filter) {
            try {
              filter = await getAction(client, createPendingTransactionFilter, "createPendingTransactionFilter")({});
              return;
            } catch (err) {
              unwatch();
              throw err;
            }
          }
          const hashes = await getAction(client, getFilterChanges, "getFilterChanges")({ filter });
          if (hashes.length === 0)
            return;
          if (batch)
            emit.onTransactions(hashes);
          else
            for (const hash3 of hashes)
              emit.onTransactions([hash3]);
        } catch (err) {
          emit.onError?.(err);
        }
      }, {
        emitOnBegin: true,
        interval: pollingInterval
      });
      return async () => {
        if (filter)
          await getAction(client, uninstallFilter, "uninstallFilter")({ filter });
        unwatch();
      };
    });
  };
  const subscribePendingTransactions = () => {
    let active = true;
    let unsubscribe = () => active = false;
    (async () => {
      try {
        const { unsubscribe: unsubscribe_ } = await client.transport.subscribe({
          params: ["newPendingTransactions"],
          onData(data4) {
            if (!active)
              return;
            const transaction14 = data4.result;
            onTransactions([transaction14]);
          },
          onError(error) {
            onError?.(error);
          }
        });
        unsubscribe = unsubscribe_;
        if (!active)
          unsubscribe();
      } catch (err) {
        onError?.(err);
      }
    })();
    return () => unsubscribe();
  };
  return enablePolling ? pollPendingTransactions() : subscribePendingTransactions();
}

// node_modules/viem/_esm/utils/siwe/parseSiweMessage.js
function parseSiweMessage(message) {
  const { scheme, statement, ...prefix } = message.match(prefixRegex)?.groups ?? {};
  const { chainId, expirationTime, issuedAt, notBefore, requestId, ...suffix } = message.match(suffixRegex)?.groups ?? {};
  const resources = message.split("Resources:")[1]?.split("\n- ").slice(1);
  return {
    ...prefix,
    ...suffix,
    ...chainId ? { chainId: Number(chainId) } : {},
    ...expirationTime ? { expirationTime: new Date(expirationTime) } : {},
    ...issuedAt ? { issuedAt: new Date(issuedAt) } : {},
    ...notBefore ? { notBefore: new Date(notBefore) } : {},
    ...requestId ? { requestId } : {},
    ...resources ? { resources } : {},
    ...scheme ? { scheme } : {},
    ...statement ? { statement } : {}
  };
}
var prefixRegex = /^(?:(?<scheme>[a-zA-Z][a-zA-Z0-9+-.]*):\/\/)?(?<domain>[a-zA-Z0-9+-.]*(?::[0-9]{1,5})?) (?:wants you to sign in with your Ethereum account:\n)(?<address>0x[a-fA-F0-9]{40})\n\n(?:(?<statement>.*)\n\n)?/;
var suffixRegex = /(?:URI: (?<uri>.+))\n(?:Version: (?<version>.+))\n(?:Chain ID: (?<chainId>\d+))\n(?:Nonce: (?<nonce>[a-zA-Z0-9]+))\n(?:Issued At: (?<issuedAt>.+))(?:\nExpiration Time: (?<expirationTime>.+))?(?:\nNot Before: (?<notBefore>.+))?(?:\nRequest ID: (?<requestId>.+))?/;

// node_modules/viem/_esm/utils/siwe/validateSiweMessage.js
init_isAddressEqual();
function validateSiweMessage(parameters) {
  const { address: address11, domain, message, nonce, scheme, time = new Date } = parameters;
  if (domain && message.domain !== domain)
    return false;
  if (nonce && message.nonce !== nonce)
    return false;
  if (scheme && message.scheme !== scheme)
    return false;
  if (message.expirationTime && time >= message.expirationTime)
    return false;
  if (message.notBefore && time < message.notBefore)
    return false;
  try {
    if (!message.address)
      return false;
    if (address11 && !isAddressEqual(message.address, address11))
      return false;
  } catch {
    return false;
  }
  return true;
}

// node_modules/viem/_esm/actions/siwe/verifySiweMessage.js
async function verifySiweMessage(client, parameters) {
  const { address: address11, domain, message, nonce, scheme, signature: signature3, time = new Date, ...callRequest } = parameters;
  const parsed = parseSiweMessage(message);
  if (!parsed.address)
    return false;
  const isValid = validateSiweMessage({
    address: address11,
    domain,
    message: parsed,
    nonce,
    scheme,
    time
  });
  if (!isValid)
    return false;
  const hash3 = hashMessage(message);
  return verifyHash(client, {
    address: parsed.address,
    hash: hash3,
    signature: signature3,
    ...callRequest
  });
}

// node_modules/viem/_esm/clients/decorators/public.js
function publicActions(client) {
  return {
    call: (args) => call2(client, args),
    createBlockFilter: () => createBlockFilter(client),
    createContractEventFilter: (args) => createContractEventFilter(client, args),
    createEventFilter: (args) => createEventFilter(client, args),
    createPendingTransactionFilter: () => createPendingTransactionFilter(client),
    estimateContractGas: (args) => estimateContractGas(client, args),
    estimateGas: (args) => estimateGas3(client, args),
    getBalance: (args) => getBalance(client, args),
    getBlobBaseFee: () => getBlobBaseFee(client),
    getBlock: (args) => getBlock(client, args),
    getBlockNumber: (args) => getBlockNumber(client, args),
    getBlockTransactionCount: (args) => getBlockTransactionCount(client, args),
    getBytecode: (args) => getCode(client, args),
    getChainId: () => getChainId(client),
    getCode: (args) => getCode(client, args),
    getContractEvents: (args) => getContractEvents(client, args),
    getEip712Domain: (args) => getEip712Domain(client, args),
    getEnsAddress: (args) => getEnsAddress(client, args),
    getEnsAvatar: (args) => getEnsAvatar(client, args),
    getEnsName: (args) => getEnsName(client, args),
    getEnsResolver: (args) => getEnsResolver(client, args),
    getEnsText: (args) => getEnsText(client, args),
    getFeeHistory: (args) => getFeeHistory(client, args),
    estimateFeesPerGas: (args) => estimateFeesPerGas(client, args),
    getFilterChanges: (args) => getFilterChanges(client, args),
    getFilterLogs: (args) => getFilterLogs(client, args),
    getGasPrice: () => getGasPrice(client),
    getLogs: (args) => getLogs(client, args),
    getProof: (args) => getProof(client, args),
    estimateMaxPriorityFeePerGas: (args) => estimateMaxPriorityFeePerGas(client, args),
    getStorageAt: (args) => getStorageAt(client, args),
    getTransaction: (args) => getTransaction(client, args),
    getTransactionConfirmations: (args) => getTransactionConfirmations(client, args),
    getTransactionCount: (args) => getTransactionCount(client, args),
    getTransactionReceipt: (args) => getTransactionReceipt(client, args),
    multicall: (args) => multicall(client, args),
    prepareTransactionRequest: (args) => prepareTransactionRequest(client, args),
    readContract: (args) => readContract(client, args),
    sendRawTransaction: (args) => sendRawTransaction(client, args),
    simulateContract: (args) => simulateContract(client, args),
    verifyMessage: (args) => verifyMessage(client, args),
    verifySiweMessage: (args) => verifySiweMessage(client, args),
    verifyTypedData: (args) => verifyTypedData(client, args),
    uninstallFilter: (args) => uninstallFilter(client, args),
    waitForTransactionReceipt: (args) => waitForTransactionReceipt(client, args),
    watchBlocks: (args) => watchBlocks(client, args),
    watchBlockNumber: (args) => watchBlockNumber(client, args),
    watchContractEvent: (args) => watchContractEvent(client, args),
    watchEvent: (args) => watchEvent(client, args),
    watchPendingTransactions: (args) => watchPendingTransactions(client, args)
  };
}

// node_modules/viem/_esm/clients/createPublicClient.js
function createPublicClient(parameters) {
  const { key = "public", name = "Public Client" } = parameters;
  const client = createClient({
    ...parameters,
    key,
    name,
    type: "publicClient"
  });
  return client.extend(publicActions);
}
// node_modules/viem/_esm/actions/wallet/deployContract.js
init_encodeDeployData();
function deployContract(walletClient, parameters) {
  const { abi: abi20, args, bytecode, ...request8 } = parameters;
  const calldata = encodeDeployData({ abi: abi20, args, bytecode });
  return sendTransaction(walletClient, {
    ...request8,
    data: calldata
  });
}

// node_modules/viem/_esm/actions/wallet/getAddresses.js
init_getAddress();
async function getAddresses(client) {
  if (client.account?.type === "local")
    return [client.account.address];
  const addresses = await client.request({ method: "eth_accounts" }, { dedupe: true });
  return addresses.map((address11) => checksumAddress(address11));
}

// node_modules/viem/_esm/actions/wallet/getPermissions.js
async function getPermissions(client) {
  const permissions = await client.request({ method: "wallet_getPermissions" }, { dedupe: true });
  return permissions;
}

// node_modules/viem/_esm/actions/wallet/requestAddresses.js
init_getAddress();
async function requestAddresses(client) {
  const addresses = await client.request({ method: "eth_requestAccounts" }, { dedupe: true, retryCount: 0 });
  return addresses.map((address11) => getAddress(address11));
}

// node_modules/viem/_esm/actions/wallet/requestPermissions.js
async function requestPermissions(client, permissions) {
  return client.request({
    method: "wallet_requestPermissions",
    params: [permissions]
  }, { retryCount: 0 });
}

// node_modules/viem/_esm/actions/wallet/signMessage.js
init_parseAccount();
init_toHex();
async function signMessage3(client, { account: account_ = client.account, message }) {
  if (!account_)
    throw new AccountNotFoundError({
      docsPath: "/docs/actions/wallet/signMessage"
    });
  const account4 = parseAccount(account_);
  if (account4.signMessage)
    return account4.signMessage({ message });
  const message_ = (() => {
    if (typeof message === "string")
      return stringToHex(message);
    if (message.raw instanceof Uint8Array)
      return toHex2(message.raw);
    return message.raw;
  })();
  return client.request({
    method: "personal_sign",
    params: [message_, account4.address]
  }, { retryCount: 0 });
}

// node_modules/viem/_esm/actions/wallet/signTransaction.js
init_parseAccount();
init_toHex();
init_transactionRequest();
init_assertRequest();
async function signTransaction3(client, parameters) {
  const { account: account_ = client.account, chain: chain5 = client.chain, ...transaction14 } = parameters;
  if (!account_)
    throw new AccountNotFoundError({
      docsPath: "/docs/actions/wallet/signTransaction"
    });
  const account5 = parseAccount(account_);
  assertRequest({
    account: account5,
    ...parameters
  });
  const chainId = await getAction(client, getChainId, "getChainId")({});
  if (chain5 !== null)
    assertCurrentChain({
      currentChainId: chainId,
      chain: chain5
    });
  const formatters = chain5?.formatters || client.chain?.formatters;
  const format = formatters?.transactionRequest?.format || formatTransactionRequest;
  if (account5.signTransaction)
    return account5.signTransaction({
      ...transaction14,
      chainId
    }, { serializer: client.chain?.serializers?.transaction });
  return await client.request({
    method: "eth_signTransaction",
    params: [
      {
        ...format(transaction14),
        chainId: numberToHex(chainId),
        from: account5.address
      }
    ]
  }, { retryCount: 0 });
}

// node_modules/viem/_esm/actions/wallet/signTypedData.js
init_parseAccount();
async function signTypedData3(client, parameters) {
  const { account: account_ = client.account, domain, message, primaryType } = parameters;
  if (!account_)
    throw new AccountNotFoundError({
      docsPath: "/docs/actions/wallet/signTypedData"
    });
  const account6 = parseAccount(account_);
  const types = {
    EIP712Domain: getTypesForEIP712Domain({ domain }),
    ...parameters.types
  };
  validateTypedData({ domain, message, primaryType, types });
  if (account6.signTypedData)
    return account6.signTypedData({ domain, message, primaryType, types });
  const typedData4 = serializeTypedData({ domain, message, primaryType, types });
  return client.request({
    method: "eth_signTypedData_v4",
    params: [account6.address, typedData4]
  }, { retryCount: 0 });
}

// node_modules/viem/_esm/actions/wallet/switchChain.js
init_toHex();
async function switchChain(client, { id: id2 }) {
  await client.request({
    method: "wallet_switchEthereumChain",
    params: [
      {
        chainId: numberToHex(id2)
      }
    ]
  }, { retryCount: 0 });
}

// node_modules/viem/_esm/actions/wallet/watchAsset.js
async function watchAsset(client, params) {
  const added = await client.request({
    method: "wallet_watchAsset",
    params
  }, { retryCount: 0 });
  return added;
}

// node_modules/viem/_esm/clients/decorators/wallet.js
function walletActions(client) {
  return {
    addChain: (args) => addChain(client, args),
    deployContract: (args) => deployContract(client, args),
    getAddresses: () => getAddresses(client),
    getChainId: () => getChainId(client),
    getPermissions: () => getPermissions(client),
    prepareTransactionRequest: (args) => prepareTransactionRequest(client, args),
    requestAddresses: () => requestAddresses(client),
    requestPermissions: (args) => requestPermissions(client, args),
    sendRawTransaction: (args) => sendRawTransaction(client, args),
    sendTransaction: (args) => sendTransaction(client, args),
    signMessage: (args) => signMessage3(client, args),
    signTransaction: (args) => signTransaction3(client, args),
    signTypedData: (args) => signTypedData3(client, args),
    switchChain: (args) => switchChain(client, args),
    watchAsset: (args) => watchAsset(client, args),
    writeContract: (args) => writeContract(client, args)
  };
}

// node_modules/viem/_esm/clients/createWalletClient.js
function createWalletClient(parameters) {
  const { key = "wallet", name = "Wallet Client", transport: transport2 } = parameters;
  const client = createClient({
    ...parameters,
    key,
    name,
    transport: transport2,
    type: "walletClient"
  });
  return client.extend(walletActions);
}
// node_modules/viem/_esm/constants/address.js
var zeroAddress = "0x0000000000000000000000000000000000000000";
// node_modules/viem/_esm/index.js
init_base();
init_contract();
init_decodeFunctionResult();
init_encodeAbiParameters();
init_encodeFunctionData();
init_toBytes();
init_toHex();
init_concat();
init_getAddress();
init_keccak256();
init_pad();
// node_modules/@biconomy/sdk/dist/_esm/account/utils/Constants.js
var MAGIC_BYTES = "0x6492649264926492649264926492649264926492649264926492649264926492";
var ERROR_MESSAGES = {
  KEY_GEN_DATA_NOT_FOUND: "Key generation data is not available",
  SIGNATURE_NOT_FOUND: "Signature not found from Dan",
  FAILED_COMPUTE_ACCOUNT_ADDRESS: "Failed to compute account address. Possible reasons:\n- The factory contract does not have the function 'computeAccountAddress'\n- The parameters passed to the factory contract function may be invalid\n- The provided factory address is not a contract",
  SIGNER_REQUIRED_FOR_CREATE_SESSION: "Signer is required",
  ACCOUNT_REQUIRED: "Account is required",
  MODULE_NOT_ACTIVATED: "Module not activated",
  SMART_SESSION_DATA_REQUIRED: "Data is required for using smart session module",
  MISSING_ACCOUNT_CONTRACT: 'The contract function "computeAccountAddress" returned no data ("0x")',
  INVALID_HEX: "Invalid hex, if you are targeting a number, consider using pad() and toHex() from viem: pad(toHex(BigInt(2000))",
  CONTRACT_NOT_DEPLOYED: "Address is not a contract. Make sure that the contract you are trying to use is deployed.",
  ACCOUNT_NOT_DEPLOYED: "Account has not yet been deployed",
  ACCOUNT_ALREADY_DEPLOYED: "Account already deployed",
  NO_NATIVE_TOKEN_BALANCE_DURING_DEPLOY: "Smart Account does not have sufficient funds to execute the User Operation.",
  SPENDER_REQUIRED: "spender is required for ERC20 mode",
  NO_FEE_QUOTE: "FeeQuote was not provided, please call smartAccount.getTokenFees() to get feeQuote",
  FAILED_FEE_QUOTE_FETCH: "Failed to fetch fee quote",
  CHAIN_NOT_FOUND: "Chain not found",
  NO_RECIPIENT: "Recipient is required",
  NATIVE_TOKEN_WITHDRAWAL_WITHOUT_AMOUNT: "'Amount' is required for withdrawal of native token without using a paymaster",
  MISSING_RPC_URL: "rpcUrl is required for this signer type, please provide it in the config",
  INVALID_SESSION_INDEXES: "Session indexes and transactions must be of the same length and correspond to each other",
  SIGNER_REQUIRED: "Signer is required for creating a smart account",
  UNKNOW_SESSION_ARGUMENTS: "You have not provided the necessary information to find and use a session"
};
var CALLTYPE_SINGLE = "0x00";
var CALLTYPE_BATCH = "0x01";
var EXECTYPE_DEFAULT = "0x00";
var EXECTYPE_TRY = "0x01";
var EXECTYPE_DELEGATE = "0xFF";
var MODE_DEFAULT = "0x00000000";
var UNUSED = "0x00000000";
var MODE_PAYLOAD = "0x00000000000000000000000000000000000000000000";
var GENERIC_FALLBACK_SELECTOR = "0xcb5baf0f";
var SENTINEL_ADDRESS = "0x0000000000000000000000000000000000000001";
var MODULE_ENABLE_MODE_TYPE_HASH = keccak256(toHex2("ModuleEnableMode(address module, bytes32 initDataHash)"));
var PARENT_TYPEHASH = "TypedDataSign(Contents contents,bytes1 fields,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt,uint256[] extensions)Contents(bytes32 stuff)";
var EXECUTE_SINGLE = concat([
  CALLTYPE_SINGLE,
  EXECTYPE_DEFAULT,
  MODE_DEFAULT,
  UNUSED,
  MODE_PAYLOAD
]);
var EXECUTE_BATCH = concat([
  CALLTYPE_BATCH,
  EXECTYPE_DEFAULT,
  MODE_DEFAULT,
  UNUSED,
  MODE_PAYLOAD
]);
var ACCOUNT_MODES = {
  DEFAULT_SINGLE: concat([
    pad(EXECTYPE_DEFAULT, { size: 1 }),
    pad(CALLTYPE_SINGLE, { size: 1 }),
    pad(UNUSED, { size: 4 }),
    pad(MODE_DEFAULT, { size: 4 }),
    pad(MODE_PAYLOAD, { size: 22 })
  ]),
  DEFAULT_BATCH: concat([
    pad(EXECTYPE_DEFAULT, { size: 1 }),
    pad(CALLTYPE_BATCH, { size: 1 }),
    pad(UNUSED, { size: 4 }),
    pad(MODE_DEFAULT, { size: 4 }),
    pad(MODE_PAYLOAD, { size: 22 })
  ]),
  TRY_BATCH: concat([
    pad(EXECTYPE_TRY, { size: 1 }),
    pad(CALLTYPE_BATCH, { size: 1 }),
    pad(UNUSED, { size: 4 }),
    pad(MODE_DEFAULT, { size: 4 }),
    pad(MODE_PAYLOAD, { size: 22 })
  ]),
  TRY_SINGLE: concat([
    pad(EXECTYPE_TRY, { size: 1 }),
    pad(CALLTYPE_SINGLE, { size: 1 }),
    pad(UNUSED, { size: 4 }),
    pad(MODE_DEFAULT, { size: 4 }),
    pad(MODE_PAYLOAD, { size: 22 })
  ]),
  DELEGATE_SINGLE: concat([
    pad(EXECTYPE_DELEGATE, { size: 1 }),
    pad(CALLTYPE_SINGLE, { size: 1 }),
    pad(UNUSED, { size: 4 }),
    pad(MODE_DEFAULT, { size: 4 }),
    pad(MODE_PAYLOAD, { size: 22 })
  ])
};

// node_modules/@biconomy/sdk/dist/_esm/constants/abi/EntryPointABI.js
var EntrypointAbi = [
  {
    inputs: [
      { internalType: "bool", name: "success", type: "bool" },
      { internalType: "bytes", name: "ret", type: "bytes" }
    ],
    name: "DelegateAndRevert",
    type: "error"
  },
  {
    inputs: [
      { internalType: "uint256", name: "opIndex", type: "uint256" },
      { internalType: "string", name: "reason", type: "string" }
    ],
    name: "FailedOp",
    type: "error"
  },
  {
    inputs: [
      { internalType: "uint256", name: "opIndex", type: "uint256" },
      { internalType: "string", name: "reason", type: "string" },
      { internalType: "bytes", name: "inner", type: "bytes" }
    ],
    name: "FailedOpWithRevert",
    type: "error"
  },
  {
    inputs: [{ internalType: "bytes", name: "returnData", type: "bytes" }],
    name: "PostOpReverted",
    type: "error"
  },
  { inputs: [], name: "ReentrancyGuardReentrantCall", type: "error" },
  {
    inputs: [{ internalType: "address", name: "sender", type: "address" }],
    name: "SenderAddressResult",
    type: "error"
  },
  {
    inputs: [{ internalType: "address", name: "aggregator", type: "address" }],
    name: "SignatureValidationFailed",
    type: "error"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32"
      },
      {
        indexed: true,
        internalType: "address",
        name: "sender",
        type: "address"
      },
      {
        indexed: false,
        internalType: "address",
        name: "factory",
        type: "address"
      },
      {
        indexed: false,
        internalType: "address",
        name: "paymaster",
        type: "address"
      }
    ],
    name: "AccountDeployed",
    type: "event"
  },
  { anonymous: false, inputs: [], name: "BeforeExecution", type: "event" },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "totalDeposit",
        type: "uint256"
      }
    ],
    name: "Deposited",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32"
      },
      {
        indexed: true,
        internalType: "address",
        name: "sender",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "nonce",
        type: "uint256"
      },
      {
        indexed: false,
        internalType: "bytes",
        name: "revertReason",
        type: "bytes"
      }
    ],
    name: "PostOpRevertReason",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "aggregator",
        type: "address"
      }
    ],
    name: "SignatureAggregatorChanged",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "totalStaked",
        type: "uint256"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "unstakeDelaySec",
        type: "uint256"
      }
    ],
    name: "StakeLocked",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "withdrawTime",
        type: "uint256"
      }
    ],
    name: "StakeUnlocked",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address"
      },
      {
        indexed: false,
        internalType: "address",
        name: "withdrawAddress",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "amount",
        type: "uint256"
      }
    ],
    name: "StakeWithdrawn",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32"
      },
      {
        indexed: true,
        internalType: "address",
        name: "sender",
        type: "address"
      },
      {
        indexed: true,
        internalType: "address",
        name: "paymaster",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "nonce",
        type: "uint256"
      },
      { indexed: false, internalType: "bool", name: "success", type: "bool" },
      {
        indexed: false,
        internalType: "uint256",
        name: "actualGasCost",
        type: "uint256"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "actualGasUsed",
        type: "uint256"
      }
    ],
    name: "UserOperationEvent",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32"
      },
      {
        indexed: true,
        internalType: "address",
        name: "sender",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "nonce",
        type: "uint256"
      }
    ],
    name: "UserOperationPrefundTooLow",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32"
      },
      {
        indexed: true,
        internalType: "address",
        name: "sender",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "nonce",
        type: "uint256"
      },
      {
        indexed: false,
        internalType: "bytes",
        name: "revertReason",
        type: "bytes"
      }
    ],
    name: "UserOperationRevertReason",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address"
      },
      {
        indexed: false,
        internalType: "address",
        name: "withdrawAddress",
        type: "address"
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "amount",
        type: "uint256"
      }
    ],
    name: "Withdrawn",
    type: "event"
  },
  {
    inputs: [
      { internalType: "uint32", name: "unstakeDelaySec", type: "uint32" }
    ],
    name: "addStake",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [{ internalType: "address", name: "account", type: "address" }],
    name: "balanceOf",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [
      { internalType: "address", name: "target", type: "address" },
      { internalType: "bytes", name: "data", type: "bytes" }
    ],
    name: "delegateAndRevert",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [{ internalType: "address", name: "account", type: "address" }],
    name: "depositTo",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [{ internalType: "address", name: "", type: "address" }],
    name: "deposits",
    outputs: [
      { internalType: "uint256", name: "deposit", type: "uint256" },
      { internalType: "bool", name: "staked", type: "bool" },
      { internalType: "uint112", name: "stake", type: "uint112" },
      { internalType: "uint32", name: "unstakeDelaySec", type: "uint32" },
      { internalType: "uint48", name: "withdrawTime", type: "uint48" }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "address", name: "account", type: "address" }],
    name: "getDepositInfo",
    outputs: [
      {
        components: [
          { internalType: "uint256", name: "deposit", type: "uint256" },
          { internalType: "bool", name: "staked", type: "bool" },
          { internalType: "uint112", name: "stake", type: "uint112" },
          { internalType: "uint32", name: "unstakeDelaySec", type: "uint32" },
          { internalType: "uint48", name: "withdrawTime", type: "uint48" }
        ],
        internalType: "struct IStakeManager.DepositInfo",
        name: "info",
        type: "tuple"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [
      { internalType: "address", name: "sender", type: "address" },
      { internalType: "uint192", name: "key", type: "uint192" }
    ],
    name: "getNonce",
    outputs: [{ internalType: "uint256", name: "nonce", type: "uint256" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "bytes", name: "initCode", type: "bytes" }],
    name: "getSenderAddress",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      {
        components: [
          { internalType: "address", name: "sender", type: "address" },
          { internalType: "uint256", name: "nonce", type: "uint256" },
          { internalType: "bytes", name: "initCode", type: "bytes" },
          { internalType: "bytes", name: "callData", type: "bytes" },
          {
            internalType: "bytes32",
            name: "accountGasLimits",
            type: "bytes32"
          },
          {
            internalType: "uint256",
            name: "preVerificationGas",
            type: "uint256"
          },
          { internalType: "bytes32", name: "gasFees", type: "bytes32" },
          { internalType: "bytes", name: "paymasterAndData", type: "bytes" },
          { internalType: "bytes", name: "signature", type: "bytes" }
        ],
        internalType: "struct PackedUserOperation",
        name: "userOp",
        type: "tuple"
      }
    ],
    name: "getUserOpHash",
    outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [
      {
        components: [
          {
            components: [
              { internalType: "address", name: "sender", type: "address" },
              { internalType: "uint256", name: "nonce", type: "uint256" },
              { internalType: "bytes", name: "initCode", type: "bytes" },
              { internalType: "bytes", name: "callData", type: "bytes" },
              {
                internalType: "bytes32",
                name: "accountGasLimits",
                type: "bytes32"
              },
              {
                internalType: "uint256",
                name: "preVerificationGas",
                type: "uint256"
              },
              { internalType: "bytes32", name: "gasFees", type: "bytes32" },
              {
                internalType: "bytes",
                name: "paymasterAndData",
                type: "bytes"
              },
              { internalType: "bytes", name: "signature", type: "bytes" }
            ],
            internalType: "struct PackedUserOperation[]",
            name: "userOps",
            type: "tuple[]"
          },
          {
            internalType: "contract IAggregator",
            name: "aggregator",
            type: "address"
          },
          { internalType: "bytes", name: "signature", type: "bytes" }
        ],
        internalType: "struct IEntryPoint.UserOpsPerAggregator[]",
        name: "opsPerAggregator",
        type: "tuple[]"
      },
      { internalType: "address payable", name: "beneficiary", type: "address" }
    ],
    name: "handleAggregatedOps",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      {
        components: [
          { internalType: "address", name: "sender", type: "address" },
          { internalType: "uint256", name: "nonce", type: "uint256" },
          { internalType: "bytes", name: "initCode", type: "bytes" },
          { internalType: "bytes", name: "callData", type: "bytes" },
          {
            internalType: "bytes32",
            name: "accountGasLimits",
            type: "bytes32"
          },
          {
            internalType: "uint256",
            name: "preVerificationGas",
            type: "uint256"
          },
          { internalType: "bytes32", name: "gasFees", type: "bytes32" },
          { internalType: "bytes", name: "paymasterAndData", type: "bytes" },
          { internalType: "bytes", name: "signature", type: "bytes" }
        ],
        internalType: "struct PackedUserOperation[]",
        name: "ops",
        type: "tuple[]"
      },
      { internalType: "address payable", name: "beneficiary", type: "address" }
    ],
    name: "handleOps",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [{ internalType: "uint192", name: "key", type: "uint192" }],
    name: "incrementNonce",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      { internalType: "bytes", name: "callData", type: "bytes" },
      {
        components: [
          {
            components: [
              { internalType: "address", name: "sender", type: "address" },
              { internalType: "uint256", name: "nonce", type: "uint256" },
              {
                internalType: "uint256",
                name: "verificationGasLimit",
                type: "uint256"
              },
              {
                internalType: "uint256",
                name: "callGasLimit",
                type: "uint256"
              },
              {
                internalType: "uint256",
                name: "paymasterVerificationGasLimit",
                type: "uint256"
              },
              {
                internalType: "uint256",
                name: "paymasterPostOpGasLimit",
                type: "uint256"
              },
              {
                internalType: "uint256",
                name: "preVerificationGas",
                type: "uint256"
              },
              { internalType: "address", name: "paymaster", type: "address" },
              {
                internalType: "uint256",
                name: "maxFeePerGas",
                type: "uint256"
              },
              {
                internalType: "uint256",
                name: "maxPriorityFeePerGas",
                type: "uint256"
              }
            ],
            internalType: "struct EntryPoint.MemoryUserOp",
            name: "mUserOp",
            type: "tuple"
          },
          { internalType: "bytes32", name: "userOpHash", type: "bytes32" },
          { internalType: "uint256", name: "prefund", type: "uint256" },
          { internalType: "uint256", name: "contextOffset", type: "uint256" },
          { internalType: "uint256", name: "preOpGas", type: "uint256" }
        ],
        internalType: "struct EntryPoint.UserOpInfo",
        name: "opInfo",
        type: "tuple"
      },
      { internalType: "bytes", name: "context", type: "bytes" }
    ],
    name: "innerHandleOp",
    outputs: [
      { internalType: "uint256", name: "actualGasCost", type: "uint256" }
    ],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      { internalType: "address", name: "", type: "address" },
      { internalType: "uint192", name: "", type: "uint192" }
    ],
    name: "nonceSequenceNumber",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "bytes4", name: "interfaceId", type: "bytes4" }],
    name: "supportsInterface",
    outputs: [{ internalType: "bool", name: "", type: "bool" }],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "unlockStake",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address payable",
        name: "withdrawAddress",
        type: "address"
      }
    ],
    name: "withdrawStake",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address payable",
        name: "withdrawAddress",
        type: "address"
      },
      { internalType: "uint256", name: "withdrawAmount", type: "uint256" }
    ],
    name: "withdrawTo",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  { stateMutability: "payable", type: "receive" }
];

// node_modules/@biconomy/sdk/dist/_esm/constants/abi/K1ValidatorFactoryAbi.js
var K1ValidatorFactoryAbi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "implementation",
        type: "address"
      },
      {
        internalType: "address",
        name: "factoryOwner",
        type: "address"
      },
      {
        internalType: "address",
        name: "k1Validator",
        type: "address"
      },
      {
        internalType: "contract NexusBootstrap",
        name: "bootstrapper",
        type: "address"
      },
      {
        internalType: "contract IERC7484",
        name: "registry",
        type: "address"
      }
    ],
    stateMutability: "nonpayable",
    type: "constructor"
  },
  {
    inputs: [],
    name: "AlreadyInitialized",
    type: "error"
  },
  {
    inputs: [],
    name: "InnerCallFailed",
    type: "error"
  },
  {
    inputs: [],
    name: "InvalidEntryPointAddress",
    type: "error"
  },
  {
    inputs: [],
    name: "NewOwnerIsZeroAddress",
    type: "error"
  },
  {
    inputs: [],
    name: "NoHandoverRequest",
    type: "error"
  },
  {
    inputs: [],
    name: "Unauthorized",
    type: "error"
  },
  {
    inputs: [],
    name: "ZeroAddressNotAllowed",
    type: "error"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address"
      },
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address"
      },
      {
        indexed: true,
        internalType: "uint256",
        name: "index",
        type: "uint256"
      }
    ],
    name: "AccountCreated",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "pendingOwner",
        type: "address"
      }
    ],
    name: "OwnershipHandoverCanceled",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "pendingOwner",
        type: "address"
      }
    ],
    name: "OwnershipHandoverRequested",
    type: "event"
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "oldOwner",
        type: "address"
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address"
      }
    ],
    name: "OwnershipTransferred",
    type: "event"
  },
  {
    inputs: [],
    name: "ACCOUNT_IMPLEMENTATION",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "BOOTSTRAPPER",
    outputs: [
      {
        internalType: "contract NexusBootstrap",
        name: "",
        type: "address"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "K1_VALIDATOR",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "REGISTRY",
    outputs: [
      {
        internalType: "contract IERC7484",
        name: "",
        type: "address"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "epAddress",
        type: "address"
      },
      {
        internalType: "uint32",
        name: "unstakeDelaySec",
        type: "uint32"
      }
    ],
    name: "addStake",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [],
    name: "cancelOwnershipHandover",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "pendingOwner",
        type: "address"
      }
    ],
    name: "completeOwnershipHandover",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "eoaOwner",
        type: "address"
      },
      {
        internalType: "uint256",
        name: "index",
        type: "uint256"
      },
      {
        internalType: "address[]",
        name: "attesters",
        type: "address[]"
      },
      {
        internalType: "uint8",
        name: "threshold",
        type: "uint8"
      }
    ],
    name: "computeAccountAddress",
    outputs: [
      {
        internalType: "address payable",
        name: "expectedAddress",
        type: "address"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "eoaOwner",
        type: "address"
      },
      {
        internalType: "uint256",
        name: "index",
        type: "uint256"
      },
      {
        internalType: "address[]",
        name: "attesters",
        type: "address[]"
      },
      {
        internalType: "uint8",
        name: "threshold",
        type: "uint8"
      }
    ],
    name: "createAccount",
    outputs: [
      {
        internalType: "address payable",
        name: "",
        type: "address"
      }
    ],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [],
    name: "owner",
    outputs: [
      {
        internalType: "address",
        name: "result",
        type: "address"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "pendingOwner",
        type: "address"
      }
    ],
    name: "ownershipHandoverExpiresAt",
    outputs: [
      {
        internalType: "uint256",
        name: "result",
        type: "uint256"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [],
    name: "renounceOwnership",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [],
    name: "requestOwnershipHandover",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address"
      }
    ],
    name: "transferOwnership",
    outputs: [],
    stateMutability: "payable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "epAddress",
        type: "address"
      }
    ],
    name: "unlockStake",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "epAddress",
        type: "address"
      },
      {
        internalType: "address payable",
        name: "withdrawAddress",
        type: "address"
      }
    ],
    name: "withdrawStake",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  }
];

// node_modules/@biconomy/sdk/dist/_esm/account/utils/Utils.js
function packUserOp(userOperation) {
  const hashedInitCode = keccak256(userOperation.factory && userOperation.factoryData ? concat([userOperation.factory, userOperation.factoryData]) : "0x");
  const hashedCallData = keccak256(userOperation.callData ?? "0x");
  const hashedPaymasterAndData = keccak256(userOperation.paymaster ? concat([
    userOperation.paymaster,
    pad(toHex2(userOperation.paymasterVerificationGasLimit || BigInt(0)), {
      size: 16
    }),
    pad(toHex2(userOperation.paymasterPostOpGasLimit || BigInt(0)), {
      size: 16
    }),
    userOperation.paymasterData || "0x"
  ]) : "0x");
  return encodeAbiParameters([
    { type: "address" },
    { type: "uint256" },
    { type: "bytes32" },
    { type: "bytes32" },
    { type: "bytes32" },
    { type: "uint256" },
    { type: "bytes32" },
    { type: "bytes32" }
  ], [
    userOperation.sender,
    userOperation.nonce ?? 0n,
    hashedInitCode,
    hashedCallData,
    concat([
      pad(toHex2(userOperation.verificationGasLimit ?? 0n), {
        size: 16
      }),
      pad(toHex2(userOperation.callGasLimit ?? 0n), { size: 16 })
    ]),
    userOperation.preVerificationGas ?? 0n,
    concat([
      pad(toHex2(userOperation.maxPriorityFeePerGas ?? 0n), {
        size: 16
      }),
      pad(toHex2(userOperation.maxFeePerGas ?? 0n), { size: 16 })
    ]),
    hashedPaymasterAndData
  ]);
}
function getTypesForEIP712Domain2({ domain }) {
  return [
    typeof domain?.name === "string" && { name: "name", type: "string" },
    domain?.version && { name: "version", type: "string" },
    typeof domain?.chainId === "number" && {
      name: "chainId",
      type: "uint256"
    },
    domain?.verifyingContract && {
      name: "verifyingContract",
      type: "address"
    },
    domain?.salt && { name: "salt", type: "bytes32" }
  ].filter(Boolean);
}
function typeToString(typeDef) {
  return Object.entries(typeDef).map(([key, fields]) => {
    const fieldStrings = (fields ?? []).map((field) => `${field.type} ${field.name}`).join(",");
    return `${key}(${fieldStrings})`;
  });
}
var isNullOrUndefined = (value) => {
  return value === null || value === undefined;
};
var addressEquals = (a, b) => !!a && !!b && a?.toLowerCase() === b.toLowerCase();
var eip712WrapHash = (typedHash, appDomainSeparator) => keccak256(concat(["0x1901", appDomainSeparator, typedHash]));
var getAccountDomainStructFields = async (publicClient, accountAddress) => {
  const accountDomainStructFields = await publicClient.readContract({
    address: accountAddress,
    abi: parseAbi([
      "function eip712Domain() public view returns (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] memory extensions)"
    ]),
    functionName: "eip712Domain"
  });
  const [fields, name, version5, chainId, verifyingContract, salt, extensions] = accountDomainStructFields;
  const params = parseAbiParameters([
    "bytes1, bytes32, bytes32, uint256, address, bytes32, bytes32"
  ]);
  return encodeAbiParameters(params, [
    fields,
    keccak256(toBytes2(name)),
    keccak256(toBytes2(version5)),
    chainId,
    verifyingContract,
    salt,
    keccak256(encodePacked(["uint256[]"], [extensions]))
  ]);
};
var playgroundTrue = process?.env?.RUN_PLAYGROUND === "true";
var isTesting = process?.env?.TEST === "true";

// node_modules/viem/_esm/op-stack/contracts.js
var contracts3 = {
  gasPriceOracle: { address: "0x420000000000000000000000000000000000000F" },
  l1Block: { address: "0x4200000000000000000000000000000000000015" },
  l2CrossDomainMessenger: {
    address: "0x4200000000000000000000000000000000000007"
  },
  l2Erc721Bridge: { address: "0x4200000000000000000000000000000000000014" },
  l2StandardBridge: { address: "0x4200000000000000000000000000000000000010" },
  l2ToL1MessagePasser: {
    address: "0x4200000000000000000000000000000000000016"
  }
};

// node_modules/viem/_esm/op-stack/formatters.js
init_fromHex();
var formatters = {
  block: defineBlock({
    format(args) {
      const transactions = args.transactions?.map((transaction15) => {
        if (typeof transaction15 === "string")
          return transaction15;
        const formatted = formatTransaction(transaction15);
        if (formatted.typeHex === "0x7e") {
          formatted.isSystemTx = transaction15.isSystemTx;
          formatted.mint = transaction15.mint ? hexToBigInt(transaction15.mint) : undefined;
          formatted.sourceHash = transaction15.sourceHash;
          formatted.type = "deposit";
        }
        return formatted;
      });
      return {
        transactions,
        stateRoot: args.stateRoot
      };
    }
  }),
  transaction: defineTransaction({
    format(args) {
      const transaction15 = {};
      if (args.type === "0x7e") {
        transaction15.isSystemTx = args.isSystemTx;
        transaction15.mint = args.mint ? hexToBigInt(args.mint) : undefined;
        transaction15.sourceHash = args.sourceHash;
        transaction15.type = "deposit";
      }
      return transaction15;
    }
  }),
  transactionReceipt: defineTransactionReceipt({
    format(args) {
      return {
        l1GasPrice: args.l1GasPrice ? hexToBigInt(args.l1GasPrice) : null,
        l1GasUsed: args.l1GasUsed ? hexToBigInt(args.l1GasUsed) : null,
        l1Fee: args.l1Fee ? hexToBigInt(args.l1Fee) : null,
        l1FeeScalar: args.l1FeeScalar ? Number(args.l1FeeScalar) : null
      };
    }
  })
};

// node_modules/viem/_esm/op-stack/serializers.js
init_address();
init_isAddress();
init_concat();
init_toHex();
function serializeTransaction5(transaction15, signature3) {
  if (isDeposit(transaction15))
    return serializeTransactionDeposit(transaction15);
  return serializeTransaction2(transaction15, signature3);
}
var serializeTransactionDeposit = function(transaction15) {
  assertTransactionDeposit(transaction15);
  const { sourceHash, data: data4, from, gas, isSystemTx, mint, to, value } = transaction15;
  const serializedTransaction = [
    sourceHash,
    from,
    to ?? "0x",
    mint ? toHex2(mint) : "0x",
    value ? toHex2(value) : "0x",
    gas ? toHex2(gas) : "0x",
    isSystemTx ? "0x1" : "0x",
    data4 ?? "0x"
  ];
  return concatHex([
    "0x7e",
    toRlp(serializedTransaction)
  ]);
};
var isDeposit = function(transaction15) {
  if (transaction15.type === "deposit")
    return true;
  if (typeof transaction15.sourceHash !== "undefined")
    return true;
  return false;
};
function assertTransactionDeposit(transaction15) {
  const { from, to } = transaction15;
  if (from && !isAddress2(from))
    throw new InvalidAddressError({ address: from });
  if (to && !isAddress2(to))
    throw new InvalidAddressError({ address: to });
}
var serializers = {
  transaction: serializeTransaction5
};

// node_modules/viem/_esm/op-stack/chainConfig.js
var chainConfig = {
  contracts: contracts3,
  formatters,
  serializers
};

// node_modules/viem/_esm/chains/definitions/baseSepolia.js
var sourceId = 11155111;
var baseSepolia = defineChain({
  ...chainConfig,
  id: 84532,
  network: "base-sepolia",
  name: "Base Sepolia",
  nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: {
    default: {
      http: ["https://sepolia.base.org"]
    }
  },
  blockExplorers: {
    default: {
      name: "Basescan",
      url: "https://sepolia.basescan.org",
      apiUrl: "https://api-sepolia.basescan.org/api"
    }
  },
  contracts: {
    ...chainConfig.contracts,
    disputeGameFactory: {
      [sourceId]: {
        address: "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1"
      }
    },
    l2OutputOracle: {
      [sourceId]: {
        address: "0x84457ca9D0163FbC4bbfe4Dfbb20ba46e48DF254"
      }
    },
    portal: {
      [sourceId]: {
        address: "0x49f53e41452c74589e85ca1677426ba426459e85",
        blockCreated: 4446677
      }
    },
    l1StandardBridge: {
      [sourceId]: {
        address: "0xfd0Bf71F60660E2f608ed56e1659C450eB113120",
        blockCreated: 4446677
      }
    },
    multicall3: {
      address: "0xca11bde05977b3631167028862be2a173976ca11",
      blockCreated: 1059647
    }
  },
  testnet: true,
  sourceId
});
// node_modules/viem/_esm/actions/index.js
init_call();
// node_modules/@biconomy/sdk/dist/_esm/account/utils/toSigner.js
async function toSigner({ signer, address: address12 }) {
  if ("provider" in signer) {
    return toAccount({
      address: getAddress(await signer.getAddress()),
      async signMessage({ message }) {
        if (typeof message === "string") {
          return await signer.signMessage(message);
        }
        if (typeof message.raw === "string") {
          return await signer.signMessage(hexToBytes2(message.raw));
        }
        return await signer.signMessage(message.raw);
      },
      async signTransaction(_) {
        throw new Error("Not supported");
      },
      async signTypedData(typedData4) {
        return signer.signTypedData(typedData4.domain, typedData4.types, typedData4.message);
      }
    });
  }
  if (("type" in signer) && ["local", "dan"].includes(signer.type)) {
    return signer;
  }
  let walletClient = undefined;
  if ("request" in signer) {
    if (!address12) {
      try {
        [address12] = await signer.request({
          method: "eth_requestAccounts"
        });
      } catch {
        [address12] = await signer.request({
          method: "eth_accounts"
        });
      }
    }
    if (!address12)
      throw new Error("address required");
    walletClient = createWalletClient({
      account: address12,
      transport: custom(signer)
    });
  }
  if (!walletClient) {
    walletClient = signer;
  }
  return toAccount({
    address: walletClient.account.address,
    async signMessage({ message }) {
      return walletClient.signMessage({ message });
    },
    async signTypedData(typedData4) {
      return getAction(walletClient, signTypedData3, "signTypedData")(typedData4);
    },
    async signTransaction(_) {
      throw new Error("Not supported");
    }
  });
}

// node_modules/viem/_esm/account-abstraction/utils/userOperation/getUserOperationHash.js
init_encodeAbiParameters();
init_concat();
init_pad();
init_toHex();
init_keccak256();
function getUserOperationHash(parameters) {
  const { chainId, entryPointAddress, entryPointVersion } = parameters;
  const userOperation = parameters.userOperation;
  const { callData, callGasLimit, initCode, maxFeePerGas, maxPriorityFeePerGas, nonce, paymasterAndData, preVerificationGas, sender, verificationGasLimit } = userOperation;
  const packedUserOp = (() => {
    if (entryPointVersion === "0.6") {
      return encodeAbiParameters([
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "bytes32" }
      ], [
        sender,
        nonce,
        keccak256(initCode ?? "0x"),
        keccak256(callData ?? "0x"),
        callGasLimit,
        verificationGasLimit,
        preVerificationGas,
        maxFeePerGas,
        maxPriorityFeePerGas,
        keccak256(paymasterAndData ?? "0x")
      ]);
    }
    if (entryPointVersion === "0.7") {
      const accountGasLimits = concat([
        pad(numberToHex(userOperation.verificationGasLimit), { size: 16 }),
        pad(numberToHex(userOperation.callGasLimit), { size: 16 })
      ]);
      const callData_hashed = keccak256(callData);
      const gasFees = concat([
        pad(numberToHex(userOperation.maxPriorityFeePerGas), { size: 16 }),
        pad(numberToHex(userOperation.maxFeePerGas), { size: 16 })
      ]);
      const initCode_hashed = keccak256(userOperation.factory && userOperation.factoryData ? concat([userOperation.factory, userOperation.factoryData]) : "0x");
      const paymasterAndData_hashed = keccak256(userOperation.paymaster ? concat([
        userOperation.paymaster,
        pad(numberToHex(userOperation.paymasterVerificationGasLimit || 0), {
          size: 16
        }),
        pad(numberToHex(userOperation.paymasterPostOpGasLimit || 0), {
          size: 16
        }),
        userOperation.paymasterData || "0x"
      ]) : "0x");
      return encodeAbiParameters([
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" }
      ], [
        sender,
        nonce,
        initCode_hashed,
        callData_hashed,
        accountGasLimits,
        preVerificationGas,
        gasFees,
        paymasterAndData_hashed
      ]);
    }
    throw new Error(`entryPointVersion "${entryPointVersion}" not supported.`);
  })();
  return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "address" }, { type: "uint256" }], [keccak256(packedUserOp), entryPointAddress, BigInt(chainId)]));
}

// node_modules/viem/_esm/account-abstraction/accounts/toSmartAccount.js
init_exports();
async function toSmartAccount(implementation) {
  const { extend, nonceKeyManager = createNonceManager({
    source: {
      get() {
        return Date.now();
      },
      set() {
      }
    }
  }), ...rest } = implementation;
  let deployed = false;
  const address12 = await implementation.getAddress();
  return {
    ...extend,
    ...rest,
    address: address12,
    async getFactoryArgs() {
      if (("isDeployed" in this) && await this.isDeployed())
        return { factory: undefined, factoryData: undefined };
      return implementation.getFactoryArgs();
    },
    async getNonce(parameters) {
      const key = parameters?.key ?? BigInt(await nonceKeyManager.consume({
        address: address12,
        chainId: implementation.client.chain.id,
        client: implementation.client
      }));
      if (implementation.getNonce)
        return await implementation.getNonce({ ...parameters, key });
      const nonce = await readContract(implementation.client, {
        abi: parseAbi([
          "function getNonce(address, uint192) pure returns (uint256)"
        ]),
        address: implementation.entryPoint.address,
        functionName: "getNonce",
        args: [address12, key]
      });
      return nonce;
    },
    async isDeployed() {
      if (deployed)
        return true;
      const code = await getAction(implementation.client, getCode, "getCode")({
        address: address12
      });
      deployed = Boolean(code);
      return deployed;
    },
    ...implementation.sign ? {
      async sign(parameters) {
        const [{ factory, factoryData }, signature3] = await Promise.all([
          this.getFactoryArgs(),
          implementation.sign(parameters)
        ]);
        if (factory && factoryData)
          return serializeErc6492Signature({
            address: factory,
            data: factoryData,
            signature: signature3
          });
        return signature3;
      }
    } : {},
    async signMessage(parameters) {
      const [{ factory, factoryData }, signature3] = await Promise.all([
        this.getFactoryArgs(),
        implementation.signMessage(parameters)
      ]);
      if (factory && factoryData)
        return serializeErc6492Signature({
          address: factory,
          data: factoryData,
          signature: signature3
        });
      return signature3;
    },
    async signTypedData(parameters) {
      const [{ factory, factoryData }, signature3] = await Promise.all([
        this.getFactoryArgs(),
        implementation.signTypedData(parameters)
      ]);
      if (factory && factoryData)
        return serializeErc6492Signature({
          address: factory,
          data: factoryData,
          signature: signature3
        });
      return signature3;
    },
    type: "smart"
  };
}
// node_modules/viem/_esm/account-abstraction/actions/bundler/estimateUserOperationGas.js
init_parseAccount();
init_stateOverride2();

// node_modules/viem/_esm/account-abstraction/utils/errors/getUserOperationError.js
init_base();
init_contract();
init_decodeErrorResult();

// node_modules/viem/_esm/account-abstraction/errors/bundler.js
init_base();

class AccountNotDeployedError extends BaseError {
  constructor({ cause }) {
    super("Smart Account is not deployed.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- No `factory`/`factoryData` or `initCode` properties are provided for Smart Account deployment.",
        "- An incorrect `sender` address is provided."
      ],
      name: "AccountNotDeployedError"
    });
  }
}
Object.defineProperty(AccountNotDeployedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa20/
});

class ExecutionRevertedError2 extends BaseError {
  constructor({ cause, message } = {}) {
    const reason = message?.replace("execution reverted: ", "")?.replace("execution reverted", "");
    super(`Execution reverted ${reason ? `with reason: ${reason}` : "for an unknown reason"}.`, {
      cause,
      name: "ExecutionRevertedError"
    });
  }
}
Object.defineProperty(ExecutionRevertedError2, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32521
});
Object.defineProperty(ExecutionRevertedError2, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /execution reverted/
});

class FailedToSendToBeneficiaryError extends BaseError {
  constructor({ cause }) {
    super("Failed to send funds to beneficiary.", {
      cause,
      name: "FailedToSendToBeneficiaryError"
    });
  }
}
Object.defineProperty(FailedToSendToBeneficiaryError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa91/
});

class GasValuesOverflowError extends BaseError {
  constructor({ cause }) {
    super("Gas value overflowed.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- one of the gas values exceeded 2**120 (uint120)"
      ].filter(Boolean),
      name: "GasValuesOverflowError"
    });
  }
}
Object.defineProperty(GasValuesOverflowError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa94/
});

class HandleOpsOutOfGasError extends BaseError {
  constructor({ cause }) {
    super("The `handleOps` function was called by the Bundler with a gas limit too low.", {
      cause,
      name: "HandleOpsOutOfGasError"
    });
  }
}
Object.defineProperty(HandleOpsOutOfGasError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa95/
});

class InitCodeFailedError extends BaseError {
  constructor({ cause, factory, factoryData, initCode }) {
    super("Failed to simulate deployment for Smart Account.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- Invalid `factory`/`factoryData` or `initCode` properties are present",
        "- Smart Account deployment execution ran out of gas (low `verificationGasLimit` value)",
        "- Smart Account deployment execution reverted with an error\n",
        factory && `factory: ${factory}`,
        factoryData && `factoryData: ${factoryData}`,
        initCode && `initCode: ${initCode}`
      ].filter(Boolean),
      name: "InitCodeFailedError"
    });
  }
}
Object.defineProperty(InitCodeFailedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa13/
});

class InitCodeMustCreateSenderError extends BaseError {
  constructor({ cause, factory, factoryData, initCode }) {
    super("Smart Account initialization implementation did not create an account.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- `factory`/`factoryData` or `initCode` properties are invalid",
        "- Smart Account initialization implementation is incorrect\n",
        factory && `factory: ${factory}`,
        factoryData && `factoryData: ${factoryData}`,
        initCode && `initCode: ${initCode}`
      ].filter(Boolean),
      name: "InitCodeMustCreateSenderError"
    });
  }
}
Object.defineProperty(InitCodeMustCreateSenderError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa15/
});

class InitCodeMustReturnSenderError extends BaseError {
  constructor({ cause, factory, factoryData, initCode, sender }) {
    super("Smart Account initialization implementation does not return the expected sender.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "Smart Account initialization implementation does not return a sender address\n",
        factory && `factory: ${factory}`,
        factoryData && `factoryData: ${factoryData}`,
        initCode && `initCode: ${initCode}`,
        sender && `sender: ${sender}`
      ].filter(Boolean),
      name: "InitCodeMustReturnSenderError"
    });
  }
}
Object.defineProperty(InitCodeMustReturnSenderError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa14/
});

class InsufficientPrefundError extends BaseError {
  constructor({ cause }) {
    super("Smart Account does not have sufficient funds to execute the User Operation.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the Smart Account does not have sufficient funds to cover the required prefund, or",
        "- a Paymaster was not provided"
      ].filter(Boolean),
      name: "InsufficientPrefundError"
    });
  }
}
Object.defineProperty(InsufficientPrefundError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa21/
});

class InternalCallOnlyError extends BaseError {
  constructor({ cause }) {
    super("Bundler attempted to call an invalid function on the EntryPoint.", {
      cause,
      name: "InternalCallOnlyError"
    });
  }
}
Object.defineProperty(InternalCallOnlyError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa92/
});

class InvalidAggregatorError extends BaseError {
  constructor({ cause }) {
    super("Bundler used an invalid aggregator for handling aggregated User Operations.", {
      cause,
      name: "InvalidAggregatorError"
    });
  }
}
Object.defineProperty(InvalidAggregatorError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa96/
});

class InvalidAccountNonceError extends BaseError {
  constructor({ cause, nonce }) {
    super("Invalid Smart Account nonce used for User Operation.", {
      cause,
      metaMessages: [nonce && `nonce: ${nonce}`].filter(Boolean),
      name: "InvalidAccountNonceError"
    });
  }
}
Object.defineProperty(InvalidAccountNonceError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa25/
});

class InvalidBeneficiaryError extends BaseError {
  constructor({ cause }) {
    super("Bundler has not set a beneficiary address.", {
      cause,
      name: "InvalidBeneficiaryError"
    });
  }
}
Object.defineProperty(InvalidBeneficiaryError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa90/
});

class InvalidFieldsError extends BaseError {
  constructor({ cause }) {
    super("Invalid fields set on User Operation.", {
      cause,
      name: "InvalidFieldsError"
    });
  }
}
Object.defineProperty(InvalidFieldsError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32602
});

class InvalidPaymasterAndDataError extends BaseError {
  constructor({ cause, paymasterAndData }) {
    super("Paymaster properties provided are invalid.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the `paymasterAndData` property is of an incorrect length\n",
        paymasterAndData && `paymasterAndData: ${paymasterAndData}`
      ].filter(Boolean),
      name: "InvalidPaymasterAndDataError"
    });
  }
}
Object.defineProperty(InvalidPaymasterAndDataError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa93/
});

class PaymasterDepositTooLowError extends BaseError {
  constructor({ cause }) {
    super("Paymaster deposit for the User Operation is too low.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the Paymaster has deposited less than the expected amount via the `deposit` function"
      ].filter(Boolean),
      name: "PaymasterDepositTooLowError"
    });
  }
}
Object.defineProperty(PaymasterDepositTooLowError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32508
});
Object.defineProperty(PaymasterDepositTooLowError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa31/
});

class PaymasterFunctionRevertedError extends BaseError {
  constructor({ cause }) {
    super("The `validatePaymasterUserOp` function on the Paymaster reverted.", {
      cause,
      name: "PaymasterFunctionRevertedError"
    });
  }
}
Object.defineProperty(PaymasterFunctionRevertedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa33/
});

class PaymasterNotDeployedError extends BaseError {
  constructor({ cause }) {
    super("The Paymaster contract has not been deployed.", {
      cause,
      name: "PaymasterNotDeployedError"
    });
  }
}
Object.defineProperty(PaymasterNotDeployedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa30/
});

class PaymasterRateLimitError extends BaseError {
  constructor({ cause }) {
    super("UserOperation rejected because paymaster (or signature aggregator) is throttled/banned.", {
      cause,
      name: "PaymasterRateLimitError"
    });
  }
}
Object.defineProperty(PaymasterRateLimitError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32504
});

class PaymasterStakeTooLowError extends BaseError {
  constructor({ cause }) {
    super("UserOperation rejected because paymaster (or signature aggregator) is throttled/banned.", {
      cause,
      name: "PaymasterStakeTooLowError"
    });
  }
}
Object.defineProperty(PaymasterStakeTooLowError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32505
});

class PaymasterPostOpFunctionRevertedError extends BaseError {
  constructor({ cause }) {
    super("Paymaster `postOp` function reverted.", {
      cause,
      name: "PaymasterPostOpFunctionRevertedError"
    });
  }
}
Object.defineProperty(PaymasterPostOpFunctionRevertedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa50/
});

class SenderAlreadyConstructedError extends BaseError {
  constructor({ cause, factory, factoryData, initCode }) {
    super("Smart Account has already been deployed.", {
      cause,
      metaMessages: [
        "Remove the following properties and try again:",
        factory && "`factory`",
        factoryData && "`factoryData`",
        initCode && "`initCode`"
      ].filter(Boolean),
      name: "SenderAlreadyConstructedError"
    });
  }
}
Object.defineProperty(SenderAlreadyConstructedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa10/
});

class SignatureCheckFailedError extends BaseError {
  constructor({ cause }) {
    super("UserOperation rejected because account signature check failed (or paymaster signature, if the paymaster uses its data as signature).", {
      cause,
      name: "SignatureCheckFailedError"
    });
  }
}
Object.defineProperty(SignatureCheckFailedError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32507
});

class SmartAccountFunctionRevertedError extends BaseError {
  constructor({ cause }) {
    super("The `validateUserOp` function on the Smart Account reverted.", {
      cause,
      name: "SmartAccountFunctionRevertedError"
    });
  }
}
Object.defineProperty(SmartAccountFunctionRevertedError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa23/
});

class UnsupportedSignatureAggregatorError extends BaseError {
  constructor({ cause }) {
    super("UserOperation rejected because account specified unsupported signature aggregator.", {
      cause,
      name: "UnsupportedSignatureAggregatorError"
    });
  }
}
Object.defineProperty(UnsupportedSignatureAggregatorError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32506
});

class UserOperationExpiredError extends BaseError {
  constructor({ cause }) {
    super("User Operation expired.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the `validAfter` or `validUntil` values returned from `validateUserOp` on the Smart Account are not satisfied"
      ].filter(Boolean),
      name: "UserOperationExpiredError"
    });
  }
}
Object.defineProperty(UserOperationExpiredError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa22/
});

class UserOperationPaymasterExpiredError extends BaseError {
  constructor({ cause }) {
    super("Paymaster for User Operation expired.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the `validAfter` or `validUntil` values returned from `validatePaymasterUserOp` on the Paymaster are not satisfied"
      ].filter(Boolean),
      name: "UserOperationPaymasterExpiredError"
    });
  }
}
Object.defineProperty(UserOperationPaymasterExpiredError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa32/
});

class UserOperationSignatureError extends BaseError {
  constructor({ cause }) {
    super("Signature provided for the User Operation is invalid.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the `signature` for the User Operation is incorrectly computed, and unable to be verified by the Smart Account"
      ].filter(Boolean),
      name: "UserOperationSignatureError"
    });
  }
}
Object.defineProperty(UserOperationSignatureError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa24/
});

class UserOperationPaymasterSignatureError extends BaseError {
  constructor({ cause }) {
    super("Signature provided for the User Operation is invalid.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the `signature` for the User Operation is incorrectly computed, and unable to be verified by the Paymaster"
      ].filter(Boolean),
      name: "UserOperationPaymasterSignatureError"
    });
  }
}
Object.defineProperty(UserOperationPaymasterSignatureError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa34/
});

class UserOperationRejectedByEntryPointError extends BaseError {
  constructor({ cause }) {
    super("User Operation rejected by EntryPoint's `simulateValidation` during account creation or validation.", {
      cause,
      name: "UserOperationRejectedByEntryPointError"
    });
  }
}
Object.defineProperty(UserOperationRejectedByEntryPointError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32500
});

class UserOperationRejectedByPaymasterError extends BaseError {
  constructor({ cause }) {
    super("User Operation rejected by Paymaster's `validatePaymasterUserOp`.", {
      cause,
      name: "UserOperationRejectedByPaymasterError"
    });
  }
}
Object.defineProperty(UserOperationRejectedByPaymasterError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32501
});

class UserOperationRejectedByOpCodeError extends BaseError {
  constructor({ cause }) {
    super("User Operation rejected with op code validation error.", {
      cause,
      name: "UserOperationRejectedByOpCodeError"
    });
  }
}
Object.defineProperty(UserOperationRejectedByOpCodeError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32502
});

class UserOperationOutOfTimeRangeError extends BaseError {
  constructor({ cause }) {
    super("UserOperation out of time-range: either wallet or paymaster returned a time-range, and it is already expired (or will expire soon).", {
      cause,
      name: "UserOperationOutOfTimeRangeError"
    });
  }
}
Object.defineProperty(UserOperationOutOfTimeRangeError, "code", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: -32503
});

class UnknownBundlerError extends BaseError {
  constructor({ cause }) {
    super(`An error occurred while executing user operation: ${cause?.shortMessage}`, {
      cause,
      name: "UnknownBundlerError"
    });
  }
}

class VerificationGasLimitExceededError extends BaseError {
  constructor({ cause }) {
    super("User Operation verification gas limit exceeded.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the gas used for verification exceeded the `verificationGasLimit`"
      ].filter(Boolean),
      name: "VerificationGasLimitExceededError"
    });
  }
}
Object.defineProperty(VerificationGasLimitExceededError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa40/
});

class VerificationGasLimitTooLowError extends BaseError {
  constructor({ cause }) {
    super("User Operation verification gas limit is too low.", {
      cause,
      metaMessages: [
        "This could arise when:",
        "- the `verificationGasLimit` is too low to verify the User Operation"
      ].filter(Boolean),
      name: "VerificationGasLimitTooLowError"
    });
  }
}
Object.defineProperty(VerificationGasLimitTooLowError, "message", {
  enumerable: true,
  configurable: true,
  writable: true,
  value: /aa41/
});

// node_modules/viem/_esm/account-abstraction/errors/userOperation.js
init_base();
init_transaction();
class UserOperationExecutionError extends BaseError {
  constructor(cause, { callData, callGasLimit, docsPath: docsPath6, factory, factoryData, initCode, maxFeePerGas, maxPriorityFeePerGas, nonce, paymaster, paymasterAndData, paymasterData, paymasterPostOpGasLimit, paymasterVerificationGasLimit, preVerificationGas, sender, signature: signature3, verificationGasLimit }) {
    const prettyArgs = prettyPrint({
      callData,
      callGasLimit,
      factory,
      factoryData,
      initCode,
      maxFeePerGas: typeof maxFeePerGas !== "undefined" && `${formatGwei(maxFeePerGas)} gwei`,
      maxPriorityFeePerGas: typeof maxPriorityFeePerGas !== "undefined" && `${formatGwei(maxPriorityFeePerGas)} gwei`,
      nonce,
      paymaster,
      paymasterAndData,
      paymasterData,
      paymasterPostOpGasLimit,
      paymasterVerificationGasLimit,
      preVerificationGas,
      sender,
      signature: signature3,
      verificationGasLimit
    });
    super(cause.shortMessage, {
      cause,
      docsPath: docsPath6,
      metaMessages: [
        ...cause.metaMessages ? [...cause.metaMessages, " "] : [],
        "Request Arguments:",
        prettyArgs
      ].filter(Boolean),
      name: "UserOperationExecutionError"
    });
    Object.defineProperty(this, "cause", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.cause = cause;
  }
}

class UserOperationReceiptNotFoundError extends BaseError {
  constructor({ hash: hash3 }) {
    super(`User Operation receipt with hash "${hash3}" could not be found. The User Operation may not have been processed yet.`, { name: "UserOperationReceiptNotFoundError" });
  }
}

class UserOperationNotFoundError extends BaseError {
  constructor({ hash: hash3 }) {
    super(`User Operation with hash "${hash3}" could not be found.`, {
      name: "UserOperationNotFoundError"
    });
  }
}

class WaitForUserOperationReceiptTimeoutError extends BaseError {
  constructor({ hash: hash3 }) {
    super(`Timed out while waiting for User Operation with hash "${hash3}" to be confirmed.`, { name: "WaitForUserOperationReceiptTimeoutError" });
  }
}

// node_modules/viem/_esm/account-abstraction/utils/errors/getBundlerError.js
function getBundlerError(err, args) {
  const message = (err.details || "").toLowerCase();
  if (AccountNotDeployedError.message.test(message))
    return new AccountNotDeployedError({
      cause: err
    });
  if (FailedToSendToBeneficiaryError.message.test(message))
    return new FailedToSendToBeneficiaryError({
      cause: err
    });
  if (GasValuesOverflowError.message.test(message))
    return new GasValuesOverflowError({
      cause: err
    });
  if (HandleOpsOutOfGasError.message.test(message))
    return new HandleOpsOutOfGasError({
      cause: err
    });
  if (InitCodeFailedError.message.test(message))
    return new InitCodeFailedError({
      cause: err,
      factory: args.factory,
      factoryData: args.factoryData,
      initCode: args.initCode
    });
  if (InitCodeMustCreateSenderError.message.test(message))
    return new InitCodeMustCreateSenderError({
      cause: err,
      factory: args.factory,
      factoryData: args.factoryData,
      initCode: args.initCode
    });
  if (InitCodeMustReturnSenderError.message.test(message))
    return new InitCodeMustReturnSenderError({
      cause: err,
      factory: args.factory,
      factoryData: args.factoryData,
      initCode: args.initCode,
      sender: args.sender
    });
  if (InsufficientPrefundError.message.test(message))
    return new InsufficientPrefundError({
      cause: err
    });
  if (InternalCallOnlyError.message.test(message))
    return new InternalCallOnlyError({
      cause: err
    });
  if (InvalidAccountNonceError.message.test(message))
    return new InvalidAccountNonceError({
      cause: err,
      nonce: args.nonce
    });
  if (InvalidAggregatorError.message.test(message))
    return new InvalidAggregatorError({
      cause: err
    });
  if (InvalidBeneficiaryError.message.test(message))
    return new InvalidBeneficiaryError({
      cause: err
    });
  if (InvalidPaymasterAndDataError.message.test(message))
    return new InvalidPaymasterAndDataError({
      cause: err
    });
  if (PaymasterDepositTooLowError.message.test(message))
    return new PaymasterDepositTooLowError({
      cause: err
    });
  if (PaymasterFunctionRevertedError.message.test(message))
    return new PaymasterFunctionRevertedError({
      cause: err
    });
  if (PaymasterNotDeployedError.message.test(message))
    return new PaymasterNotDeployedError({
      cause: err
    });
  if (PaymasterPostOpFunctionRevertedError.message.test(message))
    return new PaymasterPostOpFunctionRevertedError({
      cause: err
    });
  if (SmartAccountFunctionRevertedError.message.test(message))
    return new SmartAccountFunctionRevertedError({
      cause: err
    });
  if (SenderAlreadyConstructedError.message.test(message))
    return new SenderAlreadyConstructedError({
      cause: err,
      factory: args.factory,
      factoryData: args.factoryData,
      initCode: args.initCode
    });
  if (UserOperationExpiredError.message.test(message))
    return new UserOperationExpiredError({
      cause: err
    });
  if (UserOperationPaymasterExpiredError.message.test(message))
    return new UserOperationPaymasterExpiredError({
      cause: err
    });
  if (UserOperationPaymasterSignatureError.message.test(message))
    return new UserOperationPaymasterSignatureError({
      cause: err
    });
  if (UserOperationSignatureError.message.test(message))
    return new UserOperationSignatureError({
      cause: err
    });
  if (VerificationGasLimitExceededError.message.test(message))
    return new VerificationGasLimitExceededError({
      cause: err
    });
  if (VerificationGasLimitTooLowError.message.test(message))
    return new VerificationGasLimitTooLowError({
      cause: err
    });
  const error = err.walk((e) => bundlerErrors.some((error2) => error2.code === e.code));
  if (error) {
    if (error.code === ExecutionRevertedError2.code)
      return new ExecutionRevertedError2({
        cause: err,
        message: error.details
      });
    if (error.code === InvalidFieldsError.code)
      return new InvalidFieldsError({
        cause: err
      });
    if (error.code === PaymasterDepositTooLowError.code)
      return new PaymasterDepositTooLowError({
        cause: err
      });
    if (error.code === PaymasterRateLimitError.code)
      return new PaymasterRateLimitError({
        cause: err
      });
    if (error.code === PaymasterStakeTooLowError.code)
      return new PaymasterStakeTooLowError({
        cause: err
      });
    if (error.code === SignatureCheckFailedError.code)
      return new SignatureCheckFailedError({
        cause: err
      });
    if (error.code === UnsupportedSignatureAggregatorError.code)
      return new UnsupportedSignatureAggregatorError({
        cause: err
      });
    if (error.code === UserOperationOutOfTimeRangeError.code)
      return new UserOperationOutOfTimeRangeError({
        cause: err
      });
    if (error.code === UserOperationRejectedByEntryPointError.code)
      return new UserOperationRejectedByEntryPointError({
        cause: err
      });
    if (error.code === UserOperationRejectedByPaymasterError.code)
      return new UserOperationRejectedByPaymasterError({
        cause: err
      });
    if (error.code === UserOperationRejectedByOpCodeError.code)
      return new UserOperationRejectedByOpCodeError({
        cause: err
      });
  }
  return new UnknownBundlerError({
    cause: err
  });
}
var bundlerErrors = [
  ExecutionRevertedError2,
  InvalidFieldsError,
  PaymasterDepositTooLowError,
  PaymasterRateLimitError,
  PaymasterStakeTooLowError,
  SignatureCheckFailedError,
  UnsupportedSignatureAggregatorError,
  UserOperationOutOfTimeRangeError,
  UserOperationRejectedByEntryPointError,
  UserOperationRejectedByPaymasterError,
  UserOperationRejectedByOpCodeError
];

// node_modules/viem/_esm/account-abstraction/utils/errors/getUserOperationError.js
function getUserOperationError(err, { calls, docsPath: docsPath6, ...args }) {
  const cause = (() => {
    const cause2 = getBundlerError(err, args);
    if (calls && cause2 instanceof ExecutionRevertedError2) {
      const revertData = getRevertData(cause2);
      const contractCalls = calls?.filter((call7) => call7.abi || call7.data);
      if (revertData && contractCalls.length > 0)
        return getContractError7({ calls: contractCalls, revertData });
    }
    return cause2;
  })();
  return new UserOperationExecutionError(cause, {
    docsPath: docsPath6,
    ...args
  });
}
var getRevertData = function(error) {
  let revertData;
  error.walk((e) => {
    const error2 = e;
    if (typeof error2.data === "string" || typeof error2.data?.revertData === "string" || !(error2 instanceof BaseError) && typeof error2.message === "string") {
      const match = (error2.data?.revertData || error2.data || error2.message).match?.(/(0x[A-Za-z0-9]*)/);
      if (match) {
        revertData = match[1];
        return true;
      }
    }
    return false;
  });
  return revertData;
};
var getContractError7 = function(parameters) {
  const { calls, revertData } = parameters;
  const { abi: abi20, functionName, args, to } = (() => {
    const contractCalls = calls?.filter((call7) => Boolean(call7.abi));
    if (contractCalls.length === 1)
      return contractCalls[0];
    const compatContractCalls = contractCalls.filter((call7) => {
      try {
        return Boolean(decodeErrorResult({
          abi: call7.abi,
          data: revertData
        }));
      } catch {
        return false;
      }
    });
    if (compatContractCalls.length === 1)
      return compatContractCalls[0];
    return {
      abi: [],
      functionName: contractCalls.reduce((acc, call7) => `${acc ? `${acc} | ` : ""}${call7.functionName}`, ""),
      args: undefined,
      to: undefined
    };
  })();
  const cause = (() => {
    if (revertData === "0x")
      return new ContractFunctionZeroDataError({ functionName });
    return new ContractFunctionRevertedError({
      abi: abi20,
      data: revertData,
      functionName
    });
  })();
  return new ContractFunctionExecutionError(cause, {
    abi: abi20,
    args,
    contractAddress: to,
    functionName
  });
};

// node_modules/viem/_esm/account-abstraction/utils/formatters/userOperationGas.js
function formatUserOperationGas(parameters) {
  const gas = {};
  if (parameters.callGasLimit)
    gas.callGasLimit = BigInt(parameters.callGasLimit);
  if (parameters.preVerificationGas)
    gas.preVerificationGas = BigInt(parameters.preVerificationGas);
  if (parameters.verificationGasLimit)
    gas.verificationGasLimit = BigInt(parameters.verificationGasLimit);
  if (parameters.paymasterPostOpGasLimit)
    gas.paymasterPostOpGasLimit = BigInt(parameters.paymasterPostOpGasLimit);
  if (parameters.paymasterVerificationGasLimit)
    gas.paymasterVerificationGasLimit = BigInt(parameters.paymasterVerificationGasLimit);
  return gas;
}

// node_modules/viem/_esm/account-abstraction/utils/formatters/userOperationRequest.js
init_toHex();
function formatUserOperationRequest(request8) {
  const rpcRequest = {};
  if (typeof request8.callData !== "undefined")
    rpcRequest.callData = request8.callData;
  if (typeof request8.callGasLimit !== "undefined")
    rpcRequest.callGasLimit = numberToHex(request8.callGasLimit);
  if (typeof request8.factory !== "undefined")
    rpcRequest.factory = request8.factory;
  if (typeof request8.factoryData !== "undefined")
    rpcRequest.factoryData = request8.factoryData;
  if (typeof request8.initCode !== "undefined")
    rpcRequest.initCode = request8.initCode;
  if (typeof request8.maxFeePerGas !== "undefined")
    rpcRequest.maxFeePerGas = numberToHex(request8.maxFeePerGas);
  if (typeof request8.maxPriorityFeePerGas !== "undefined")
    rpcRequest.maxPriorityFeePerGas = numberToHex(request8.maxPriorityFeePerGas);
  if (typeof request8.nonce !== "undefined")
    rpcRequest.nonce = numberToHex(request8.nonce);
  if (typeof request8.paymaster !== "undefined")
    rpcRequest.paymaster = request8.paymaster;
  if (typeof request8.paymasterAndData !== "undefined")
    rpcRequest.paymasterAndData = request8.paymasterAndData || "0x";
  if (typeof request8.paymasterData !== "undefined")
    rpcRequest.paymasterData = request8.paymasterData;
  if (typeof request8.paymasterPostOpGasLimit !== "undefined")
    rpcRequest.paymasterPostOpGasLimit = numberToHex(request8.paymasterPostOpGasLimit);
  if (typeof request8.paymasterVerificationGasLimit !== "undefined")
    rpcRequest.paymasterVerificationGasLimit = numberToHex(request8.paymasterVerificationGasLimit);
  if (typeof request8.preVerificationGas !== "undefined")
    rpcRequest.preVerificationGas = numberToHex(request8.preVerificationGas);
  if (typeof request8.sender !== "undefined")
    rpcRequest.sender = request8.sender;
  if (typeof request8.signature !== "undefined")
    rpcRequest.signature = request8.signature;
  if (typeof request8.verificationGasLimit !== "undefined")
    rpcRequest.verificationGasLimit = numberToHex(request8.verificationGasLimit);
  return rpcRequest;
}

// node_modules/viem/_esm/account-abstraction/actions/bundler/prepareUserOperation.js
init_parseAccount();
init_encodeFunctionData();
init_concat();

// node_modules/viem/_esm/account-abstraction/actions/paymaster/getPaymasterData.js
init_fromHex();
init_toHex();
async function getPaymasterData(client, parameters) {
  const { chainId, entryPointAddress, context: context3, ...userOperation2 } = parameters;
  const request8 = formatUserOperationRequest(userOperation2);
  const { paymasterPostOpGasLimit, paymasterVerificationGasLimit, ...rest } = await client.request({
    method: "pm_getPaymasterData",
    params: [
      {
        ...request8,
        callGasLimit: request8.callGasLimit ?? "0x0",
        verificationGasLimit: request8.verificationGasLimit ?? "0x0",
        preVerificationGas: request8.preVerificationGas ?? "0x0"
      },
      entryPointAddress,
      numberToHex(chainId),
      context3
    ]
  });
  return {
    ...rest,
    ...paymasterPostOpGasLimit && {
      paymasterPostOpGasLimit: hexToBigInt(paymasterPostOpGasLimit)
    },
    ...paymasterVerificationGasLimit && {
      paymasterVerificationGasLimit: hexToBigInt(paymasterVerificationGasLimit)
    }
  };
}

// node_modules/viem/_esm/account-abstraction/actions/paymaster/getPaymasterStubData.js
init_fromHex();
init_toHex();
async function getPaymasterStubData(client, parameters) {
  const { chainId, entryPointAddress, context: context3, ...userOperation2 } = parameters;
  const request8 = formatUserOperationRequest(userOperation2);
  const { paymasterPostOpGasLimit, paymasterVerificationGasLimit, ...rest } = await client.request({
    method: "pm_getPaymasterStubData",
    params: [
      {
        ...request8,
        callGasLimit: request8.callGasLimit ?? "0x0",
        verificationGasLimit: request8.verificationGasLimit ?? "0x0",
        preVerificationGas: request8.preVerificationGas ?? "0x0"
      },
      entryPointAddress,
      numberToHex(chainId),
      context3
    ]
  });
  return {
    ...rest,
    ...paymasterPostOpGasLimit && {
      paymasterPostOpGasLimit: hexToBigInt(paymasterPostOpGasLimit)
    },
    ...paymasterVerificationGasLimit && {
      paymasterVerificationGasLimit: hexToBigInt(paymasterVerificationGasLimit)
    }
  };
}

// node_modules/viem/_esm/account-abstraction/actions/bundler/prepareUserOperation.js
async function prepareUserOperation(client, parameters_) {
  const parameters = parameters_;
  const { account: account_ = client.account, parameters: properties = defaultParameters2, stateOverride: stateOverride5 } = parameters;
  if (!account_)
    throw new AccountNotFoundError;
  const account7 = parseAccount(account_);
  const bundlerClient = client;
  const paymaster = parameters.paymaster ?? bundlerClient?.paymaster;
  const paymasterAddress = typeof paymaster === "string" ? paymaster : undefined;
  const { getPaymasterStubData: getPaymasterStubData3, getPaymasterData: getPaymasterData3 } = (() => {
    if (paymaster === true)
      return {
        getPaymasterStubData: (parameters2) => getAction(bundlerClient, getPaymasterStubData, "getPaymasterStubData")(parameters2),
        getPaymasterData: (parameters2) => getAction(bundlerClient, getPaymasterData, "getPaymasterData")(parameters2)
      };
    if (typeof paymaster === "object") {
      const { getPaymasterStubData: getPaymasterStubData4, getPaymasterData: getPaymasterData4 } = paymaster;
      return {
        getPaymasterStubData: getPaymasterData4 && getPaymasterStubData4 ? getPaymasterStubData4 : getPaymasterData4,
        getPaymasterData: getPaymasterData4 && getPaymasterStubData4 ? getPaymasterData4 : undefined
      };
    }
    return {
      getPaymasterStubData: undefined,
      getPaymasterData: undefined
    };
  })();
  const paymasterContext = parameters.paymasterContext ? parameters.paymasterContext : bundlerClient?.paymasterContext;
  let request8 = {
    ...parameters,
    paymaster: paymasterAddress,
    sender: account7.address
  };
  const [callData, factory, fees, nonce] = await Promise.all([
    (async () => {
      if (parameters.calls)
        return account7.encodeCalls(parameters.calls.map((call_) => {
          const call7 = call_;
          if ("abi" in call7)
            return {
              data: encodeFunctionData(call7),
              to: call7.to,
              value: call7.value
            };
          return call7;
        }));
      return parameters.callData;
    })(),
    (async () => {
      if (!properties.includes("factory"))
        return;
      if (parameters.initCode)
        return { initCode: parameters.initCode };
      if (parameters.factory && parameters.factoryData) {
        return {
          factory: parameters.factory,
          factoryData: parameters.factoryData
        };
      }
      const { factory: factory2, factoryData } = await account7.getFactoryArgs();
      if (account7.entryPoint.version === "0.6")
        return {
          initCode: factory2 && factoryData ? concat([factory2, factoryData]) : undefined
        };
      return {
        factory: factory2,
        factoryData
      };
    })(),
    (async () => {
      if (!properties.includes("fees"))
        return;
      if (typeof parameters.maxFeePerGas === "bigint" && typeof parameters.maxPriorityFeePerGas === "bigint")
        return request8;
      if (bundlerClient?.userOperation?.estimateFeesPerGas) {
        const fees2 = await bundlerClient.userOperation.estimateFeesPerGas({
          account: account7,
          bundlerClient,
          userOperation: request8
        });
        return {
          ...request8,
          ...fees2
        };
      }
      try {
        const client_ = bundlerClient.client ?? client;
        const fees2 = await getAction(client_, estimateFeesPerGas, "estimateFeesPerGas")({
          chain: client_.chain,
          type: "eip1559"
        });
        return {
          maxFeePerGas: typeof parameters.maxFeePerGas === "bigint" ? parameters.maxFeePerGas : BigInt(Math.max(Number(2n * fees2.maxFeePerGas), Number(parseGwei("3")))),
          maxPriorityFeePerGas: typeof parameters.maxPriorityFeePerGas === "bigint" ? parameters.maxPriorityFeePerGas : BigInt(Math.max(Number(2n * fees2.maxPriorityFeePerGas), Number(parseGwei("1"))))
        };
      } catch {
        return;
      }
    })(),
    (async () => {
      if (!properties.includes("nonce"))
        return;
      if (typeof parameters.nonce === "bigint")
        return parameters.nonce;
      return account7.getNonce();
    })()
  ]);
  if (typeof callData !== "undefined")
    request8.callData = callData;
  if (typeof factory !== "undefined")
    request8 = { ...request8, ...factory };
  if (typeof fees !== "undefined")
    request8 = { ...request8, ...fees };
  if (typeof nonce !== "undefined")
    request8.nonce = nonce;
  if (properties.includes("signature")) {
    if (typeof parameters.signature !== "undefined")
      request8.signature = parameters.signature;
    else
      request8.signature = await account7.getStubSignature(request8);
  }
  if (account7.entryPoint.version === "0.6" && !request8.initCode)
    request8.initCode = "0x";
  let chainId;
  async function getChainId8() {
    if (chainId)
      return chainId;
    if (client.chain)
      return client.chain.id;
    const chainId_ = await getAction(client, getChainId, "getChainId")({});
    chainId = chainId_;
    return chainId;
  }
  let isPaymasterPopulated = false;
  if (properties.includes("paymaster") && getPaymasterStubData3 && !paymasterAddress && !parameters.paymasterAndData) {
    const { isFinal = false, sponsor, ...paymasterArgs } = await getPaymasterStubData3({
      chainId: await getChainId8(),
      entryPointAddress: account7.entryPoint.address,
      context: paymasterContext,
      ...request8
    });
    isPaymasterPopulated = isFinal;
    request8 = {
      ...request8,
      ...paymasterArgs
    };
  }
  if (account7.entryPoint.version === "0.6" && !request8.paymasterAndData)
    request8.paymasterAndData = "0x";
  if (properties.includes("gas")) {
    if (account7.userOperation?.estimateGas) {
      const gas = await account7.userOperation.estimateGas(request8);
      request8 = {
        ...request8,
        ...gas
      };
    }
    if (typeof request8.callGasLimit === "undefined" || typeof request8.preVerificationGas === "undefined" || typeof request8.verificationGasLimit === "undefined" || request8.paymaster && typeof request8.paymasterPostOpGasLimit === "undefined" || request8.paymaster && typeof request8.paymasterVerificationGasLimit === "undefined") {
      const gas = await getAction(bundlerClient, estimateUserOperationGas2, "estimateUserOperationGas")({
        account: account7,
        callGasLimit: 0n,
        preVerificationGas: 0n,
        verificationGasLimit: 0n,
        stateOverride: stateOverride5,
        ...request8.paymaster ? {
          paymasterPostOpGasLimit: 0n,
          paymasterVerificationGasLimit: 0n
        } : {},
        ...request8
      });
      request8 = {
        ...request8,
        callGasLimit: request8.callGasLimit ?? gas.callGasLimit,
        preVerificationGas: request8.preVerificationGas ?? gas.preVerificationGas,
        verificationGasLimit: request8.verificationGasLimit ?? gas.verificationGasLimit,
        paymasterPostOpGasLimit: request8.paymasterPostOpGasLimit ?? gas.paymasterPostOpGasLimit,
        paymasterVerificationGasLimit: request8.paymasterVerificationGasLimit ?? gas.paymasterVerificationGasLimit
      };
    }
  }
  if (properties.includes("paymaster") && getPaymasterData3 && !paymasterAddress && !parameters.paymasterAndData && !isPaymasterPopulated) {
    const paymaster2 = await getPaymasterData3({
      chainId: await getChainId8(),
      entryPointAddress: account7.entryPoint.address,
      context: paymasterContext,
      ...request8
    });
    request8 = {
      ...request8,
      ...paymaster2
    };
  }
  delete request8.calls;
  delete request8.parameters;
  delete request8.paymasterContext;
  if (typeof request8.paymaster !== "string")
    delete request8.paymaster;
  return request8;
}
var defaultParameters2 = [
  "factory",
  "fees",
  "gas",
  "paymaster",
  "nonce",
  "signature"
];

// node_modules/viem/_esm/account-abstraction/actions/bundler/estimateUserOperationGas.js
async function estimateUserOperationGas2(client, parameters) {
  const { account: account_ = client.account, entryPointAddress, stateOverride: stateOverride6 } = parameters;
  if (!account_ && !parameters.sender)
    throw new AccountNotFoundError;
  const account8 = account_ ? parseAccount(account_) : undefined;
  const rpcStateOverride = serializeStateOverride(stateOverride6);
  const request8 = account8 ? await getAction(client, prepareUserOperation, "prepareUserOperation")({
    ...parameters,
    parameters: ["factory", "nonce", "paymaster", "signature"]
  }) : parameters;
  try {
    const params = [
      formatUserOperationRequest(request8),
      entryPointAddress ?? account8?.entryPoint?.address
    ];
    const result = await client.request({
      method: "eth_estimateUserOperationGas",
      params: rpcStateOverride ? [...params, rpcStateOverride] : [...params]
    });
    return formatUserOperationGas(result);
  } catch (error) {
    const calls = parameters.calls;
    throw getUserOperationError(error, {
      ...request8,
      ...calls ? { calls } : {}
    });
  }
}

// node_modules/viem/_esm/account-abstraction/actions/bundler/getSupportedEntryPoints.js
function getSupportedEntryPoints(client) {
  return client.request({ method: "eth_supportedEntryPoints" });
}

// node_modules/viem/_esm/account-abstraction/utils/formatters/userOperation.js
function formatUserOperation(parameters) {
  const userOperation2 = { ...parameters };
  if (parameters.callGasLimit)
    userOperation2.callGasLimit = BigInt(parameters.callGasLimit);
  if (parameters.maxFeePerGas)
    userOperation2.maxFeePerGas = BigInt(parameters.maxFeePerGas);
  if (parameters.maxPriorityFeePerGas)
    userOperation2.maxPriorityFeePerGas = BigInt(parameters.maxPriorityFeePerGas);
  if (parameters.nonce)
    userOperation2.nonce = BigInt(parameters.nonce);
  if (parameters.paymasterPostOpGasLimit)
    userOperation2.paymasterPostOpGasLimit = BigInt(parameters.paymasterPostOpGasLimit);
  if (parameters.paymasterVerificationGasLimit)
    userOperation2.paymasterVerificationGasLimit = BigInt(parameters.paymasterVerificationGasLimit);
  if (parameters.preVerificationGas)
    userOperation2.preVerificationGas = BigInt(parameters.preVerificationGas);
  if (parameters.verificationGasLimit)
    userOperation2.verificationGasLimit = BigInt(parameters.verificationGasLimit);
  return userOperation2;
}

// node_modules/viem/_esm/account-abstraction/actions/bundler/getUserOperation.js
async function getUserOperation(client, { hash: hash3 }) {
  const result = await client.request({
    method: "eth_getUserOperationByHash",
    params: [hash3]
  }, { dedupe: true });
  if (!result)
    throw new UserOperationNotFoundError({ hash: hash3 });
  const { blockHash, blockNumber, entryPoint, transactionHash, userOperation: userOperation4 } = result;
  return {
    blockHash,
    blockNumber: BigInt(blockNumber),
    entryPoint,
    transactionHash,
    userOperation: formatUserOperation(userOperation4)
  };
}

// node_modules/viem/_esm/account-abstraction/utils/formatters/userOperationReceipt.js
function formatUserOperationReceipt(parameters) {
  const receipt = { ...parameters };
  if (parameters.actualGasCost)
    receipt.actualGasCost = BigInt(parameters.actualGasCost);
  if (parameters.actualGasUsed)
    receipt.actualGasUsed = BigInt(parameters.actualGasUsed);
  if (parameters.logs)
    receipt.logs = parameters.logs.map((log9) => formatLog(log9));
  if (parameters.receipt)
    receipt.receipt = formatTransactionReceipt(receipt.receipt);
  return receipt;
}

// node_modules/viem/_esm/account-abstraction/actions/bundler/getUserOperationReceipt.js
async function getUserOperationReceipt(client, { hash: hash3 }) {
  const receipt = await client.request({
    method: "eth_getUserOperationReceipt",
    params: [hash3]
  }, { dedupe: true });
  if (!receipt)
    throw new UserOperationReceiptNotFoundError({ hash: hash3 });
  return formatUserOperationReceipt(receipt);
}

// node_modules/viem/_esm/account-abstraction/actions/bundler/sendUserOperation.js
init_parseAccount();
async function sendUserOperation(client, parameters) {
  const { account: account_ = client.account, entryPointAddress } = parameters;
  if (!account_ && !parameters.sender)
    throw new AccountNotFoundError;
  const account9 = account_ ? parseAccount(account_) : undefined;
  const request8 = account9 ? await getAction(client, prepareUserOperation, "prepareUserOperation")(parameters) : parameters;
  const signature3 = parameters.signature || await account9?.signUserOperation(request8);
  const rpcParameters = formatUserOperationRequest({
    ...request8,
    signature: signature3
  });
  try {
    return await client.request({
      method: "eth_sendUserOperation",
      params: [
        rpcParameters,
        entryPointAddress ?? account9?.entryPoint.address
      ]
    }, { retryCount: 0 });
  } catch (error) {
    const calls = parameters.calls;
    throw getUserOperationError(error, {
      ...request8,
      ...calls ? { calls } : {},
      signature: signature3
    });
  }
}
// node_modules/viem/_esm/account-abstraction/actions/bundler/waitForUserOperationReceipt.js
init_stringify();
function waitForUserOperationReceipt(client, parameters) {
  const { hash: hash3, pollingInterval = client.pollingInterval, retryCount, timeout = 120000 } = parameters;
  let count = 0;
  const observerId = stringify([
    "waitForUserOperationReceipt",
    client.uid,
    hash3
  ]);
  return new Promise((resolve, reject) => {
    const unobserve = observe(observerId, { resolve, reject }, (emit) => {
      const done = (fn) => {
        unpoll();
        fn();
        unobserve();
      };
      const unpoll = poll(async () => {
        if (retryCount && count >= retryCount)
          done(() => emit.reject(new WaitForUserOperationReceiptTimeoutError({ hash: hash3 })));
        try {
          const receipt = await getAction(client, getUserOperationReceipt, "getUserOperationReceipt")({ hash: hash3 });
          done(() => emit.resolve(receipt));
        } catch (err) {
          const error = err;
          if (error.name !== "UserOperationReceiptNotFoundError")
            done(() => emit.reject(error));
        }
        count++;
      }, {
        emitOnBegin: true,
        interval: pollingInterval
      });
      if (timeout)
        setTimeout(() => done(() => emit.reject(new WaitForUserOperationReceiptTimeoutError({ hash: hash3 }))), timeout);
      return unpoll;
    });
  });
}
// node_modules/viem/_esm/account-abstraction/clients/decorators/bundler.js
function bundlerActions(client) {
  return {
    estimateUserOperationGas: (parameters) => estimateUserOperationGas2(client, parameters),
    getChainId: () => getChainId(client),
    getSupportedEntryPoints: () => getSupportedEntryPoints(client),
    getUserOperation: (parameters) => getUserOperation(client, parameters),
    getUserOperationReceipt: (parameters) => getUserOperationReceipt(client, parameters),
    prepareUserOperation: (parameters) => prepareUserOperation(client, parameters),
    sendUserOperation: (parameters) => sendUserOperation(client, parameters),
    waitForUserOperationReceipt: (parameters) => waitForUserOperationReceipt(client, parameters)
  };
}

// node_modules/viem/_esm/account-abstraction/clients/decorators/paymaster.js
function paymasterActions(client) {
  return {
    getPaymasterData: (parameters) => getPaymasterData(client, parameters),
    getPaymasterStubData: (parameters) => getPaymasterStubData(client, parameters)
  };
}

// node_modules/viem/_esm/account-abstraction/clients/createBundlerClient.js
function createBundlerClient(parameters) {
  const { client: client_, key = "bundler", name = "Bundler Client", paymaster, paymasterContext, transport: transport2, userOperation: userOperation6 } = parameters;
  const client = Object.assign(createClient({
    ...parameters,
    chain: parameters.chain ?? client_?.chain,
    key,
    name,
    transport: transport2,
    type: "bundlerClient"
  }), { client: client_, paymaster, paymasterContext, userOperation: userOperation6 });
  return client.extend(bundlerActions);
}
// node_modules/viem/_esm/account-abstraction/clients/createPaymasterClient.js
function createPaymasterClient(parameters) {
  const { key = "bundler", name = "Bundler Client", transport: transport2 } = parameters;
  const client = createClient({
    ...parameters,
    key,
    name,
    transport: transport2,
    type: "PaymasterClient"
  });
  return client.extend(paymasterActions);
}
// node_modules/viem/_esm/account-abstraction/constants/address.js
var entryPoint07Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
// node_modules/@biconomy/sdk/dist/_esm/constants/index.js
var ENTRY_POINT_ADDRESS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
var TEST_ADDRESS_K1_VALIDATOR_FACTORY_ADDRESS = "0xB19db8087aCc0Bcb8Fb559dDF2fD483978EA136F";
var TEST_ADDRESS_K1_VALIDATOR_ADDRESS = "0x5aec3f1c43B920a4dc21d500617fb37B8db1992C";
var MAINNET_ADDRESS_K1_VALIDATOR_FACTORY_ADDRESS = "0x00000bb19a3579F4D779215dEf97AFbd0e30DB55";
var MAINNET_ADDRESS_K1_VALIDATOR_ADDRESS = "0x00000004171351c442B202678c48D8AB5B321E8f";
var k1ValidatorFactoryAddress = isTesting ? TEST_ADDRESS_K1_VALIDATOR_FACTORY_ADDRESS : MAINNET_ADDRESS_K1_VALIDATOR_FACTORY_ADDRESS;
var k1ValidatorAddress = isTesting ? TEST_ADDRESS_K1_VALIDATOR_ADDRESS : MAINNET_ADDRESS_K1_VALIDATOR_ADDRESS;

// node_modules/@biconomy/sdk/dist/_esm/modules/utils/Helpers.js
function sanitizeSignature(signature3) {
  let signature_ = signature3;
  const potentiallyIncorrectV = Number.parseInt(signature_.slice(-2), 16);
  if (![27, 28].includes(potentiallyIncorrectV)) {
    const correctV = potentiallyIncorrectV + 27;
    signature_ = signature_.slice(0, -2) + correctV.toString(16);
  }
  if (signature3.slice(0, 2) !== "0x") {
    signature_ = `0x${signature_}`;
  }
  return signature_;
}

// node_modules/@biconomy/sdk/dist/_esm/modules/utils/toModule.js
function toModule(parameters) {
  const { account: account10, extend, initArgs = {}, deInitData = "0x", initData = "0x", moduleInitArgs = "0x", accountAddress = account10?.address ?? "0x", moduleInitData = {
    address: "0x",
    type: "validator"
  }, ...rest } = parameters;
  let data_ = parameters.data ?? {};
  const setData = (d) => {
    data_ = d;
  };
  const getData = () => data_;
  return {
    ...parameters,
    initData,
    moduleInitData,
    moduleInitArgs,
    deInitData,
    accountAddress,
    initArgs,
    setData,
    getData,
    module: parameters.address,
    type: "validator",
    getStubSignature: async () => {
      const dynamicPart = parameters.address.substring(2).padEnd(40, "0");
      return `0x0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000${dynamicPart}000000000000000000000000000000000000000000000000000000000000004181d4b4981670cb18f99f0b4a66446df1bf5b204d24cfcb659bf38ba27a4359b5711649ec2423c5e1247245eba2964679b6a1dbb85c992ae40b9b00c6935b02ff1b00000000000000000000000000000000000000000000000000000000000000`;
    },
    signUserOpHash: async (userOpHash) => await parameters.signer.signMessage({
      message: { raw: userOpHash }
    }),
    signMessage: async (message) => sanitizeSignature(await parameters.signer.signMessage({ message })),
    ...extend,
    ...rest
  };
}

// node_modules/@biconomy/sdk/dist/_esm/modules/k1Validator/toK1Validator.js
var getK1ModuleInitData = (_) => ({
  address: k1ValidatorAddress,
  type: "validator",
  initData: "0x"
});
var getK1InitData = ({ signerAddress }) => encodePacked(["address"], [signerAddress]);
var toK1Validator = (parameters) => {
  const { signer, initData: initData_, initArgs: initArgs_ = {
    signerAddress: signer.address
  }, moduleInitArgs: moduleInitArgs_, moduleInitData: moduleInitData_, deInitData = "0x", accountAddress, address: address12 = k1ValidatorAddress } = parameters;
  const initData = initData_ ?? getK1InitData(initArgs_);
  const moduleInitData = moduleInitData_ ?? getK1ModuleInitData(moduleInitArgs_);
  return toModule({
    signer,
    address: address12,
    accountAddress,
    initData,
    deInitData,
    moduleInitData,
    getStubSignature: async () => {
      const dynamicPart = address12.substring(2).padEnd(40, "0");
      return `0x0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000${dynamicPart}000000000000000000000000000000000000000000000000000000000000004181d4b4981670cb18f99f0b4a66446df1bf5b204d24cfcb659bf38ba27a4359b5711649ec2423c5e1247245eba2964679b6a1dbb85c992ae40b9b00c6935b02ff1b00000000000000000000000000000000000000000000000000000000000000`;
    },
    signUserOpHash: async (userOpHash) => {
      const signature3 = await signer.signMessage({
        message: { raw: userOpHash }
      });
      return signature3;
    },
    signMessage: async (message) => sanitizeSignature(await signer.signMessage({ message }))
  });
};

// node_modules/@biconomy/sdk/dist/_esm/account/toNexusAccount.js
var toNexusAccount = async (parameters) => {
  const { chain: chain5, transport: transport2, signer: _signer, index: index2 = 0n, module: module_, factoryAddress = k1ValidatorFactoryAddress, k1ValidatorAddress: k1ValidatorAddress2 = k1ValidatorAddress, key = "nexus account", name = "Nexus Account" } = parameters;
  const signer = await toSigner({ signer: _signer });
  const walletClient = createWalletClient({
    account: signer,
    chain: chain5,
    transport: transport2,
    key,
    name
  }).extend(publicActions);
  const publicClient = createPublicClient({
    chain: chain5,
    transport: transport2
  });
  const signerAddress = walletClient.account.address;
  const entryPointContract = getContract({
    address: ENTRY_POINT_ADDRESS,
    abi: EntrypointAbi,
    client: {
      public: publicClient,
      wallet: walletClient
    }
  });
  const factoryData = encodeFunctionData({
    abi: K1ValidatorFactoryAbi,
    functionName: "createAccount",
    args: [signerAddress, index2, [], 0]
  });
  let _accountAddress = parameters.accountAddress;
  const getAddress8 = async () => {
    if (!isNullOrUndefined(_accountAddress))
      return _accountAddress;
    try {
      _accountAddress = await publicClient.readContract({
        address: factoryAddress,
        abi: K1ValidatorFactoryAbi,
        functionName: "computeAccountAddress",
        args: [signerAddress, index2, [], 0]
      });
    } catch (e) {
      if (e.shortMessage?.includes(ERROR_MESSAGES.MISSING_ACCOUNT_CONTRACT)) {
        throw new Error(ERROR_MESSAGES.FAILED_COMPUTE_ACCOUNT_ADDRESS);
      }
      throw e;
    }
    return _accountAddress;
  };
  const getInitCode = () => concatHex([factoryAddress, factoryData]);
  const getCounterFactualAddress = async () => {
    if (_accountAddress)
      return _accountAddress;
    try {
      await entryPointContract.simulate.getSenderAddress([getInitCode()]);
    } catch (e) {
      if (e?.cause?.data?.errorName === "SenderAddressResult") {
        _accountAddress = e?.cause.data.args[0];
        if (!addressEquals(_accountAddress, zeroAddress)) {
          return _accountAddress;
        }
      }
    }
    throw new Error("Failed to get counterfactual account address");
  };
  let module = module_ ?? toK1Validator({
    address: k1ValidatorAddress2,
    accountAddress: await getCounterFactualAddress(),
    initData: signerAddress,
    deInitData: "0x",
    signer
  });
  const isDeployed = async () => {
    const address12 = await getCounterFactualAddress();
    const contractCode = await publicClient.getCode({ address: address12 });
    return (contractCode?.length ?? 0) > 2;
  };
  const getUserOpHash = async (userOp) => {
    const packedUserOp = packUserOp(userOp);
    const userOpHash = keccak256(packedUserOp);
    const enc = encodeAbiParameters(parseAbiParameters("bytes32, address, uint256"), [userOpHash, ENTRY_POINT_ADDRESS, BigInt(chain5.id)]);
    return keccak256(enc);
  };
  const encodeExecuteBatch = async (calls, mode = EXECUTE_BATCH) => {
    const executionAbiParams = {
      type: "tuple[]",
      components: [
        { name: "target", type: "address" },
        { name: "value", type: "uint256" },
        { name: "callData", type: "bytes" }
      ]
    };
    const executions = calls.map((tx) => ({
      target: tx.to,
      callData: tx.data ?? "0x",
      value: BigInt(tx.value ?? 0n)
    }));
    const executionCalldataPrep = encodeAbiParameters([executionAbiParams], [executions]);
    return encodeFunctionData({
      abi: parseAbi([
        "function execute(bytes32 mode, bytes calldata executionCalldata) external"
      ]),
      functionName: "execute",
      args: [mode, executionCalldataPrep]
    });
  };
  const encodeExecute = async (call7, mode = EXECUTE_SINGLE) => {
    const executionCalldata = encodePacked(["address", "uint256", "bytes"], [call7.to, BigInt(call7.value ?? 0n), call7.data ?? "0x"]);
    return encodeFunctionData({
      abi: parseAbi([
        "function execute(bytes32 mode, bytes calldata executionCalldata) external"
      ]),
      functionName: "execute",
      args: [mode, executionCalldata]
    });
  };
  const getNonce = async (parameters2) => {
    try {
      const TIMESTAMP_ADJUSTMENT = 16777215n;
      const defaultedKey = BigInt(parameters2?.key ?? 0n) % TIMESTAMP_ADJUSTMENT;
      const defaultedValidationMode = parameters2?.validationMode ?? "0x00";
      const key2 = concat([
        toHex2(defaultedKey, { size: 3 }),
        defaultedValidationMode,
        module.address
      ]);
      const accountAddress = await getAddress8();
      return await entryPointContract.read.getNonce([
        accountAddress,
        BigInt(key2)
      ]);
    } catch (e) {
      return 0n;
    }
  };
  const setModule = (validationModule) => {
    module = validationModule;
  };
  const signMessage5 = async ({ message }) => {
    const tempSignature = await module.signMessage(message);
    const signature3 = encodePacked(["address", "bytes"], [module.address, tempSignature]);
    const erc6492Signature = concat([
      encodeAbiParameters([
        {
          type: "address",
          name: "create2Factory"
        },
        {
          type: "bytes",
          name: "factoryCalldata"
        },
        {
          type: "bytes",
          name: "originalERC1271Signature"
        }
      ], [factoryAddress, factoryData, signature3]),
      MAGIC_BYTES
    ]);
    const accountIsDeployed = await isDeployed();
    return accountIsDeployed ? signature3 : erc6492Signature;
  };
  async function signTypedData5(parameters2) {
    const { message, primaryType, types: _types, domain } = parameters2;
    if (!domain)
      throw new Error("Missing domain");
    if (!message)
      throw new Error("Missing message");
    const types = {
      EIP712Domain: getTypesForEIP712Domain2({ domain }),
      ..._types
    };
    const messageStuff = message.stuff;
    validateTypedData({
      domain,
      message,
      primaryType,
      types
    });
    const appDomainSeparator = domainSeparator({ domain });
    const accountDomainStructFields = await getAccountDomainStructFields(publicClient, await getAddress8());
    const parentStructHash = keccak256(encodePacked(["bytes", "bytes"], [
      encodeAbiParameters(parseAbiParameters(["bytes32, bytes32"]), [
        keccak256(toBytes2(PARENT_TYPEHASH)),
        messageStuff
      ]),
      accountDomainStructFields
    ]));
    const wrappedTypedHash = eip712WrapHash(parentStructHash, appDomainSeparator);
    let signature3 = await module.signMessage({ raw: toBytes2(wrappedTypedHash) });
    const contentsType = toBytes2(typeToString(types)[1]);
    const signatureData = concatHex([
      signature3,
      appDomainSeparator,
      messageStuff,
      toHex2(contentsType),
      toHex2(contentsType.length, { size: 2 })
    ]);
    signature3 = encodePacked(["address", "bytes"], [module.address, signatureData]);
    return signature3;
  }
  return toSmartAccount({
    client: walletClient,
    entryPoint: {
      abi: EntrypointAbi,
      address: ENTRY_POINT_ADDRESS,
      version: "0.7"
    },
    getAddress: getAddress8,
    encodeCalls: (calls) => {
      return calls.length === 1 ? encodeExecute(calls[0]) : encodeExecuteBatch(calls);
    },
    getFactoryArgs: async () => ({ factory: factoryAddress, factoryData }),
    getStubSignature: async () => module.getStubSignature(),
    signMessage: signMessage5,
    signTypedData: signTypedData5,
    signUserOperation: async (parameters2) => {
      const { chainId = publicClient.chain.id, ...userOpWithoutSender } = parameters2;
      const address12 = await getCounterFactualAddress();
      const userOperation6 = {
        ...userOpWithoutSender,
        sender: address12
      };
      const hash3 = getUserOperationHash({
        chainId,
        entryPointAddress: entryPoint07Address,
        entryPointVersion: "0.7",
        userOperation: userOperation6
      });
      return await module.signUserOpHash(hash3);
    },
    getNonce,
    extend: {
      entryPointAddress: entryPoint07Address,
      getCounterFactualAddress,
      isDeployed,
      getInitCode,
      encodeExecute,
      encodeExecuteBatch,
      getUserOpHash,
      setModule,
      getModule: () => module,
      factoryData,
      factoryAddress,
      signer,
      walletClient,
      publicClient
    }
  });
};

// node_modules/@biconomy/sdk/dist/_esm/account/utils/AccountNotFound.js
class AccountNotFoundError2 extends BaseError {
  constructor({ docsPath: docsPath6 } = {}) {
    super([
      "Could not find an Account to execute with this Action.",
      "Please provide an Account with the `account` argument on the Action, or by supplying an `account` to the Client."
    ].join("\n"), {
      docsPath: docsPath6,
      docsSlug: "account",
      name: "AccountNotFoundError"
    });
  }
}

// node_modules/@biconomy/sdk/dist/_esm/clients/createBicoPaymasterClient.js
var biconomyPaymasterContext = {
  mode: "SPONSORED",
  expiryDuration: 300,
  calculateGasLimits: true,
  sponsorshipInfo: {
    smartAccountInfo: {
      name: "BICONOMY",
      version: "1.0.0"
    }
  }
};
var createBicoPaymasterClient = (parameters) => {
  const defaultedTransport = parameters.transport ? parameters.transport : parameters.paymasterUrl ? http2(parameters.paymasterUrl) : http2(`https://paymaster.biconomy.io/api/v2/${parameters.chainId}/${parameters.apiKey}`);
  const { getPaymasterStubData: getPaymasterStubData4, ...paymasterClient } = createPaymasterClient({
    ...parameters,
    transport: defaultedTransport
  });
  return paymasterClient;
};

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/bundler/getGasFeeValues.js
var getGasFeeValues = async (client) => {
  const gasPrice = await client.request({
    method: isTesting ? "pimlico_getUserOperationGasPrice" : "biconomy_getGasFeeValues",
    params: []
  });
  return {
    slow: {
      maxFeePerGas: BigInt(gasPrice.slow.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(gasPrice.slow.maxPriorityFeePerGas)
    },
    standard: {
      maxFeePerGas: BigInt(gasPrice.standard.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(gasPrice.standard.maxPriorityFeePerGas)
    },
    fast: {
      maxFeePerGas: BigInt(gasPrice.fast.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(gasPrice.fast.maxPriorityFeePerGas)
    }
  };
};

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/bundler/index.js
var bicoBundlerActions = () => (client) => ({
  getGasFeeValues: async () => getGasFeeValues(client)
});

// node_modules/@biconomy/sdk/dist/_esm/clients/createBicoBundlerClient.js
var createBicoBundlerClient = (parameters) => {
  if (!parameters.apiKey && !parameters.bundlerUrl && !parameters.transport && !parameters?.chain) {
    throw new Error("Cannot set determine a bundler url, please provide a chain.");
  }
  const defaultedTransport = parameters.transport ? parameters.transport : parameters.bundlerUrl ? http2(parameters.bundlerUrl) : http2(`https://bundler.biconomy.io/api/v3/${parameters.chain.id}/${parameters.apiKey ?? "nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f14"}`);
  const defaultedUserOperation = parameters.userOperation ?? {
    estimateFeesPerGas: async (_) => {
      const gasFees = await bundler_.getGasFeeValues();
      return gasFees.fast;
    }
  };
  const defaultedPaymasterContext = parameters.paymaster ? parameters.paymasterContext ?? biconomyPaymasterContext : undefined;
  const bundler_ = createBundlerClient({
    ...parameters,
    transport: defaultedTransport,
    paymasterContext: defaultedPaymasterContext,
    userOperation: defaultedUserOperation
  }).extend(bicoBundlerActions());
  return bundler_;
};

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/accountId.js
async function accountId(client, args) {
  let account_ = client.account;
  if (args) {
    account_ = args.account;
  }
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = account_;
  const publicClient = account10.client;
  const abi22 = [
    {
      name: "accountId",
      type: "function",
      stateMutability: "view",
      inputs: [],
      outputs: [
        {
          type: "string",
          name: "accountImplementationId"
        }
      ]
    }
  ];
  try {
    return await getAction(publicClient, readContract, "readContract")({
      abi: abi22,
      functionName: "accountId",
      address: await account10.getAddress()
    });
  } catch (error) {
    if (error instanceof ContractFunctionExecutionError) {
      const { factory, factoryData } = await account10.getFactoryArgs();
      const result = await getAction(publicClient, call2, "call")({
        factory,
        factoryData,
        to: account10.address,
        data: encodeFunctionData({
          abi: abi22,
          functionName: "accountId"
        })
      });
      if (!result || !result.data) {
        throw new Error("accountId result is empty");
      }
      return decodeFunctionResult({
        abi: abi22,
        functionName: "accountId",
        data: result.data
      });
    }
    throw error;
  }
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/getActiveHook.js
async function getActiveHook(client, parameters) {
  const account_ = parameters?.account ?? client.account;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  return getAction(publicClient, readContract, "readContract")({
    address: account10.address,
    abi: [
      {
        inputs: [],
        name: "getActiveHook",
        outputs: [
          {
            internalType: "address",
            name: "hook",
            type: "address"
          }
        ],
        stateMutability: "view",
        type: "function"
      }
    ],
    functionName: "getActiveHook"
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/getFallbackBySelector.js
async function getFallbackBySelector(client, parameters) {
  const { account: account_ = client.account, selector = GENERIC_FALLBACK_SELECTOR } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  return getAction(publicClient, readContract, "readContract")({
    address: account10.address,
    abi: [
      {
        inputs: [
          {
            internalType: "bytes4",
            name: "selector",
            type: "bytes4"
          }
        ],
        name: "getFallbackHandlerBySelector",
        outputs: [
          {
            internalType: "CallType",
            name: "",
            type: "bytes1"
          },
          {
            internalType: "address",
            name: "",
            type: "address"
          }
        ],
        stateMutability: "view",
        type: "function"
      }
    ],
    functionName: "getFallbackHandlerBySelector",
    args: [selector]
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/getInstalledExecutors.js
async function getInstalledExecutors(client, parameters) {
  const account_ = parameters?.account ?? client.account;
  const pageSize = parameters?.pageSize ?? 100n;
  const cursor6 = parameters?.cursor ?? SENTINEL_ADDRESS;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  return getAction(publicClient, readContract, "readContract")({
    address: account10.address,
    abi: [
      {
        inputs: [
          {
            internalType: "address",
            name: "cursor",
            type: "address"
          },
          {
            internalType: "uint256",
            name: "size",
            type: "uint256"
          }
        ],
        name: "getExecutorsPaginated",
        outputs: [
          {
            internalType: "address[]",
            name: "array",
            type: "address[]"
          },
          {
            internalType: "address",
            name: "next",
            type: "address"
          }
        ],
        stateMutability: "view",
        type: "function"
      }
    ],
    functionName: "getExecutorsPaginated",
    args: [cursor6, pageSize]
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/getInstalledValidators.js
async function getInstalledValidators(client, parameters) {
  const account_ = parameters?.account ?? client.account;
  const pageSize = parameters?.pageSize ?? 100n;
  const cursor6 = parameters?.cursor ?? SENTINEL_ADDRESS;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  return getAction(publicClient, readContract, "readContract")({
    address: account10.address,
    abi: [
      {
        inputs: [
          {
            internalType: "address",
            name: "cursor",
            type: "address"
          },
          {
            internalType: "uint256",
            name: "size",
            type: "uint256"
          }
        ],
        name: "getValidatorsPaginated",
        outputs: [
          {
            internalType: "address[]",
            name: "array",
            type: "address[]"
          },
          {
            internalType: "address",
            name: "next",
            type: "address"
          }
        ],
        stateMutability: "view",
        type: "function"
      }
    ],
    functionName: "getValidatorsPaginated",
    args: [cursor6, pageSize]
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/getPreviousModule.js
async function getPreviousModule(client, parameters) {
  const { account: account_ = client.account, module } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  let installedModules;
  if (module.type === "validator") {
    if (!parameters.installedValidators)
      throw Error("installedValidators parameter is missing");
    installedModules = [...parameters.installedValidators];
  } else if (module.type === "executor") {
    if (!parameters.installedExecutors)
      throw Error("installedExecutors parameter is missing");
    installedModules = [...parameters.installedExecutors];
  } else {
    throw new Error(`Unknown module type ${module.type}`);
  }
  const index2 = installedModules.indexOf(getAddress(module.address));
  if (index2 === 0) {
    return SENTINEL_ADDRESS2;
  }
  if (index2 > 0) {
    return installedModules[index2 - 1];
  }
  throw new Error(`Module ${module.address} not found in installed modules`);
}
var SENTINEL_ADDRESS2 = "0x0000000000000000000000000000000000000001";

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/supportsModule.js
function parseModuleTypeId(type) {
  switch (type) {
    case "validator":
      return BigInt(1);
    case "executor":
      return BigInt(2);
    case "fallback":
      return BigInt(3);
    case "hook":
      return BigInt(4);
    default:
      throw new Error("Invalid module type");
  }
}
async function supportsModule(client, args) {
  const { account: account_ = client.account } = args;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  const abi22 = [
    {
      name: "supportsModule",
      type: "function",
      stateMutability: "view",
      inputs: [
        {
          type: "uint256",
          name: "moduleTypeId"
        }
      ],
      outputs: [
        {
          type: "bool"
        }
      ]
    }
  ];
  try {
    return await getAction(publicClient, readContract, "readContract")({
      abi: abi22,
      functionName: "supportsModule",
      args: [parseModuleTypeId(args.type)],
      address: account10.address
    });
  } catch (error) {
    if (error instanceof ContractFunctionExecutionError) {
      const { factory, factoryData } = await account10.getFactoryArgs();
      const result = await getAction(publicClient, call2, "call")({
        factory,
        factoryData,
        to: account10.address,
        data: encodeFunctionData({
          abi: abi22,
          functionName: "supportsModule",
          args: [parseModuleTypeId(args.type)]
        })
      });
      if (!result || !result.data) {
        throw new Error("accountId result is empty");
      }
      return decodeFunctionResult({
        abi: abi22,
        functionName: "supportsModule",
        data: result.data
      });
    }
    throw error;
  }
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/installModule.js
async function installModule(client, parameters) {
  const { account: account_ = client.account, maxFeePerGas, maxPriorityFeePerGas, nonce, module: { address: address12, initData, type } } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  return getAction(client, sendUserOperation, "sendUserOperation")({
    calls: [
      {
        to: account10.address,
        value: BigInt(0),
        data: encodeFunctionData({
          abi: [
            {
              name: "installModule",
              type: "function",
              stateMutability: "nonpayable",
              inputs: [
                {
                  type: "uint256",
                  name: "moduleTypeId"
                },
                {
                  type: "address",
                  name: "module"
                },
                {
                  type: "bytes",
                  name: "initData"
                }
              ],
              outputs: []
            }
          ],
          functionName: "installModule",
          args: [parseModuleTypeId(type), getAddress(address12), initData ?? "0x"]
        })
      }
    ],
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce,
    account: account10
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/installModules.js
async function installModules(client, parameters) {
  const { account: account_ = client.account, maxFeePerGas, maxPriorityFeePerGas, nonce, modules } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  return getAction(client, sendUserOperation, "sendUserOperation")({
    calls: modules.map(({ type, address: address12, data: data4 }) => ({
      to: account10.address,
      value: BigInt(0),
      data: encodeFunctionData({
        abi: [
          {
            name: "installModule",
            type: "function",
            stateMutability: "nonpayable",
            inputs: [
              {
                type: "uint256",
                name: "moduleTypeId"
              },
              {
                type: "address",
                name: "module"
              },
              {
                type: "bytes",
                name: "initData"
              }
            ],
            outputs: []
          }
        ],
        functionName: "installModule",
        args: [parseModuleTypeId(type), getAddress(address12), data4]
      })
    })),
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce,
    account: account10
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/isModuleInstalled.js
async function isModuleInstalled(client, parameters) {
  const { account: account_ = client.account, module: { address: address12, initData, type } } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  const abi22 = [
    {
      name: "isModuleInstalled",
      type: "function",
      stateMutability: "view",
      inputs: [
        {
          type: "uint256",
          name: "moduleTypeId"
        },
        {
          type: "address",
          name: "module"
        },
        {
          type: "bytes",
          name: "additionalContext"
        }
      ],
      outputs: [
        {
          type: "bool"
        }
      ]
    }
  ];
  try {
    return await getAction(publicClient, readContract, "readContract")({
      abi: abi22,
      functionName: "isModuleInstalled",
      args: [parseModuleTypeId(type), getAddress(address12), initData ?? "0x"],
      address: account10.address
    });
  } catch (error) {
    if (error instanceof ContractFunctionExecutionError) {
      const { factory, factoryData } = await account10.getFactoryArgs();
      const result = await getAction(publicClient, call2, "call")({
        factory,
        factoryData,
        to: account10.address,
        data: encodeFunctionData({
          abi: abi22,
          functionName: "isModuleInstalled",
          args: [parseModuleTypeId(type), getAddress(address12), initData ?? "0x"]
        })
      });
      if (!result || !result.data) {
        throw new Error("accountId result is empty");
      }
      return decodeFunctionResult({
        abi: abi22,
        functionName: "isModuleInstalled",
        data: result.data
      });
    }
    throw error;
  }
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/supportsExecutionMode.js
var parseCallType = function(callType) {
  switch (callType) {
    case "call":
      return "0x00";
    case "batchcall":
      return "0x01";
    case "delegatecall":
      return "0xff";
  }
};
function encodeExecutionMode({ type, revertOnError, selector, data: data4 }) {
  return encodePacked(["bytes1", "bytes1", "bytes4", "bytes4", "bytes22"], [
    toHex2(toBytes2(parseCallType(type), { size: 1 })),
    toHex2(toBytes2(revertOnError ? "0x01" : "0x00", { size: 1 })),
    toHex2(toBytes2("0x0", { size: 4 })),
    toHex2(toBytes2(selector ?? "0x", { size: 4 })),
    toHex2(toBytes2(data4 ?? "0x", { size: 22 }))
  ]);
}
async function supportsExecutionMode(client, args) {
  const { account: account_ = client.account, type, revertOnError, selector, data: data4 } = args;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const publicClient = account10.client;
  const encodedMode = encodeExecutionMode({
    type,
    revertOnError,
    selector,
    data: data4
  });
  const abi22 = [
    {
      name: "supportsExecutionMode",
      type: "function",
      stateMutability: "view",
      inputs: [
        {
          type: "bytes32",
          name: "encodedMode"
        }
      ],
      outputs: [
        {
          type: "bool"
        }
      ]
    }
  ];
  try {
    return await getAction(publicClient, readContract, "readContract")({
      abi: abi22,
      functionName: "supportsExecutionMode",
      args: [encodedMode],
      address: account10.address
    });
  } catch (error) {
    if (error instanceof ContractFunctionExecutionError) {
      const { factory, factoryData } = await account10.getFactoryArgs();
      const result = await getAction(publicClient, call2, "call")({
        factory,
        factoryData,
        to: account10.address,
        data: encodeFunctionData({
          abi: abi22,
          functionName: "supportsExecutionMode",
          args: [encodedMode]
        })
      });
      if (!result || !result.data) {
        throw new Error("accountId result is empty");
      }
      return decodeFunctionResult({
        abi: abi22,
        functionName: "supportsExecutionMode",
        data: result.data
      });
    }
    throw error;
  }
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/uninstallModule.js
async function uninstallModule(client, parameters) {
  const { account: account_ = client.account, maxFeePerGas, maxPriorityFeePerGas, nonce, module: { address: address12, initData, type } } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  const [installedValidators] = await getInstalledValidators(client);
  const prevModule = await getPreviousModule(client, {
    module: {
      address: address12,
      type
    },
    installedValidators,
    account: account10
  });
  const deInitData = encodeAbiParameters([
    { name: "prev", type: "address" },
    { name: "disableModuleData", type: "bytes" }
  ], [prevModule, initData ?? "0x"]);
  return getAction(client, sendUserOperation, "sendUserOperation")({
    calls: [
      {
        to: account10.address,
        value: BigInt(0),
        data: encodeFunctionData({
          abi: [
            {
              name: "uninstallModule",
              type: "function",
              stateMutability: "nonpayable",
              inputs: [
                {
                  type: "uint256",
                  name: "moduleTypeId"
                },
                {
                  type: "address",
                  name: "module"
                },
                {
                  type: "bytes",
                  name: "deInitData"
                }
              ],
              outputs: []
            }
          ],
          functionName: "uninstallModule",
          args: [parseModuleTypeId(type), getAddress(address12), deInitData]
        })
      }
    ],
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce,
    account: account10
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/uninstallModules.js
async function uninstallModules(client, parameters) {
  const { account: account_ = client.account, maxFeePerGas, maxPriorityFeePerGas, nonce, modules } = parameters;
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/nexus-client/methods#sendtransaction"
    });
  }
  const account10 = parseAccount(account_);
  return getAction(client, sendUserOperation, "sendUserOperation")({
    calls: modules.map(({ type, address: address12, initData }) => ({
      to: account10.address,
      value: BigInt(0),
      data: encodeFunctionData({
        abi: [
          {
            name: "uninstallModule",
            type: "function",
            stateMutability: "nonpayable",
            inputs: [
              {
                type: "uint256",
                name: "moduleTypeId"
              },
              {
                type: "address",
                name: "module"
              },
              {
                type: "bytes",
                name: "deInitData"
              }
            ],
            outputs: []
          }
        ],
        functionName: "uninstallModule",
        args: [parseModuleTypeId(type), getAddress(address12), initData ?? "0x"]
      })
    })),
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce,
    account: account10
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/erc7579/index.js
function erc7579Actions() {
  return (client) => ({
    accountId: (args) => accountId(client, args),
    installModule: (args) => installModule(client, args),
    installModules: (args) => installModules(client, args),
    isModuleInstalled: (args) => isModuleInstalled(client, args),
    supportsExecutionMode: (args) => supportsExecutionMode(client, args),
    supportsModule: (args) => supportsModule(client, args),
    uninstallModule: (args) => uninstallModule(client, args),
    uninstallModules: (args) => uninstallModules(client, args),
    getInstalledValidators: (args) => getInstalledValidators(client, args),
    getInstalledExecutors: (args) => getInstalledExecutors(client, args),
    getActiveHook: (args) => getActiveHook(client, args),
    getFallbackBySelector: (args) => getFallbackBySelector(client, args),
    getPreviousModule: (args) => getPreviousModule(client, args)
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/smartAccount/sendTransaction.js
async function sendTransaction5(client, args) {
  let userOpHash;
  if ("to" in args) {
    const { account: account_ = client.account, data: data4, maxFeePerGas, maxPriorityFeePerGas, to, value, nonce } = args;
    if (!account_) {
      throw new AccountNotFoundError2({
        docsPath: "/nexus-client/methods#sendtransaction"
      });
    }
    const account10 = parseAccount(account_);
    if (!to)
      throw new Error("Missing to address");
    userOpHash = await getAction(client, sendUserOperation, "sendUserOperation")({
      calls: [
        {
          to,
          value: value || BigInt(0),
          data: data4 || "0x"
        }
      ],
      account: account10,
      maxFeePerGas,
      maxPriorityFeePerGas,
      nonce: nonce ? BigInt(nonce) : undefined
    });
  } else {
    userOpHash = await getAction(client, sendUserOperation, "sendUserOperation")({ ...args });
  }
  const userOperationReceipt2 = await getAction(client, waitForUserOperationReceipt, "waitForUserOperationReceipt")({
    hash: userOpHash
  });
  return userOperationReceipt2?.receipt.transactionHash;
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/smartAccount/signMessage.js
async function signMessage5(client, { account: account_ = client.account, message }) {
  if (!account_)
    throw new AccountNotFoundError2({
      docsPath: "/docs/actions/wallet/signMessage"
    });
  const account10 = parseAccount(account_);
  return account10.signMessage({ message });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/smartAccount/signTypedData.js
async function signTypedData5(client, { account: account_ = client.account, domain, message, primaryType, types: types_ }) {
  if (!account_) {
    throw new AccountNotFoundError2({
      docsPath: "/docs/actions/wallet/signMessage"
    });
  }
  const account10 = parseAccount(account_);
  const types = {
    EIP712Domain: getTypesForEIP712Domain({ domain }),
    ...types_
  };
  validateTypedData({
    domain,
    message,
    primaryType,
    types
  });
  return account10.signTypedData({
    domain,
    primaryType,
    types,
    message
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/smartAccount/waitForTransactionReceipt.js
async function waitForTransactionReceipt3(client, { account: account_ = client.account, hash: hash3 }) {
  if (!account_)
    throw new AccountNotFoundError2({
      docsPath: "/docs/actions/wallet/waitForTransactionReceipt"
    });
  const account10 = parseAccount(account_);
  const accountClient = account10?.client;
  if (!accountClient)
    throw new Error("Requires a Public Client");
  return accountClient.waitForTransactionReceipt({ hash: hash3 });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/smartAccount/writeContract.js
async function writeContract4(client, { abi: abi22, address: address12, args, dataSuffix, functionName, ...request8 }) {
  const data4 = encodeFunctionData({
    abi: abi22,
    args,
    functionName
  });
  const hash3 = await getAction(client, sendTransaction5, "sendTransaction")({
    data: `${data4}${dataSuffix ? dataSuffix.replace("0x", "") : ""}`,
    to: address12,
    ...request8
  });
  return hash3;
}

// node_modules/@biconomy/sdk/dist/_esm/clients/decorators/smartAccount/index.js
function smartAccountActions() {
  return (client) => ({
    sendTransaction: (args) => sendTransaction5(client, args),
    signMessage: (args) => signMessage5(client, args),
    signTypedData: (args) => signTypedData5(client, args),
    writeContract: (args) => writeContract4(client, args),
    waitForTransactionReceipt: (args) => waitForTransactionReceipt3(client, args)
  });
}

// node_modules/@biconomy/sdk/dist/_esm/clients/createNexusClient.js
async function createNexusClient(parameters) {
  const { client: client_, chain: chain5 = parameters.chain ?? client_?.chain, signer, index: index2 = 0n, key = "nexus client", name = "Nexus Client", module, factoryAddress = k1ValidatorFactoryAddress, k1ValidatorAddress: k1ValidatorAddress2 = k1ValidatorAddress, bundlerTransport, transport: transport2, accountAddress, ...bundlerConfig } = parameters;
  if (!chain5)
    throw new Error("Missing chain");
  const nexusAccount = await toNexusAccount({
    accountAddress,
    transport: transport2,
    chain: chain5,
    signer,
    index: index2,
    module,
    factoryAddress,
    k1ValidatorAddress: k1ValidatorAddress2
  });
  const bundler_ = createBicoBundlerClient({
    ...bundlerConfig,
    chain: chain5,
    key,
    name,
    account: nexusAccount,
    transport: bundlerTransport
  }).extend(erc7579Actions()).extend(smartAccountActions());
  return bundler_;
}

// src/index.ts
async function getNexusClient(handle) {
  let index2 = ConvertToBn(handle);
  return await createNexusClient({
    signer: account10,
    chain: baseSepolia,
    transport: http2(),
    index: index2,
    bundlerTransport: http2(bundlerUrl),
    paymaster: createBicoPaymasterClient({ paymasterUrl })
  });
}
var ConvertToBn = function(handle) {
  return BigInt(`0x${Buffer.from(handle).toString("hex")}`);
};
var app = new Hono2;
app.get("/", (c) => {
  return c.text("Hello Hono!");
});
var privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
var account10 = privateKeyToAccount(`${privateKey}`);
var bundlerUrl = "https://bundler.biconomy.io/api/v3/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44";
var paymasterUrl = "https://paymaster.biconomy.io/api/v2/84532/F7wyL1clz.75a64804-3e97-41fa-ba1e-33e98c2cc703";
var TRANSFER_OWNERSHIP_ABI = parseAbi([
  "function transferOwnership(address newOwner) external"
]);
var SMART_ACCOUNT_OWNER_ABI = parseAbi([
  "function smartAccountOwners(address account) view returns (address)"
]);
var K1_VALIDATOR_ADDRESS = "0x00000004171351c442B202678c48D8AB5B321E8f";
app.get("/address/:handle", async (c) => {
  const handle = c.req.param("handle");
  const nexusClient = await getNexusClient(handle);
  return c.json({ address: await nexusClient.account.address });
});
app.post("/deploy", async (c) => {
  const { handle, newOwner } = await c.req.json();
  console.log("handle: ", handle, "newOwner: ", newOwner);
  const nexusClient = await getNexusClient(handle);
  const hash0 = await nexusClient.sendTransaction({ calls: [{ to: "0xf5715961C550FC497832063a98eA34673ad7C816", value: parseEther("0") }] });
  console.log("Transaction hash0: ", hash0);
  await nexusClient.waitForTransactionReceipt({ hash: hash0 });
  const callData = encodeFunctionData({
    abi: TRANSFER_OWNERSHIP_ABI,
    functionName: "transferOwnership",
    args: [newOwner]
  });
  console.log(K1_VALIDATOR_ADDRESS);
  const hash3 = await nexusClient.sendTransaction({
    calls: [{
      to: K1_VALIDATOR_ADDRESS,
      data: callData,
      value: parseEther("0")
    }]
  });
  console.log("Ownership transfer transaction hash:", hash3);
  const receipt = await nexusClient.waitForTransactionReceipt({ hash: hash3 });
  return c.json({ address: await nexusClient.account.address, hash: hash3 });
});
app.get("/owners/:account", async (c) => {
  const account11 = c.req.param("account");
  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http2()
  });
  const owners = await publicClient.call({
    to: K1_VALIDATOR_ADDRESS,
    data: encodeFunctionData({
      abi: SMART_ACCOUNT_OWNER_ABI,
      functionName: "smartAccountOwners",
      args: [account11]
    })
  });
  return c.json({ owners });
});
var src_default = app;
export {
  src_default as default
};
