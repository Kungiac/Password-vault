const PBKDF2_ITERATIONS = 310_000;

/** Normalize typed arrays for DOM `SubtleCrypto` typings (ArrayBuffer vs SharedArrayBuffer). */
function asBufferSource(buf: Uint8Array): BufferSource {
  return buf as BufferSource;
}

function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuffer(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, "").trim();
  if (clean.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

export async function deriveKey(
  masterPassword: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: asBufferSource(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptPassword(
  plainText: string,
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(iv) },
    key,
    enc.encode(plainText)
  );
  return {
    ciphertext: bufferToHex(new Uint8Array(cipherBuf)),
    iv: bufferToHex(iv),
  };
}

export async function decryptPassword(
  ciphertext: string,
  iv: string,
  key: CryptoKey
): Promise<string> {
  const ivBytes = hexToBuffer(iv);
  const ctBytes = hexToBuffer(ciphertext);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBufferSource(ivBytes) },
    key,
    asBufferSource(ctBytes)
  );
  return new TextDecoder().decode(plainBuf);
}

export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

export function saltToHex(salt: Uint8Array): string {
  return bufferToHex(salt);
}

export function saltFromHex(hex: string): Uint8Array {
  return hexToBuffer(hex);
}
