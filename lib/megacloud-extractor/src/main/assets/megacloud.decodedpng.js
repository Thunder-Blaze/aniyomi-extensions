"use strict"

// megacloud.decodedpng.js

function hexToBytes(hex) {
    const arr = [];
    for (let i = 0; i < hex.length; i += 2)
        arr.push(parseInt(hex.substr(i, 2), 16));
    return new Uint8Array(arr);
}

function deriveKeyAndIv(password) {
    const md5 = CryptoJS.MD5;
    let digest = password;
    const hashes = [];

    for (let i = 0; i < 3; i++) {
        const hash = md5(CryptoJS.lib.WordArray.create(digest));
        const hashBytes = hexToBytes(hash.toString());
        hashes.push(hashBytes);
        const newDigest = new Uint8Array(hashBytes.length + password.length);
        newDigest.set(hashBytes);
        newDigest.set(password, hashBytes.length);
        digest = newDigest;
    }

    const key = new Uint8Array([...hashes[0], ...hashes[1]]);
    const iv = hashes[2];
    return { key, iv };
}

function decryptSources(key, value) {
    const encrypted = base64ToBytes(value);
    const salt = encrypted.slice(8, 16);
    const data = encrypted.slice(16);
    const derived = deriveKeyAndIv(concatBytes(key, salt));

    const keyWA = CryptoJS.lib.WordArray.create(derived.key);
    const ivWA = CryptoJS.lib.WordArray.create(derived.iv);
    const encWA = CryptoJS.lib.WordArray.create(data);

    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: encWA },
        keyWA,
        { iv: ivWA, padding: CryptoJS.pad.Pkcs7, mode: CryptoJS.mode.CBC }
    );

    const decryptedStr = CryptoJS.enc.Utf8.stringify(decrypted);
    return decryptedStr;
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function concatBytes(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
}
