"use strict"
const baseUrl = 'https://megacloud.tv';
const userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

async function getMegaCloudKey() {
    try {
        const resp = await fetch('https://raw.githubusercontent.com/yogesh-hacker/MegacloudKeys/refs/heads/main/keys.json');
        const data = await resp.json();
        return data?.mega; // This is a hex string
    } catch (err) {
        console.error("Error fetching MegaCloud key:", err);
        return null;
    }
}

/**
 * Custom key derivation function mimicking Node.js crypto's EVP_BytesToKey behavior.
 * The 'password' (initialPasswordWordArray) is the byte representation of the concatenated key and salt.
 *
 * @param {CryptoJS.lib.WordArray} initialPasswordWordArray - The combined bytes of the key and salt as a WordArray.
 * @returns {{key: CryptoJS.lib.WordArray, iv: CryptoJS.lib.WordArray}} Derived key and IV
 */
function deriveKeyAndIv(initialPasswordWordArray) {
    let digest = initialPasswordWordArray.clone(); // Start with a clone of the initial input for the first hash
    const hashes = [];

    for (let i = 0; i < 3; i++) {
        const hash = CryptoJS.MD5(digest); // MD5 hash of the current digest WordArray
        hashes.push(hash);

        if (i < 2) { // For the first two iterations, prepare the digest for the next hash
            const newWords = hash.words.concat(initialPasswordWordArray.words);
            const newSigBytes = hash.sigBytes + initialPasswordWordArray.sigBytes;
            digest = CryptoJS.lib.WordArray.create(newWords, newSigBytes);
        }
    }

    // Combine the first two hashes for the 32-byte key
    const keyWords = hashes[0].words.concat(hashes[1].words);
    const keySigBytes = hashes[0].sigBytes + hashes[1].sigBytes;
    const key = CryptoJS.lib.WordArray.create(keyWords, keySigBytes);

    // The third hash is the 16-byte IV
    const iv = hashes[2];

    return { key, iv };
}

function decryptSources(key_hex_string, value_base64_encrypted) {

    if (!key_hex_string) {
        console.error("decryptSources: Key is undefined or null.");
        throw new Error("Decryption key is missing.");
    }
    if (!value_base64_encrypted) {
        console.error("decryptSources: Encrypted value is undefined or null.");
        throw new Error("Encrypted value is missing.");
    }

    const encryptedWordArray = CryptoJS.enc.Base64.parse(value_base64_encrypted);

    if (encryptedWordArray.sigBytes < 16) { // Minimum 8 bytes "Salted__" + 8 bytes salt
        console.error("decryptSources: Encrypted data too short. Expected at least 16 bytes (Salted__ + salt).");
        throw new Error("Invalid encrypted data length.");
    }

    // Check for "Salted__" magic bytes (first 8 bytes, or 2 words)
    const saltedMagic = CryptoJS.lib.WordArray.create(encryptedWordArray.words.slice(0, 2), 8);

    // Extract salt (8 bytes from index 8 to 15, words 2 and 3)
    const saltWordArray = CryptoJS.lib.WordArray.create(encryptedWordArray.words.slice(2, 4), 8);

    // Extract data (from index 16 onwards)
    const dataWordArray = CryptoJS.lib.WordArray.create(encryptedWordArray.words.slice(4), encryptedWordArray.sigBytes - 16);

    // Parse the hex key string into actual bytes.
    const keyWordArray = CryptoJS.enc.Utf8.parse(key_hex_string);

    // Concatenate the key bytes WordArray with the salt bytes WordArray
    const initialPasswordForKDF = keyWordArray.concat(saltWordArray);

    // Pass this combined byte WordArray to the deriveKeyAndIv function
    const derived = deriveKeyAndIv(initialPasswordForKDF);

    let decrypted;
    try {
        decrypted = CryptoJS.AES.decrypt(
            { ciphertext: dataWordArray }, // This is the actual encrypted data bytes
            derived.key, // This is the derived key from KDF
            {
                iv: derived.iv, // This is the derived IV from KDF
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7 // Standard PKCS7 padding
            }
        );
    } catch (e) {
        console.error("decryptSources: AES decryption failed:", e);
        throw new Error("AES decryption failed. Check key, IV, mode, and padding. " + e.message);
    }

    let decryptedText;
    try {
        // If sigBytes is 0, it means decryption failed and produced an empty WordArray.
        if (decrypted.sigBytes === 0) {
            throw new Error("Decrypted WordArray is empty after AES decryption. This usually means decryption failed or input was empty.");
        }
        decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        console.error("decryptSources: Error converting decrypted data to UTF-8:", e);
        // Log the raw hex of the decrypted data if UTF-8 conversion fails
        console.error("decryptSources: Raw decrypted hex data (failed UTF-8 conversion):", decrypted.toString(CryptoJS.enc.Hex));
        throw new Error("Malformed UTF-8 data after decryption. Possible wrong key/IV or padding, or empty decrypted data: " + e.message);
    }
    return decryptedText;
}

async function getSomeData(url, headers = {}, params = {}) {
    const urlObj = new URL(url);
    Object.keys(params).forEach(key => urlObj.searchParams.append(key, params[key]));

    const response = await fetch(urlObj.toString(), { headers });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status} - ${errorText}`);
    }
    const data = await response.json();
    return data;
}

async function getSources(xrax) {
    try {
        let sourcesRes;
        sourcesRes = await getSomeData(`${baseUrl}/embed-2/v2/e-1/getSources`, {
            'User-Agent': userAgent,
            'Referer': baseUrl,
            'Origin': baseUrl,
        }, { id: xrax });

        if (!sourcesRes || !sourcesRes.sources) {
            console.error("extract: No sources found in response.");
            throw new Error("no sources found");
        }

        let key;
        try {
            key = await getMegaCloudKey();
        } catch (err) {
            console.error("extract: Error retrieving MegaCloud key:", err);
            throw new Error("Failed to retrieve MegaCloud key.");
        }

        if (!key) {
            console.error("extract: MegaCloud key is null or empty.");
            throw new Error("MegaCloud key is missing or invalid.");
        }

        let decrypted;
        try {
            const decryptedString = decryptSources(key, sourcesRes.sources);
            // const decryptedString = decryptSources("1c6b2db4e08cef974828318a0f025e71993e0a57440c4da6f302d914f7185682", "U2FsdGVkX1+gHc9AA5gxBf7kF9twdCKGuZx5bExcdin+4/SiNx+P22P8p0pmRAZCUqUqhkpmTpiauqeLjpYRTBbUuChowaXcGvpeLainqo9ZpooYU8D8QREyeItcJgaHMslcLPlQogBuHwHhPo+fmdCKk8cHya/8e0KXwp5MrDsx/Up6ILb+Uo8BL8TDQuJMOuwET87UhPOyWUD2K8uzt68jPiYNu7knaxlMcw+u7FD/RVYgyEj3NmOh+tyOArJ6GIOTUhn9jksozFBhMWV0UrtSrOaXLWNOJPyJDRKQkm+aPWzMZiIu2q7d+f1okg5bjocHOJWcFjZ+JvGHdmWd6YmLtLVnKs/8bvLvUovjGtsUQiTbOf0gOr6nioSxgVV03qDKmOvFikva8vPxhcplQna7OkErjZ/aOVezv8o2+EcCxaUZy7PYqQi9bmknE8FEbBpyfkls/bpoRC7IexHsgJ4OncT6Qcy3mssdkGNba1gEDzHwBlhQckWpZjhzSpq2oROgWWF8fkmJAPmAqIi0kw==");
            decrypted = JSON.parse(decryptedString);
        } catch (err) {
            console.error("extract: Error parsing decrypted sources to JSON:", err);
            throw new Error(`Failed to decrypt and parse sources: ${err.message}`);
        }

        return {
            sources: decrypted.map(source => {
                return {
                    file: source.file,
                }
            }),
            tracks: sourcesRes.tracks,
        };
    } catch (err) {
        console.error(err);
    }
}
