
const tagLength = 16;

var _appendBuffer = function(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
};

function base64ToUint8Array(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function Uint8ArrayToBase64(arbuffer) {
    return btoa(String.fromCharCode(...arbuffer));
}

function AESGCMEncrypt(Base64IV, Base64AAD, Base64Key, Base64In) {
    const iv = base64ToUint8Array(Base64IV);
    const ivBuffer = Module._malloc(iv.length);
    Module.HEAPU8.set(iv, ivBuffer);

    const aad = base64ToUint8Array(Base64AAD);
    const aadBuffer = Module._malloc(aad.length);
    Module.HEAPU8.set(aad, aadBuffer);

    const key = base64ToUint8Array(Base64Key);
    const keyBuffer = Module._malloc(key.length);
    Module.HEAPU8.set(key, keyBuffer);

    const _in = base64ToUint8Array(Base64In);
    const _inBuffer = Module._malloc(_in.length);
    Module.HEAPU8.set(_in, _inBuffer);

    const out = new Uint8Array(_in.length);
    const outBuffer = Module._malloc(out.length);
    Module.HEAPU8.set(out, outBuffer);

    const tag = new Uint8Array(tagLength);
    const tagBuffer = Module._malloc(tag.length);
    Module.HEAPU8.set(tag, tagBuffer);

    const result = 
    Module.ccall('JSAESEncryptGCM', 'number', ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number' ], 
                 [_inBuffer, _in.length, aadBuffer, aad.length, keyBuffer, ivBuffer, iv.length, outBuffer, tagBuffer, tagLength]);

    if (result < 0) {
        console.log('encrypt failed');
    }

    const encryptedArbuf = Module.HEAPU8.subarray(outBuffer, outBuffer+out.length);
    const tagArbuf = Module.HEAPU8.subarray(tagBuffer, tagBuffer+tag.length);

    const bufferArray = _appendBuffer(encryptedArbuf, tagArbuf);
    const encryptedBase64 = Uint8ArrayToBase64(new Uint8Array(bufferArray));

    Module._free(ivBuffer);
    Module._free(aadBuffer);
    Module._free(keyBuffer);
    Module._free(_inBuffer);
    Module._free(outBuffer);
    Module._free(tagBuffer);

    return encryptedBase64;
}

function AESGCMDecrypt(Base64IV, Base64AAD, Base64Key, Base64In) {
    const iv = base64ToUint8Array(Base64IV);
    const ivBuffer = Module._malloc(iv.length);
    Module.HEAPU8.set(iv, ivBuffer);

    const aad = base64ToUint8Array(Base64AAD);
    const aadBuffer = Module._malloc(aad.length);
    Module.HEAPU8.set(aad, aadBuffer);

    const key = base64ToUint8Array(Base64Key);
    const keyBuffer = Module._malloc(key.length);
    Module.HEAPU8.set(key, keyBuffer);

    const _in = base64ToUint8Array(Base64In);
    const _inBuffer = Module._malloc(_in.length);
    Module.HEAPU8.set(_in, _inBuffer);

    const out = new Uint8Array(_in.length - 16);
    const outBuffer = Module._malloc(out.length);
    Module.HEAPU8.set(out, outBuffer);

    const CipherTextLen = _in.length - tagLength;
    const tag = _in.slice(CipherTextLen, _in.length);
    const tagBuffer = Module._malloc(tag.length);
    Module.HEAPU8.set(tag, tagBuffer);

    const resultLength =
    Module.ccall('JSAESDecryptGCM', 'number', ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number' ],
                [_inBuffer, CipherTextLen, aadBuffer, aad.length, tagBuffer, tagLength, keyBuffer, ivBuffer, iv.length, outBuffer]);

    if (resultLength < 0) {
        console.log('decrypt failed');
    }

    const decryptedArbuf = Module.HEAPU8.subarray(outBuffer, outBuffer+out.length);

    // const str = String.fromCharCode.apply(null,decryptedArbuf);
    // console.log('decrypted str = ', str);

    const decryptedBase64 = Uint8ArrayToBase64(decryptedArbuf);

    Module._free(ivBuffer);
    Module._free(aadBuffer);
    Module._free(keyBuffer);
    Module._free(_inBuffer);
    Module._free(outBuffer);
    Module._free(tagBuffer);

    return decryptedBase64;
}

// window.ssf = {
//     CryptoLib: {}
// };
// window.ssf.CryptoLib.AESGCMDecrypt = AESGCMDecrypt;
// window.ssf.CryptoLib.AESGCMEncrypt = AESGCMEncrypt;

function testCrypto() {
    debugger;
    // @Lynn Neir --> decrypted base 64: 'QEx5bm4gTmVpciA='
    const decryptedb64Text = AESGCMDecrypt("fPUHWXxVcwjZqgtCgwEkig==", "yaaITRl/qU5DTKH9A1TMtA==", "0LGtofpjrU7HrVdUlizam+C9a9cM4HTKDFmINjjigGM=", "ZsQOt9H4ottLu547GnJYCeNMJmcLtxnjAe6p")
    if (decryptedb64Text === 'QEx5bm4gTmVpciA=') {
      console.log('decrypt successfull')
    } else {
      console.log('decrypt failed')
    }

    // cleartext: test --> encrypted b64: jBCFO1wTNcKL0Uu1UfsZbeoTgN0=
    const encryptedb64Text = AESGCMEncrypt("FyARjJW+5Be2Lq8rXcFCxA==", "h46WgoNQBk5JXdyYQmq+hw==", "0LGtofpjrU7HrVdUlizam+C9a9cM4HTKDFmINjjigGM=", "dGVzdA==");
    if (encryptedb64Text === "jBCFO1wTNcKL0Uu1UfsZbeoTgN0=") {
        console.log('encryption successful');
    } else {
        console.log('encryption failed');
    }
}
