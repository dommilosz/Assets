(function (exports) {
    exports.signContent = function (password, certificate, content) {
        const p12Der = forge.util.decode64(certificate);
        const p12Asn1 = forge.asn1.fromDer(p12Der);
        const pkcs12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

        return importCryptoKeyPkcs8(loadPrivateKey(pkcs12), true).then(function (cryptoKey) {
            return crypto.subtle.sign(
                {name: "RSASSA-PKCS1-v1_5"},
                cryptoKey,
                stringToArrayBuffer(content)
            ).then(function (signature) {
                return forge.util.encode64(arrayBufferToString(signature));
            });
        });
    };

}(typeof exports === 'undefined' ? this.signer = {} : exports));

function arrayBufferToString(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}

function _privateKeyToPkcs8(privateKey) {
    const rsaPrivateKey = forge.pki.privateKeyToAsn1(privateKey);
    const privateKeyInfo = forge.pki.wrapRsaPrivateKey(rsaPrivateKey);
    const privateKeyInfoDer = forge.asn1.toDer(privateKeyInfo).getBytes();
    return stringToArrayBuffer(privateKeyInfoDer);
}

function stringToArrayBuffer(data) {
    const arrBuff = new ArrayBuffer(data.length);
    const writer = new Uint8Array(arrBuff);
    for (let i = 0, len = data.length; i < len; i++) {
        writer[i] = data.charCodeAt(i);
    }

    return arrBuff;
}

function loadPrivateKey(pkcs12) {
    for (let sci = 0; sci < pkcs12.safeContents.length; ++sci) {
        const safeContents = pkcs12.safeContents[sci];

        for (let sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
            const safeBag = safeContents.safeBags[sbi];

            if (safeBag.type === forge.pki.oids.keyBag) {
                return safeBag.key;
            } else if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                return safeBag.key;
            } else if (safeBag.type === forge.pki.oids.certBag) {
            }
        }
    }
}

function importCryptoKeyPkcs8(privateKey, extractable) {
    const privateKeyInfoDerBuff = _privateKeyToPkcs8(privateKey);

    return crypto.subtle.importKey('pkcs8',
        privateKeyInfoDerBuff, {
            name: "RSASSA-PKCS1-v1_5",
            hash: {name: "SHA-1"}
        },
        extractable,
        ["sign"]
    );
}
