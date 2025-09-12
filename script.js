import * as asn1js from 'https://cdn.jsdelivr.net/npm/asn1js@3.0.6/+esm'
window.asn1js = asn1js

function uint8ArrayToInteger(arr) {
    return BigInt('0x' + arr.toHex())
    // let num = 0n
    // for (let i = 0; i < arr.length; i++) {
    //     num += BigInt(arr[arr.length - i - 1]) * 256n ** BigInt(i)
    // }
    // return num
}

function integerToUint8Array(num) {
    let hex = num.toString(16)
    if (hex.length % 2 != 0) {
        hex = '0' + hex
    }
    return Uint8Array.fromHex(hex)
}

async function generateAesKey() {
    return crypto.getRandomValues(new Uint8Array(32))
}

async function encryptAesGcm(key, plaintext) {
    key = await crypto.subtle.importKey(
        'raw',
        key,
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    )
    let iv = crypto.getRandomValues(new Uint8Array(16))

    let ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        plaintext
    )

    return { ciphertext, iv: iv.buffer }
}

async function decryptAesGcm(key, ciphertext, iv) {
    key = await crypto.subtle.importKey(
        'raw',
        key,
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    )
    let decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
        },
        key,
        ciphertext
  )

  return decrypted
}

function urlB64toInteger(b64) {
    b64 = b64.replaceAll('-', '+').replaceAll('_', '/')
    return uint8ArrayToInteger(Uint8Array.fromBase64(b64))
}

async function generateRsaKey() {
    let key = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
    )

    let jwk = await crypto.subtle.exportKey(
      'jwk',
      key.privateKey
    )

    let n = urlB64toInteger(jwk.n)
    let p = urlB64toInteger(jwk.p)
    let q = urlB64toInteger(jwk.q)

    return [n, p, q]
}

async function generateRandomBigIntBelow(n) {
    let byteLength = ((n.toString(2).length + 7) >> 3)

    while (true) {
        let randomBytes = new Uint8Array(byteLength)
        crypto.getRandomValues(randomBytes)

        let randomValue = 0n
        for (let i = 0; i < byteLength; i++) {
            randomValue = (randomValue << 8n) + BigInt(randomBytes[i])
        }

        if (randomValue < n) {
            return randomValue
        }
    }
}

function modularExponentiation(a, b, n) {
    a = a % n
    let result = 1n
    while (b > 0n) {
        if (b % 2n === 1n) {
            result = (result * a) % n
        }
        a = (a * a) % n
        b = b / 2n
    }
    return result
}

function encodePuzzle(puzzle) {
    let sequence = new asn1js.Sequence({
        value: [
            // Using string doesn't work
            new asn1js.Integer({ valueHex: integerToUint8Array(puzzle.n) }),
            new asn1js.Integer({ valueHex: integerToUint8Array(puzzle.a) }),
            new asn1js.Integer({ valueHex: integerToUint8Array(puzzle.t) }),
            new asn1js.OctetString({ valueHex: puzzle.ciphertext }),
            new asn1js.OctetString({ valueHex: puzzle.iv }),
            new asn1js.Integer({ valueHex: integerToUint8Array(puzzle.encryptedKey) })
        ]
    })

  return sequence.toBER()
}

function decodePuzzle(buffer) {
    let asn1 = asn1js.fromBER(buffer)
    let seq = asn1.result

    return {
        n: uint8ArrayToInteger(seq.valueBlock.value[0].valueBlock.valueHexView),
        a: uint8ArrayToInteger(seq.valueBlock.value[1].valueBlock.valueHexView),
        t: uint8ArrayToInteger(seq.valueBlock.value[2].valueBlock.valueHexView),
        ciphertext: new Uint8Array(seq.valueBlock.value[3].valueBlock.valueHex),
        iv: new Uint8Array(seq.valueBlock.value[4].valueBlock.valueHex),
        encryptedKey: uint8ArrayToInteger(seq.valueBlock.value[5].valueBlock.valueHexView)
    }
}

async function lock(t) {
    let fileElem = document.querySelector('#file')
    let file = fileElem.files[0]
    let fileBuffer = await file.arrayBuffer()

    let [n, p, q] = await generateRsaKey()
    let phi = (p - 1n) * (q - 1n)

    let aesKey = await generateAesKey()
    let { ciphertext, iv } = await encryptAesGcm(aesKey, fileBuffer)

    // A random value. TODO: make it (1, n) instead of [0, N)
    let a = await generateRandomBigIntBelow(n)
    // A variable that can help to compute a^2^t efficiently
    let e = modularExponentiation(2n, t, phi)
    // This is the a^2^t
    let b = modularExponentiation(a, e, n)
    // And this is the C_k
    let encryptedKey = (uint8ArrayToInteger(aesKey) + b) % n

    // Now we have the public value (n, a, t, (C_k, iv), C_m)
    let puzzle = { n, a, t, ciphertext, iv, encryptedKey }

    let encodedPuzzle = encodePuzzle(puzzle)
    let blob = new Blob([encodedPuzzle], { type: 'application/octet-stream' })
    let url = URL.createObjectURL(blob)

    let aElem = document.createElement('a')
    aElem.href = url
    aElem.download = file.name + '_locked'
    aElem.click()
}

document.querySelector('#lock').addEventListener('click', () => {
    let t = BigInt(document.querySelector('#t').value)
    lock(t)
})

async function unlock() {
    let fileElem = document.querySelector('#puzzle')
    let file = fileElem.files[0]
    let fileBuffer = await file.arrayBuffer()

    let puzzle = decodePuzzle(fileBuffer)
    let { n, a, t, ciphertext, iv, encryptedKey } = puzzle

    let squaringWorker = new Worker('./squaring.js')
    squaringWorker.postMessage({ n, a, t })
    squaringWorker.addEventListener('message', async (e) => {
        a = e.data.a
        t = e.data.t

        // Computation is complete, a is now a^2^t
        if (t == 0) {
            let aesKey = (encryptedKey - a) % n
            // Since javascript handle modulo differently
            if (aesKey < 0n) {
                aesKey += n
            }
            aesKey = integerToUint8Array(aesKey)

            let plaintext = await decryptAesGcm(aesKey, ciphertext, iv)
            let blob = new Blob([plaintext], { type: 'application/octet-stream' })
            let url = URL.createObjectURL(blob)

            let aElem = document.createElement('a')
            aElem.href = url
            aElem.download = file.name.endsWith('_locked') ? file.name.slice(0, -7) : file.name
            aElem.click()
        }
    })
}

document.querySelector('#unlock').addEventListener('click', () => {
    unlock()
})