import * as asn1js from 'https://cdn.jsdelivr.net/npm/asn1js@3.0.6/+esm'

let squaringPerSecond = 0

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

    return { ciphertext, iv }
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

async function generateRsaKey(modulusSize=2048) {
    let key = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: modulusSize,
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
            new asn1js.OctetString({ valueHex: integerToUint8Array(puzzle.n) }),
            new asn1js.OctetString({ valueHex: integerToUint8Array(puzzle.a) }),
            new asn1js.OctetString({ valueHex: integerToUint8Array(puzzle.t) }),
            new asn1js.OctetString({ valueHex: puzzle.ciphertext }),
            new asn1js.OctetString({ valueHex: puzzle.iv }),
            new asn1js.OctetString({ valueHex: integerToUint8Array(puzzle.encryptedKey) })
        ]
    })

  return sequence.toBER()
}

function decodePuzzle(buffer) {
    let asn1 = asn1js.fromBER(buffer)
    let seq = asn1.result
    console.log(seq)

    return {
        n: uint8ArrayToInteger(seq.valueBlock.value[0].valueBlock.valueHexView),
        a: uint8ArrayToInteger(seq.valueBlock.value[1].valueBlock.valueHexView),
        t: uint8ArrayToInteger(seq.valueBlock.value[2].valueBlock.valueHexView),
        ciphertext: seq.valueBlock.value[3].valueBlock.valueHexView,
        iv: seq.valueBlock.value[4].valueBlock.valueHexView,
        encryptedKey: uint8ArrayToInteger(seq.valueBlock.value[5].valueBlock.valueHexView)
    }
}

window.increaseTBy = function (num) {
    let t = BigInt(document.querySelector('#t').value)
    t += num
    document.querySelector('#t').value = t.toString()
    updateApproximation()
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
    aElem.text = 'Save as puzzle'
    fileElem.parentElement.appendChild(aElem)
}

document.querySelector('#lock').addEventListener('click', () => {
    let t = BigInt(document.querySelector('#t').value)
    lock(t)
})

async function unlock() {
    let progressElem = document.querySelector('#progress')
    let fileElem = document.querySelector('#puzzle')
    let file = fileElem.files[0]
    let fileBuffer = await file.arrayBuffer()

    let puzzle = decodePuzzle(fileBuffer)
    console.log(puzzle)
    let { n, a, t, ciphertext, iv, encryptedKey } = puzzle
    let originalT = t

    let squaringWorker = new Worker('./squaring.js')
    squaringWorker.postMessage({ n, a, t })
    squaringWorker.addEventListener('message', async (e) => {
        a = e.data.a
        t = e.data.t
        progressElem.value = 1000 - parseInt(1000n*t/originalT)

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
            aElem.text = 'Save unlocked file'
            fileElem.parentElement.appendChild(aElem)
        }
    })
}

function convertSecondsToTimeUnits(totalSeconds) {
    let units = [
        { label: 'year', seconds: 365 * 24 * 60 * 60 },
        { label: 'month', seconds: (365 * 24 * 60 * 60) / 12 },
        { label: 'day', seconds: 24 * 60 * 60 },
        { label: 'hour', seconds: 60 * 60 },
        { label: 'minute', seconds: 60 },
        { label: 'second', seconds: 1 }
    ]

    let parts = []

    for (let { label, seconds } of units) {
        let value = Math.floor(totalSeconds / seconds)
        if (value > 0) {
            parts.push(`${value} ${label}${value > 1 ? 's' : ''}`)
            totalSeconds %= seconds;
        }
    }

    return parts.length ? parts.join(' ') : '0 seconds'
}

function updateApproximation() {
    if (squaringPerSecond == 0) return
    let t = parseInt(document.querySelector('#t').value)
    let timeNeededInSecond = Math.round(t / squaringPerSecond)

    document.querySelector('#estimation').innerText = `Time needed to unlock: ~${convertSecondsToTimeUnits(timeNeededInSecond)}`
}

document.querySelector('#t').addEventListener('input', () => {
    updateApproximation()
})

document.querySelector('#unlock').addEventListener('click', () => {
    unlock()
})

document.querySelector('#speedtest').addEventListener('click', async () => {
    let [n, _, __] = await generateRsaKey(1024)
    let a = await generateRandomBigIntBelow(n)
    let t = 200000
    let squaringWorker = new Worker('./squaring.js')

    document.querySelector('#test-result').innerText = `Running test...`

    let startTime = performance.now()
    squaringWorker.postMessage({ n, a, t })
    squaringWorker.addEventListener('message', e => {
        if (e.data.t == 0) {
            let timeTaken = performance.now() - startTime
            squaringPerSecond = Math.round(1000*t / timeTaken)
            document.querySelector('#test-result').innerText = `Your machine can run ~${squaringPerSecond} squaring every second`
            updateApproximation()
        }
    })

    // let originalT = t
    // squaringWorker.postMessage({ n, a, t })
    // squaringWorker.addEventListener('message', e => {
    //     t = e.data.t
    // })

    // setTimeout(() => {
    //     squaringWorker.terminate()
    //     let squaringDone = originalT - t
    //     document.querySelector('#test-result').innerText = `Your machine can run ~${squaringDone} squaring every second`
    // }, 1000)
})