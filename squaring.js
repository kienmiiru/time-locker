onmessage = (e) => {
    n = BigInt(e.data.n)
    a = BigInt(e.data.a)
    t = BigInt(e.data.t)

    a = a % n
    for (; t > 0; t--) {
        a = (a * a) % n
        postMessage({ t, a })
    }
    postMessage({ t, a })
}