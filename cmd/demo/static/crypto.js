// Secp256k1 Cryptographic Functions for zkDPoP Demo
class Secp256k1Crypto {
    constructor() {
        this.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
        this.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
        this.Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
        this.Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
    }
    
    // Modular arithmetic helpers
    mod(a, m) {
        return ((a % m) + m) % m;
    }
    
    modInverse(a, m) {
        if (a < 0n) a = this.mod(a, m);
        const g = this.gcdExtended(a, m);
        if (g[0] !== 1n) throw new Error('Modular inverse does not exist');
        return this.mod(g[1], m);
    }
    
    gcdExtended(a, b) {
        if (a === 0n) return [b, 0n, 1n];
        const [gcd, x1, y1] = this.gcdExtended(b % a, a);
        const x = y1 - (b / a) * x1;
        const y = x1;
        return [gcd, x, y];
    }
    
    // Elliptic curve point operations
    isOnCurve(x, y) {
        return this.mod(y * y - x * x * x - 7n, this.p) === 0n;
    }
    
    pointAdd(x1, y1, x2, y2) {
        if (x1 === null) return [x2, y2]; // Point at infinity
        if (x2 === null) return [x1, y1];
        if (x1 === x2 && y1 === y2) return this.pointDouble(x1, y1);
        if (x1 === x2) return [null, null]; // Point at infinity
        
        const s = this.mod((y2 - y1) * this.modInverse(x2 - x1, this.p), this.p);
        const x3 = this.mod(s * s - x1 - x2, this.p);
        const y3 = this.mod(s * (x1 - x3) - y1, this.p);
        
        return [x3, y3];
    }
    
    pointDouble(x, y) {
        if (x === null) return [null, null];
        const s = this.mod((3n * x * x) * this.modInverse(2n * y, this.p), this.p);
        const x3 = this.mod(s * s - 2n * x, this.p);
        const y3 = this.mod(s * (x - x3) - y, this.p);
        return [x3, y3];
    }
    
    pointMultiply(k, x, y) {
        if (k === 0n) return [null, null];
        if (k === 1n) return [x, y];
        
        let result = [null, null];
        let addend = [x, y];
        
        while (k > 0n) {
            if (k & 1n) {
                result = this.pointAdd(result[0], result[1], addend[0], addend[1]);
            }
            addend = this.pointDouble(addend[0], addend[1]);
            k >>= 1n;
        }
        
        return result;
    }
    
    // Key generation
    generatePrivateKey() {
        const array = new Uint8Array(32);
        do {
            crypto.getRandomValues(array);
            const privateKey = this.bytesToBigInt(array);
            if (privateKey > 0n && privateKey < this.n) {
                return privateKey;
            }
        } while (true);
    }
    
    privateKeyToPublic(privateKey) {
        return this.pointMultiply(privateKey, this.Gx, this.Gy);
    }
    
    // Utility functions
    bigIntToBytes(bigint, length = 32) {
        const hex = bigint.toString(16).padStart(length * 2, '0');
        return new Uint8Array(hex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    }
    
    bytesToBigInt(bytes) {
        return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    
    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    hexToBytes(hex) {
        if (hex.startsWith('0x')) hex = hex.slice(2);
        return new Uint8Array(hex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    }
    
    // Point compression/decompression
    compressPoint(x, y) {
        const xBytes = this.bigIntToBytes(x, 32);
        const prefix = y % 2n === 0n ? 0x02 : 0x03;
        return new Uint8Array([prefix, ...xBytes]);
    }
    
    decompressPoint(compressed) {
        const prefix = compressed[0];
        const x = this.bytesToBigInt(compressed.slice(1));
        
        // Calculate y² = x³ + 7
        const ySq = this.mod(x * x * x + 7n, this.p);
        let y = this.modPow(ySq, (this.p + 1n) / 4n, this.p);
        
        // Choose correct y based on parity
        if (y % 2n !== BigInt(prefix - 2)) {
            y = this.p - y;
        }
        
        return [x, y];
    }
    
    modPow(base, exp, mod) {
        let result = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            exp = exp >> 1n;
            base = (base * base) % mod;
        }
        return result;
    }
}

// Schnorr Signature Implementation
class SchnorrCrypto {
    constructor() {
        this.secp = new Secp256k1Crypto();
    }
    
    async hash(...inputs) {
        const data = new Uint8Array(inputs.reduce((acc, input) => acc + input.length, 0));
        let offset = 0;
        for (const input of inputs) {
            data.set(input, offset);
            offset += input.length;
        }
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hashBuffer);
    }
    
    async generateCommitment(privateKey) {
        const r = this.secp.generatePrivateKey();
        const [Tx, Ty] = this.secp.pointMultiply(r, this.secp.Gx, this.secp.Gy);
        const T = this.secp.compressPoint(Tx, Ty);
        return { r, T };
    }
    
    async deriveChallenge(T, publicKey, context) {
        const domainSep = new TextEncoder().encode('zkdpop/1/chal');
        const challengeHash = await this.hash(domainSep, T, publicKey, context);
        const challenge = this.secp.mod(this.secp.bytesToBigInt(challengeHash), this.secp.n);
        return this.secp.bigIntToBytes(challenge, 32);
    }
    
    async deriveContext(aud, path, method, timestamp, serverEphemeral) {
        const domainSep = new TextEncoder().encode('zkdpop/1/ctx');
        const audBytes = new TextEncoder().encode(aud);
        const pathBytes = new TextEncoder().encode(path);
        const methodBytes = new TextEncoder().encode(method);
        const timestampBytes = new TextEncoder().encode(timestamp);
        
        return await this.hash(domainSep, audBytes, pathBytes, methodBytes, timestampBytes, serverEphemeral);
    }
    
    computeResponse(r, challenge, privateKey) {
        const c = this.secp.bytesToBigInt(challenge);
        const s = this.secp.mod(r + c * privateKey, this.secp.n);
        return this.secp.bigIntToBytes(s, 32);
    }
}

// DPoP Token Implementation
class DPoPCrypto {
    constructor() {
        this.keyPair = null;
    }
    
    async generateKeyPair() {
        this.keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );
        return this.keyPair;
    }
    
    async getJWK() {
        if (!this.keyPair) throw new Error('No key pair generated');
        
        const jwk = await crypto.subtle.exportKey('jwk', this.keyPair.publicKey);
        return {
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y
        };
    }
    
    async getJWKThumbprint() {
        const jwk = await this.getJWK();
        const jwkString = JSON.stringify({
            crv: jwk.crv,
            kty: jwk.kty,
            x: jwk.x,
            y: jwk.y
        });
        
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(jwkString));
        return btoa(String.fromCharCode(...new Uint8Array(hash)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    async createDPoPToken(method, url) {
        if (!this.keyPair) throw new Error('No key pair generated');
        
        const jwk = await this.getJWK();
        const jti = crypto.randomUUID();
        const iat = Math.floor(Date.now() / 1000);
        
        const header = {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: jwk
        };
        
        const payload = {
            jti: jti,
            htm: method,
            htu: url,
            iat: iat
        };
        
        const headerB64 = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const payloadB64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        
        const signatureInput = headerB64 + '.' + payloadB64;
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            this.keyPair.privateKey,
            new TextEncoder().encode(signatureInput)
        );
        
        const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        return headerB64 + '.' + payloadB64 + '.' + signatureB64;
    }
}

// Export classes for use in app.js
window.Secp256k1Crypto = Secp256k1Crypto;
window.SchnorrCrypto = SchnorrCrypto;
window.DPoPCrypto = DPoPCrypto;