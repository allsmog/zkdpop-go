// zkDPoP Demo Application
class ZKDPoPDemo {
    constructor() {
        this.secp = new Secp256k1Crypto();
        this.schnorr = new SchnorrCrypto();
        this.dpop = new DPoPCrypto();
        
        this.privateKey = null;
        this.publicKey = null;
        this.publicKeyCompressed = null;
        this.jwtToken = null;
        
        this.baseUrl = window.location.origin;
        
        this.initializeEventListeners();
        this.updateUI();
    }
    
    initializeEventListeners() {
        document.getElementById('generateKeysBtn').addEventListener('click', () => this.generateKeys());
        document.getElementById('registerBtn').addEventListener('click', () => this.registerUser());
        document.getElementById('authBtn').addEventListener('click', () => this.authenticateUser());
        document.getElementById('testBtn').addEventListener('click', () => this.testProtectedEndpoint());
        document.getElementById('clearBtn').addEventListener('click', () => this.clearAll());
        document.getElementById('debugBtn').addEventListener('click', () => this.toggleDebugInfo());
    }
    
    updateUI() {
        const step1 = document.getElementById('step1');
        const step2 = document.getElementById('step2');
        const step3 = document.getElementById('step3');
        const step4 = document.getElementById('step4');
        
        // Reset step states
        [step1, step2, step3, step4].forEach(step => {
            step.className = 'step';
        });
        
        if (this.privateKey && this.publicKey) {
            step1.classList.add('completed');
            step2.classList.add('active');
            document.getElementById('registerBtn').disabled = false;
        } else {
            step1.classList.add('active');
            document.getElementById('registerBtn').disabled = true;
        }
        
        if (this.jwtToken) {
            step2.classList.remove('active');
            step2.classList.add('completed');
            step3.classList.add('completed');
            step4.classList.add('active');
            document.getElementById('testBtn').disabled = false;
        } else {
            document.getElementById('authBtn').disabled = !this.publicKey;
            document.getElementById('testBtn').disabled = true;
        }
    }
    
    showStatus(elementId, message, type = 'info') {
        const element = document.getElementById(elementId);
        element.innerHTML = `<div class="status ${type}">${message}</div>`;
    }
    
    async generateKeys() {
        try {
            this.showStatus('keysStatus', '🔑 Generating secp256k1 keypair...', 'info');
            
            // Generate secp256k1 keypair
            this.privateKey = this.secp.generatePrivateKey();
            const [pubX, pubY] = this.secp.privateKeyToPublic(this.privateKey);
            this.publicKey = [pubX, pubY];
            this.publicKeyCompressed = this.secp.compressPoint(pubX, pubY);
            
            // Generate DPoP keypair
            await this.dpop.generateKeyPair();
            const jkt = await this.dpop.getJWKThumbprint();
            
            // Update UI
            const pubKeyHex = this.secp.bytesToHex(this.publicKeyCompressed);
            document.getElementById('publicKeyDisplay').value = pubKeyHex;
            document.getElementById('jktDisplay').value = jkt;
            
            this.showStatus('keysStatus', '✅ Keys generated successfully!', 'success');
            this.updateUI();
            
        } catch (error) {
            this.showStatus('keysStatus', `❌ Error: ${error.message}`, 'error');
        }
    }
    
    async registerUser() {
        try {
            this.showStatus('registerStatus', '📝 Registering user...', 'info');
            
            const pubKeyHex = this.secp.bytesToHex(this.publicKeyCompressed);
            
            const response = await fetch(`${this.baseUrl}/api/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    pk: pubKeyHex,
                    meta: {
                        demo: true,
                        timestamp: new Date().toISOString()
                    }
                })
            });
            
            if (response.ok) {
                this.showStatus('registerStatus', '✅ User registered successfully!', 'success');
                document.getElementById('authBtn').disabled = false;
                document.getElementById('step3').classList.add('active');
            } else {
                const error = await response.text();
                this.showStatus('registerStatus', `❌ Registration failed: ${error}`, 'error');
            }
            
        } catch (error) {
            this.showStatus('registerStatus', `❌ Error: ${error.message}`, 'error');
        }
    }
    
    async authenticateUser() {
        try {
            this.showStatus('authStatus', '🔐 Starting ZK authentication...', 'info');
            
            // Step 1: Generate commitment
            const { r, T } = await this.schnorr.generateCommitment(this.privateKey);
            const pubKeyHex = this.secp.bytesToHex(this.publicKeyCompressed);
            const THex = this.secp.bytesToHex(T);
            
            // Step 2: Start commit phase with DPoP
            const commitUrl = `${this.baseUrl}/api/auth/zk/commit`;
            const dpopToken = await this.dpop.createDPoPToken('POST', commitUrl);
            
            this.showStatus('authStatus', '🤝 Sending commitment...', 'info');
            
            const commitResponse = await fetch(commitUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'DPoP': dpopToken
                },
                body: JSON.stringify({
                    pk: pubKeyHex,
                    T: THex,
                    aud: 'demo-api',
                    path: '/api/auth/zk/commit',
                    method: 'POST'
                })
            });
            
            if (!commitResponse.ok) {
                const error = await commitResponse.text();
                throw new Error(`Commit failed: ${error}`);
            }
            
            const commitData = await commitResponse.json();
            
            this.showStatus('authStatus', '🧮 Computing ZK proof...', 'info');
            
            // Step 3: Compute challenge and response
            const serverEphemeral = this.secp.hexToBytes(commitData.server_ephemeral);
            const context = await this.schnorr.deriveContext(
                'demo-api',
                '/api/auth/zk/commit',
                'POST',
                commitData.timeslice,
                serverEphemeral
            );
            
            const challenge = await this.schnorr.deriveChallenge(
                T,
                this.publicKeyCompressed,
                context
            );
            
            const response = this.schnorr.computeResponse(r, challenge, this.privateKey);
            const responseHex = this.secp.bytesToHex(response);
            
            // Step 4: Complete authentication
            const completeUrl = `${this.baseUrl}/api/auth/zk/complete`;
            const completeDPoPToken = await this.dpop.createDPoPToken('POST', completeUrl);
            
            this.showStatus('authStatus', '✅ Completing authentication...', 'info');
            
            const completeResponse = await fetch(completeUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'DPoP': completeDPoPToken
                },
                body: JSON.stringify({
                    session_id: commitData.session_id,
                    s: responseHex
                })
            });
            
            if (!completeResponse.ok) {
                const error = await completeResponse.text();
                throw new Error(`Complete failed: ${error}`);
            }
            
            const completeData = await completeResponse.json();
            this.jwtToken = completeData.access_token;
            
            // Update UI
            document.getElementById('tokenDisplay').value = this.jwtToken;
            this.showStatus('authStatus', '🎉 Authentication successful! JWT token received.', 'success');
            this.updateUI();
            
        } catch (error) {
            this.showStatus('authStatus', `❌ Authentication failed: ${error.message}`, 'error');
        }
    }
    
    async testProtectedEndpoint() {
        try {
            this.showStatus('testStatus', '🛡️ Accessing protected resource...', 'info');
            
            if (!this.jwtToken) {
                throw new Error('No JWT token available');
            }
            
            const protectedUrl = `${this.baseUrl}/api/protected`;
            const dpopToken = await this.dpop.createDPoPToken('GET', protectedUrl);
            
            const response = await fetch(protectedUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.jwtToken}`,
                    'DPoP': dpopToken
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.showStatus('testStatus', 
                    `🎉 Success! User ID: ${data.user_id}<br>` +
                    `🔐 ZK Scheme: ${data.zk_scheme}<br>` +
                    `🏷️ Group: ${data.zk_group}<br>` +
                    `🔑 DPoP JKT: ${data.dpop_jkt}`, 
                    'success'
                );
            } else {
                const error = await response.text();
                this.showStatus('testStatus', `❌ Access denied: ${error}`, 'error');
            }
            
        } catch (error) {
            this.showStatus('testStatus', `❌ Error: ${error.message}`, 'error');
        }
    }
    
    clearAll() {
        this.privateKey = null;
        this.publicKey = null;
        this.publicKeyCompressed = null;
        this.jwtToken = null;
        this.dpop = new DPoPCrypto();
        
        document.getElementById('publicKeyDisplay').value = '';
        document.getElementById('jktDisplay').value = '';
        document.getElementById('tokenDisplay').value = '';
        document.getElementById('debugInfo').style.display = 'none';
        
        // Clear all status messages
        ['keysStatus', 'registerStatus', 'authStatus', 'testStatus'].forEach(id => {
            document.getElementById(id).innerHTML = '';
        });
        
        this.updateUI();
    }
    
    toggleDebugInfo() {
        const debugInfo = document.getElementById('debugInfo');
        if (debugInfo.style.display === 'none') {
            this.showDebugInfo();
            debugInfo.style.display = 'block';
        } else {
            debugInfo.style.display = 'none';
        }
    }
    
    async showDebugInfo() {
        const debugData = {
            secp256k1: {
                privateKey: this.privateKey ? this.secp.bytesToHex(this.secp.bigIntToBytes(this.privateKey)) : null,
                publicKey: this.publicKey ? {
                    x: this.secp.bytesToHex(this.secp.bigIntToBytes(this.publicKey[0])),
                    y: this.secp.bytesToHex(this.secp.bigIntToBytes(this.publicKey[1])),
                    compressed: this.secp.bytesToHex(this.publicKeyCompressed)
                } : null
            },
            dpop: {
                jwk: this.dpop.keyPair ? await this.dpop.getJWK() : null,
                jkt: this.dpop.keyPair ? await this.dpop.getJWKThumbprint() : null
            },
            jwt: this.jwtToken ? {
                token: this.jwtToken,
                parts: this.jwtToken.split('.'),
                header: this.jwtToken ? JSON.parse(atob(this.jwtToken.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'))) : null,
                payload: this.jwtToken ? JSON.parse(atob(this.jwtToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))) : null
            } : null,
            endpoints: {
                base: this.baseUrl,
                register: `${this.baseUrl}/api/register`,
                commit: `${this.baseUrl}/api/auth/zk/commit`,
                complete: `${this.baseUrl}/api/auth/zk/complete`,
                protected: `${this.baseUrl}/api/protected`,
                jwks: `${this.baseUrl}/.well-known/jwks.json`
            }
        };
        
        document.getElementById('debugInfo').textContent = JSON.stringify(debugData, null, 2);
    }
}

// Initialize demo when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.demo = new ZKDPoPDemo();
});