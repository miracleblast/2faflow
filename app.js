// ============ AUTHFLOW PRO - COMPLETE SPA PWA ============
// Real TOTP + License System + Team Management

// ============ REAL TOTP ENGINE ============
class RealTOTPEngine {
    constructor() {
        this.accounts = new Map();
        this.intervals = new Map();
        console.log('🔥 Real TOTP Engine Initialized!');
    }

    base32Decode(encoded) {
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        let result = '';

        encoded = encoded.replace(/=+$/, '').replace(/\s/g, '').toUpperCase();

        for (let i = 0; i < encoded.length; i++) {
            const val = base32Chars.indexOf(encoded[i]);
            if (val === -1) throw new Error('Invalid base32 character');
            bits += val.toString(2).padStart(5, '0');
        }

        for (let i = 0; i + 8 <= bits.length; i += 8) {
            const byte = bits.substr(i, 8);
            result += String.fromCharCode(parseInt(byte, 2));
        }

        return result;
    }

    numToBytes(num) {
        const byteArray = [];
        for (let i = 7; i >= 0; i--) {
            byteArray.push((num >>> (i * 8)) & 0xFF);
        }
        return byteArray;
    }

    generateTOTP(secret, window = 0) {
        try {
            const key = this.base32Decode(secret);
            const time = Math.floor(Date.now() / 1000 / 30) + window;
            const timeBuffer = this.numToBytes(time);
            
            const timeWordArray = CryptoJS.lib.WordArray.create(new Uint8Array(timeBuffer));
            const keyWordArray = CryptoJS.enc.Latin1.parse(key);
            
            const hmac = CryptoJS.HmacSHA1(timeWordArray, keyWordArray);
            const hmacWords = hmac.words;
            
            const offset = hmacWords[19] & 0xf;
            const code = (
                ((hmacWords[offset] & 0x7f) << 24) |
                ((hmacWords[offset + 1] & 0xff) << 16) |
                ((hmacWords[offset + 2] & 0xff) << 8) |
                (hmacWords[offset + 3] & 0xff)
            ) % 1000000;
            
            return code.toString().padStart(6, '0');
            
        } catch (error) {
            console.error('TOTP generation error:', error);
            return '000000';
        }
    }

    addAccount(accountId, name, secret, issuer = 'Unknown', type = 'TOTP') {
        const account = {
            id: accountId,
            name,
            secret,
            issuer,
            type,
            backupCodes: this.generateBackupCodes(),
            added: new Date(),
            lastUsed: null
        };

        this.accounts.set(accountId, account);
        this.startRealTimeUpdates(accountId);
        
        console.log(`✅ Added account: ${name}`);
        return account;
    }

    startRealTimeUpdates(accountId) {
        if (this.intervals.has(accountId)) {
            clearInterval(this.intervals.get(accountId));
        }

        const interval = setInterval(() => {
            const account = this.accounts.get(accountId);
            if (!account) return;

            const token = this.generateTOTP(account.secret);
            const timeLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
            
            window.dispatchEvent(new CustomEvent('realTokenUpdate', {
                detail: {
                    accountId,
                    token: this.formatToken(token),
                    timeLeft,
                    valid: timeLeft > 3,
                    rawToken: token
                }
            }));
            
        }, 1000);

        this.intervals.set(accountId, interval);
    }

    formatToken(token) {
        return token.replace(/(\d{3})(\d{3})/, '$1 $2');
    }

    generateBackupCodes(count = 10) {
        const codes = [];
        for (let i = 0; i < count; i++) {
            codes.push({
                code: Math.random().toString(36).substring(2, 10).toUpperCase(),
                used: false,
                usedAt: null
            });
        }
        return codes;
    }

    validateToken(secret, token, window = 1) {
        const cleanToken = token.replace(/\s/g, '');
        for (let i = -window; i <= window; i++) {
            if (this.generateTOTP(secret, i) === cleanToken) {
                return true;
            }
        }
        return false;
    }

    getAllAccounts() {
        return Array.from(this.accounts.values());
    }

    removeAccount(accountId) {
        if (this.intervals.has(accountId)) {
            clearInterval(this.intervals.get(accountId));
            this.intervals.delete(accountId);
        }
        this.accounts.delete(accountId);
    }
}

// ============ LICENSE MANAGER ============
class LicenseManager {
    constructor() {
        this.licenseKey = null;
        this.plan = null;
        this.expiryDate = null;
        this.features = {};
        this.pricing = {
            'starter': { price: 9.99, name: 'Starter', description: 'Perfect for freelancers' },
            'professional': { price: 15.99, name: 'Professional', description: 'Ideal for agencies' },
            'enterprise': { price: 49.99, name: 'Enterprise', description: 'For large teams' }
        };
    }

    async validateLicense(key) {
        return new Promise((resolve) => {
            setTimeout(() => {
                const demoLicenses = {
                    'AUTHFLOW-DEMO-1234': { 
                        plan: 'professional', 
                        expiry: '2024-12-31', 
                        active: true,
                        created: '2024-01-15'
                    },
                    'AUTHFLOW-TEST-5678': { 
                        plan: 'starter', 
                        expiry: '2024-06-30', 
                        active: true,
                        created: '2024-01-10'
                    }
                };
                
                const license = demoLicenses[key];
                if (license && license.active) {
                    this.licenseKey = key;
                    this.plan = license.plan;
                    this.expiryDate = new Date(license.expiry);
                    this.features = this.getFeaturesForPlan(license.plan);
                    
                    localStorage.setItem('authflow-license', JSON.stringify({
                        key: key,
                        plan: license.plan,
                        expiry: license.expiry,
                        created: license.created,
                        features: this.features
                    }));
                    
                    resolve(true);
                } else {
                    resolve(false);
                }
            }, 1000);
        });
    }

    getFeaturesForPlan(plan) {
        const features = {
            'starter': { 
                accounts: 10, 
                teamMembers: 3, 
                apiAccess: false, 
                advancedSecurity: false,
                prioritySupport: false
            },
            'professional': { 
                accounts: 50, 
                teamMembers: 10, 
                apiAccess: true, 
                advancedSecurity: true,
                prioritySupport: true
            },
            'enterprise': { 
                accounts: 9999, 
                teamMembers: 25, 
                apiAccess: true, 
                advancedSecurity: true,
                prioritySupport: true
            }
        };
        return features[plan] || features['starter'];
    }

    checkLicenseStatus() {
        const saved = localStorage.getItem('authflow-license');
        if (!saved) return false;

        const license = JSON.parse(saved);
        const now = new Date();
        const expiry = new Date(license.expiry);

        if (now > expiry) {
            this.invalidateLicense();
            return false;
        }

        this.licenseKey = license.key;
        this.plan = license.plan;
        this.expiryDate = expiry;
        this.features = license.features;
        
        return true;
    }

    getDaysUntilExpiry() {
        if (!this.expiryDate) return 0;
        const now = new Date();
        const expiry = new Date(this.expiryDate);
        const diffTime = expiry - now;
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays;
    }

    getLicenseStatus() {
        const days = this.getDaysUntilExpiry();
        if (days <= 0) return 'expired';
        if (days <= 7) return 'expiring';
        if (days <= 30) return 'warning';
        return 'active';
    }

    invalidateLicense() {
        localStorage.removeItem('authflow-license');
        localStorage.removeItem('authflow-authenticated');
        localStorage.removeItem('authflow-user');
        this.licenseKey = null;
        
        window.location.hash = 'license';
        window.location.reload();
    }

    hasFeature(feature) {
        return this.features[feature] === true;
    }

    getAccountLimit() {
        return this.features.accounts || 5;
    }

    getTeamLimit() {
        return this.features.teamMembers || 1;
    }

    getPlanPrice(plan) {
        return this.pricing[plan]?.price || 0;
    }

    getPlanName(plan) {
        return this.pricing[plan]?.name || 'Starter';
    }
}

// ============ MAIN SPA APPLICATION ============
class AuthFlowSPA {
    constructor() {
        this.currentPage = 'license';
        this.isAuthenticated = false;
        this.userData = null;
        this.accounts = [];
        this.teamMembers = [];
        this.securityLogs = [];
        this.apiKeys = [];
        this.settings = {};
        
        this.totpEngine = new RealTOTPEngine();
        this.licenseManager = new LicenseManager();
        
        this.init();
    }

    init() {
        this.setupRouter();
        this.setupRealTokenUpdates();
        this.loadData();
        
        const hasValidLicense = this.licenseManager.checkLicenseStatus();
        if (hasValidLicense) {
            this.navigate('login');
        } else {
            this.navigate('license');
        }
    }

    setupRouter() {
        window.addEventListener('popstate', (e) => {
            this.navigate(e.state?.page || 'license', false);
        });

        document.addEventListener('click', (e) => {
            const routeLink = e.target.closest('[data-route]');
            if (routeLink) {
                e.preventDefault();
                this.navigate(routeLink.getAttribute('data-route'));
            }
            
            if (e.target.closest('#logoutBtn')) {
                e.preventDefault();
                this.logout();
            }
        });
    }

    setupRealTokenUpdates() {
        window.addEventListener('realTokenUpdate', (event) => {
            const { accountId, token, timeLeft, valid } = event.detail;
            
            const tokenElement = document.getElementById(`token-${accountId}`);
            const timerElement = document.getElementById(`timer-${accountId}`);
            
            if (tokenElement) {
                tokenElement.textContent = token;
                tokenElement.className = `token-code ${!valid ? 'token-warning' : ''}`;
            }
            
            if (timerElement) {
                timerElement.textContent = `Expires in ${timeLeft}s`;
                timerElement.className = `token-timer ${!valid ? 'timer-warning' : ''}`;
            }
        });
    }

    navigate(page, pushState = true) {
        if (pushState) {
            history.pushState({ page }, '', `#${page}`);
        }

        this.currentPage = page;
        this.renderPage(page);
        
        // Show/hide global footer based on page
        this.toggleGlobalFooter(page);
    }

    toggleGlobalFooter(page) {
        const footer = document.getElementById('globalAuthFooter');
        if (!footer) return;

        // Show footer only on auth pages (license, login, register)
        const authPages = ['license', 'login', 'register'];
        if (authPages.includes(page)) {
            footer.style.display = 'block';
        } else {
            footer.style.display = 'none';
        }
    }

    async renderPage(page) {
        const app = document.getElementById('app');
        app.innerHTML = this.getLoadingTemplate();

        try {
            await new Promise(resolve => setTimeout(resolve, 200));

            let template;
            switch (page) {
                case 'license':
                    template = this.getLicenseTemplate();
                    break;
                case 'login':
                    template = this.getLoginTemplate();
                    break;
                case 'register':
                    template = this.getRegisterTemplate();
                    break;
                case 'dashboard':
                    if (!this.isAuthenticated) return this.navigate('login');
                    template = this.getDashboardTemplate();
                    break;
                case 'accounts':
                    if (!this.isAuthenticated) return this.navigate('login');
                    template = this.getAccountsTemplate();
                    break;
                case 'users':
                    if (!this.isAuthenticated) return this.navigate('login');
                    template = this.getUsersTemplate();
                    break;
                case 'api-keys':
                    if (!this.isAuthenticated) return this.navigate('login');
                    template = this.getApiKeysTemplate();
                    break;
                case 'security-logs':
                    if (!this.isAuthenticated) return this.navigate('login');
                    template = this.getSecurityLogsTemplate();
                    break;
                case 'settings':
                    if (!this.isAuthenticated) return this.navigate('login');
                    template = this.getSettingsTemplate();
                    break;
                default:
                    template = this.getLicenseTemplate();
            }

            app.innerHTML = template;
            this.initializePageScripts(page);
            
        } catch (error) {
            console.error('Error rendering page:', error);
            app.innerHTML = this.getErrorTemplate();
        }
    }

    // ============ PAGE TEMPLATES ============

    getLoadingTemplate() {
        return `
            <div class="loading-screen">
                <div class="logo">
                    <i class="bi bi-shield-check"></i>
                    <span>AuthFlow Pro</span>
                </div>
                <div class="spinner"></div>
            </div>
        `;
    }

    getErrorTemplate() {
        return `
            <div class="error-container">
                <div class="error-card">
                    <i class="bi bi-exclamation-triangle"></i>
                    <h3>Something went wrong</h3>
                    <p>Please try refreshing the page</p>
                    <button onclick="window.authFlowApp.navigate('dashboard')" class="btn-primary">
                        Back to Dashboard
                    </button>
                </div>
            </div>
        `;
    }

    getLicenseTemplate() {
        return `
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <div class="logo">
                            <i class="bi bi-shield-check"></i>
                            <span>AuthFlow Pro</span>
                        </div>
                        <p class="auth-subtitle">Activate Your License</p>
                    </div>

                    <div class="alert alert-danger" id="licenseError" style="display: none;">
                        <i class="bi bi-exclamation-triangle"></i>
                        <span id="licenseErrorText">Invalid license key</span>
                    </div>

                    <form id="licenseForm" class="auth-form">
                        <div class="form-group">
                            <label class="form-label">License Key</label>
                            <input type="text" class="form-control" id="licenseKey" 
                                   placeholder="AUTHFLOW-XXXX-XXXX-XXXX" required>
                        </div>

                        <button type="submit" class="btn-primary">
                            <i class="bi bi-key"></i>
                            Activate License
                        </button>
                    </form>

                    <div class="license-demo">
                        <h6><i class="bi bi-info-circle"></i> Demo License Keys</h6>
                        <p>Try these demo keys to test the app:</p>
                        <div class="demo-keys">
                            <code>AUTHFLOW-DEMO-1234</code> (Professional Plan - $15.99/month)
                            <br>
                            <code>AUTHFLOW-TEST-5678</code> (Starter Plan - $9.99/month)
                        </div>
                    </div>

                    <div class="auth-switch">
                        Need a license? <a href="#" onclick="authFlowApp.showPricingModal()" class="auth-link">View Pricing</a>
                    </div>
                </div>
            </div>
        `;
    }

    getLoginTemplate() {
        return `
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <div class="logo">
                            <i class="bi bi-shield-check"></i>
                            <span>AuthFlow Pro</span>
                        </div>
                        <p class="auth-subtitle">Secure 2FA Management for Teams</p>
                    </div>

                    <div class="alert alert-danger" id="errorAlert" style="display: none;">
                        <i class="bi bi-exclamation-triangle"></i>
                        <span id="errorText">Invalid credentials</span>
                    </div>

                    <form id="loginForm" class="auth-form">
                        <div class="form-group">
                            <label class="form-label">Email Address</label>
                            <input type="email" class="form-control" id="loginEmail" 
                                   placeholder="team@youragency.com" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" id="loginPassword" 
                                   placeholder="••••••••" required>
                        </div>

                        <div class="form-options">
                            <label class="form-check">
                                <input type="checkbox" id="rememberMe">
                                <span>Remember me</span>
                            </label>
                            <a href="#" class="auth-link">Forgot password?</a>
                        </div>

                        <button type="submit" class="btn-primary">
                            <i class="bi bi-box-arrow-in-right"></i>
                            Sign In
                        </button>
                    </form>

                    <div class="auth-switch">
                        Don't have an account? 
                        <a href="#" data-route="register" class="auth-link">Sign up</a>
                    </div>
                </div>
            </div>
        `;
    }

    getRegisterTemplate() {
        return `
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <div class="logo">
                            <i class="bi bi-shield-check"></i>
                            <span>Join AuthFlow Pro</span>
                        </div>
                        <p class="auth-subtitle">Start securing your team's accounts</p>
                    </div>

                    <form id="registerForm" class="auth-form">
                        <div class="form-group">
                            <label class="form-label">Full Name</label>
                            <input type="text" class="form-control" id="fullName" 
                                   placeholder="John Doe" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Company/Agency</label>
                            <input type="text" class="form-control" id="company" 
                                   placeholder="Your Agency Name" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Work Email</label>
                            <input type="email" class="form-control" id="regEmail" 
                                   placeholder="team@youragency.com" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" id="regPassword" 
                                   placeholder="••••••••" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Confirm Password</label>
                            <input type="password" class="form-control" id="confirmPassword" 
                                   placeholder="••••••••" required>
                        </div>

                        <div class="form-check">
                            <input type="checkbox" id="agreeTerms" required>
                            <label for="agreeTerms">
                                I agree to the <a href="#" class="auth-link">Terms</a> and 
                                <a href="#" class="auth-link">Privacy Policy</a>
                            </label>
                        </div>

                        <button type="submit" class="btn-primary">
                            <i class="bi bi-person-plus"></i>
                            Create Account
                        </button>
                    </form>

                    <div class="auth-switch">
                        Already have an account? 
                        <a href="#" data-route="login" class="auth-link">Sign in</a>
                    </div>
                </div>
            </div>
        `;
    }

    getDashboardTemplate() {
        const accountLimit = this.licenseManager.getAccountLimit();
        const teamLimit = this.licenseManager.getTeamLimit();
        const daysUntilExpiry = this.licenseManager.getDaysUntilExpiry();
        const licenseStatus = this.licenseManager.getLicenseStatus();
        
        return `
            <div class="app-wrapper">
                <header class="app-header">
                    <div class="app-container">
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="#" data-route="dashboard" class="logo">
                                <i class="bi bi-shield-check"></i>
                                <span>AuthFlow Pro</span>
                            </a>
                            
                            <div class="d-flex align-items-center gap-4">
                                <nav class="d-flex gap-3 nav-menu">
                                    <a href="#" data-route="dashboard" class="nav-link active">Dashboard</a>
                                    <a href="#" data-route="accounts" class="nav-link">Accounts</a>
                                    <a href="#" data-route="users" class="nav-link">Users</a>
                                    <a href="#" data-route="api-keys" class="nav-link">API Keys</a>
                                    <a href="#" data-route="security-logs" class="nav-link">Security Logs</a>
                                </nav>
                                
                                <div class="dropdown">
                                    <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                        <span>${this.userData?.initials || 'JD'}</span>
                                    </div>
                                    <ul class="dropdown-menu dropdown-menu-dark">
                                        <li><span class="dropdown-item-text">
                                            <small>Plan: ${this.licenseManager.plan}</small>
                                        </span></li>
                                        <li><hr class="dropdown-divider"></li>
                                        <li><a class="dropdown-item" href="#" data-route="settings"><i class="bi bi-gear"></i> Settings</a></li>
                                        <li><a class="dropdown-item text-warning" href="#" onclick="authFlowApp.showPricingModal()"><i class="bi bi-arrow-repeat"></i> Upgrade Plan</a></li>
                                        <li><hr class="dropdown-divider"></li>
                                        <li><a class="dropdown-item text-danger" href="#" id="logoutBtn"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main class="app-container">
                    <!-- License Status Banner -->
                    ${licenseStatus === 'expiring' ? `
                        <div class="alert alert-warning mb-4">
                            <div class="d-flex align-items-center justify-content-between">
                                <div>
                                    <i class="bi bi-exclamation-triangle"></i>
                                    Your license expires in ${daysUntilExpiry} days
                                </div>
                                <button class="btn btn-sm btn-warning" onclick="authFlowApp.showPricingModal()">
                                    Renew Now
                                </button>
                            </div>
                        </div>
                    ` : ''}

                    ${licenseStatus === 'warning' ? `
                        <div class="alert alert-info mb-4">
                            <div class="d-flex align-items-center justify-content-between">
                                <div>
                                    <i class="bi bi-info-circle"></i>
                                    Your license expires in ${daysUntilExpiry} days
                                </div>
                                <button class="btn btn-sm btn-primary" onclick="authFlowApp.showPricingModal()">
                                    Renew Early
                                </button>
                            </div>
                        </div>
                    ` : ''}

                    <div class="dashboard-section">
                        <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                            <h1 class="section-title">
                                <i class="bi bi-speedometer2"></i>
                                Dashboard
                            </h1>
                            <div class="license-badge">
                                ${this.licenseManager.plan} Plan • 
                                ${this.accounts.length}/${accountLimit} Accounts •
                                ${daysUntilExpiry} days remaining
                            </div>
                        </div>
                        
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value">${this.accounts.length}</div>
                                <div class="stat-label">Connected Accounts</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${new Set(this.accounts.map(a => a.platform)).size}</div>
                                <div class="stat-label">Platforms</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${this.teamMembers.length}</div>
                                <div class="stat-label">Team Members</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${this.securityLogs.length}</div>
                                <div class="stat-label">Security Events</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="dashboard-section">
                        <div class="row">
                            <div class="col-lg-8">
                                <h2 class="section-title">
                                    <i class="bi bi-person-badge"></i>
                                    Recent Accounts
                                </h2>
                                
                                <div class="card">
                                    <div class="card-header">
                                        <span>Active Accounts</span>
                                        <span class="badge bg-primary">${this.accounts.length}</span>
                                    </div>
                                    <div class="card-body" id="accountsList">
                                        ${this.accounts.slice(0, 5).map(account => this.getAccountCardTemplate(account)).join('')}
                                        ${this.accounts.length === 0 ? `
                                            <div class="empty-state">
                                                <i class="bi bi-person-badge"></i>
                                                <p>No accounts added yet</p>
                                                <button class="btn btn-primary" data-route="accounts">
                                                    Add Your First Account
                                                </button>
                                            </div>
                                        ` : `
                                            <div class="text-center mt-3">
                                                <a href="#" data-route="accounts" class="btn btn-outline-primary">
                                                    View All Accounts
                                                </a>
                                            </div>
                                        `}
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-lg-4">
                                <h2 class="section-title">
                                    <i class="bi bi-lightning"></i>
                                    Quick Actions
                                </h2>
                                
                                <div class="card">
                                    <div class="card-body">
                                        <div class="quick-actions">
                                            <a href="#" data-route="accounts" class="action-btn">
                                                <div class="action-icon"><i class="bi bi-plus-circle"></i></div>
                                                <div class="action-text">Add Account</div>
                                            </a>
                                            <a href="#" data-route="users" class="action-btn">
                                                <div class="action-icon"><i class="bi bi-person-plus"></i></div>
                                                <div class="action-text">Invite User</div>
                                            </a>
                                            <a href="#" data-route="api-keys" class="action-btn">
                                                <div class="action-icon"><i class="bi bi-key"></i></div>
                                                <div class="action-text">API Keys</div>
                                            </a>
                                            <a href="#" class="action-btn" onclick="authFlowApp.exportAllTokens()">
                                                <div class="action-icon"><i class="bi bi-download"></i></div>
                                                <div class="action-text">Export Codes</div>
                                            </a>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="card mt-4">
                                    <div class="card-header">
                                        <span>License Information</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="license-info">
                                            <div class="license-item">
                                                <span class="license-label">Plan:</span>
                                                <span class="license-value">${this.licenseManager.getPlanName(this.licenseManager.plan)}</span>
                                            </div>
                                            <div class="license-item">
                                                <span class="license-label">Price:</span>
                                                <span class="license-value">$${this.licenseManager.getPlanPrice(this.licenseManager.plan)}/month</span>
                                            </div>
                                            <div class="license-item">
                                                <span class="license-label">Expires:</span>
                                                <span class="license-value ${licenseStatus !== 'active' ? 'text-warning' : ''}">
                                                    ${daysUntilExpiry} days
                                                </span>
                                            </div>
                                            <div class="license-item">
                                                <span class="license-label">Status:</span>
                                                <span class="license-value">
                                                    <span class="badge ${licenseStatus === 'active' ? 'bg-success' : licenseStatus === 'warning' ? 'bg-warning' : 'bg-danger'}">
                                                        ${licenseStatus.charAt(0).toUpperCase() + licenseStatus.slice(1)}
                                                    </span>
                                                </span>
                                            </div>
                                        </div>
                                        <button class="btn btn-primary w-100 mt-3" onclick="authFlowApp.showPricingModal()">
                                            <i class="bi bi-arrow-repeat"></i>
                                            Manage Subscription
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="dashboard-section">
                        <div class="row">
                            <div class="col-lg-6">
                                <h2 class="section-title">
                                    <i class="bi bi-people"></i>
                                    Team Members
                                </h2>
                                <div class="card">
                                    <div class="card-header">
                                        <span>Active Team</span>
                                        <span class="badge bg-primary">${this.teamMembers.length}/${teamLimit}</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="user-list">
                                            ${this.teamMembers.slice(0, 4).map(user => this.getUserItemTemplate(user)).join('')}
                                            ${this.teamMembers.length === 0 ? `
                                                <div class="empty-state">
                                                    <i class="bi bi-people"></i>
                                                    <p>No team members yet</p>
                                                    <button class="btn btn-primary" data-route="users">
                                                        Invite Team Members
                                                    </button>
                                                </div>
                                            ` : `
                                                <div class="text-center mt-3">
                                                    <a href="#" data-route="users" class="btn btn-outline-primary">
                                                        Manage Team
                                                    </a>
                                                </div>
                                            `}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-lg-6">
                                <h2 class="section-title">
                                    <i class="bi bi-clock-history"></i>
                                    Recent Activity
                                </h2>
                                <div class="card">
                                    <div class="card-header">
                                        <span>Security Events</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="security-events">
                                            ${this.securityLogs.slice(0, 5).map(log => `
                                                <div class="security-event">
                                                    <div class="event-icon">
                                                        <i class="bi bi-${log.icon || 'shield-check'}"></i>
                                                    </div>
                                                    <div class="event-details">
                                                        <div class="event-action">${log.action}</div>
                                                        <div class="event-meta">${log.user} • ${log.time}</div>
                                                    </div>
                                                    <div class="event-status ${log.status === 'Success' ? 'success' : 'failed'}">
                                                        <i class="bi bi-${log.status === 'Success' ? 'check' : 'x'}"></i>
                                                    </div>
                                                </div>
                                            `).join('')}
                                        </div>
                                        <div class="text-center mt-3">
                                            <a href="#" data-route="security-logs" class="btn btn-outline-primary">
                                                View All Logs
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        `;
    }

getAccountCardTemplate(account) {
    return `
        <div class="account-card" data-account-id="${account.id}">
            <div class="platform-icon platform-${account.platform}">
                <span class="iconify" data-icon="${account.icon}"></span>
            </div>
            <div class="account-info">
                <div class="account-name">${account.name}</div>
                <div class="account-username">${account.username}</div>
            </div>
            <div class="text-end">
                <div class="token-code" id="token-${account.id}">Loading...</div>
                <div class="token-timer" id="timer-${account.id}">Calculating...</div>
            </div>
        </div>
    `;
}

getUserItemTemplate(user) {
    return `
        <div class="user-item">
            <div class="user-avatar-sm">${user.initials}</div>
            <div class="user-details">
                <div class="user-name">${user.name}</div>
                <div class="user-role">${user.role}</div>
            </div>
            <div class="user-status ${user.status === 'online' ? 'online' : 'offline'}"></div>
        </div>
    `;
}

getAccountsTemplate() {
    const accountLimit = this.licenseManager.getAccountLimit();
    const canAddMore = this.accounts.length < accountLimit;
    
    return `
        <div class="app-wrapper">
            <header class="app-header">
                <div class="app-container">
                    <div class="d-flex justify-content-between align-items-center">
                        <a href="#" data-route="dashboard" class="logo">
                            <span class="iconify" data-icon="mdi:shield-account"></span>
                            <span>AuthFlow Pro</span>
                        </a>
                        
                        <div class="d-flex align-items-center gap-4">
                            <nav class="d-flex gap-3 nav-menu">
                                <a href="#" data-route="dashboard" class="nav-link">
                                    <span class="iconify" data-icon="mdi:view-dashboard"></span>
                                    Dashboard
                                </a>
                                <a href="#" data-route="accounts" class="nav-link">
                                    <span class="iconify" data-icon="mdi:account-multiple"></span>
                                    Accounts
                                </a>
                                <a href="#" data-route="users" class="nav-link active">
                                    <span class="iconify" data-icon="mdi:users"></span>
                                    Users
                                </a>
                                <a href="#" data-route="api-keys" class="nav-link">
                                    <span class="iconify" data-icon="mdi:key-chain"></span>
                                    API Keys
                                </a>
                                <a href="#" data-route="security-logs" class="nav-link">
                                    <span class="iconify" data-icon="mdi:shield-account"></span>
                                    Security Logs
                                </a>
                            </nav>
                            
                            <div class="dropdown">
                                <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                    <span>${this.userData?.initials || 'JD'}</span>
                                </div>
                                <ul class="dropdown-menu dropdown-menu-dark">
                                    <li><a class="dropdown-item" href="#" data-route="settings">
                                        <span class="iconify" data-icon="mdi:cog"></span>
                                        Settings
                                    </a></li>
                                    <li><a class="dropdown-item text-danger" href="#" id="logoutBtn">
                                        <span class="iconify" data-icon="mdi:logout"></span>
                                        Logout
                                    </a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            <main class="app-container">
                <div class="dashboard-section">
                    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                        <h1 class="section-title">
                            <span class="iconify" data-icon="mdi:account-badge"></span>
                            Account Management
                        </h1>
                        <div>
                            <span class="me-3">${this.accounts.length}/${accountLimit} Accounts</span>
                            <button class="btn btn-primary d-flex align-items-center gap-2" 
                                    id="addAccountBtn" ${!canAddMore ? 'disabled' : ''}>
                                <span class="iconify" data-icon="mdi:plus-circle"></span>
                                Add Account
                            </button>
                        </div>
                    </div>

                    ${!canAddMore ? `
                        <div class="alert alert-warning">
                            <span class="iconify" data-icon="mdi:alert-circle"></span>
                            You've reached your account limit (${accountLimit}). 
                            <a href="#" onclick="authFlowApp.showPricingModal()" class="alert-link">Upgrade your plan</a> to add more accounts.
                        </div>
                    ` : ''}

                    <div class="card">
                        <div class="card-header">
                            <span>All Connected Accounts</span>
                            <span class="badge bg-primary">${this.accounts.length}</span>
                        </div>
                        <div class="card-body">
                            ${this.accounts.length > 0 ? `
                                <div class="accounts-grid">
                                    ${this.accounts.map(account => `
                                        <div class="account-card-large">
                                            <div class="account-header">
                                                <div class="platform-icon platform-${account.platform}">
                                                    <span class="iconify" data-icon="${account.icon}"></span>
                                                </div>
                                                <div class="account-title">
                                                    <h5>${account.name}</h5>
                                                    <span>${account.username}</span>
                                                </div>
                                                <div class="account-actions">
                                                    <button class="btn btn-sm btn-outline-primary" onclick="authFlowApp.copyToken('${account.id}')">
                                                        <span class="iconify" data-icon="mdi:content-copy"></span>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-danger" onclick="authFlowApp.removeAccount('${account.id}')">
                                                        <span class="iconify" data-icon="mdi:trash-can"></span>
                                                    </button>
                                                </div>
                                            </div>
                                            <div class="account-token">
                                                <div class="token-display">
                                                    <span class="token-code" id="token-${account.id}">Loading...</span>
                                                    <span class="token-timer" id="timer-${account.id}">Calculating...</span>
                                                </div>
                                            </div>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : `
                                <div class="empty-state">
                                    <span class="iconify" data-icon="mdi:account-badge" style="font-size: 4rem;"></span>
                                    <h3>No Accounts Yet</h3>
                                    <p>Add your first 2FA account to get started</p>
                                    <button class="btn btn-primary" id="addFirstAccountBtn">
                                        <span class="iconify" data-icon="mdi:plus-circle"></span>
                                        Add Your First Account
                                    </button>
                                </div>
                            `}
                        </div>
                    </div>
                </div>
            </main>
        </div>
    `;
}

    getUsersTemplate() {
        const teamLimit = this.licenseManager.getTeamLimit();
        const canAddMore = this.teamMembers.length < teamLimit;
        
        return `
            <div class="app-wrapper">
                <header class="app-header">
                    <div class="app-container">
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="#" data-route="dashboard" class="logo">
                                <i class="bi bi-shield-check"></i>
                                <span>AuthFlow Pro</span>
                            </a>
                            
                            <div class="d-flex align-items-center gap-4">
                                <nav class="d-flex gap-3 nav-menu">
                                    <a href="#" data-route="dashboard" class="nav-link">Dashboard</a>
                                    <a href="#" data-route="accounts" class="nav-link">Accounts</a>
                                    <a href="#" data-route="users" class="nav-link active">Users</a>
                                    <a href="#" data-route="api-keys" class="nav-link">API Keys</a>
                                    <a href="#" data-route="security-logs" class="nav-link">Security Logs</a>
                                </nav>
                                
                                <div class="dropdown">
                                    <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                        <span>${this.userData?.initials || 'JD'}</span>
                                    </div>
                                    <ul class="dropdown-menu dropdown-menu-dark">
                                        <li><a class="dropdown-item" href="#" data-route="settings"><i class="bi bi-gear"></i> Settings</a></li>
                                        <li><a class="dropdown-item text-danger" href="#" id="logoutBtn"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main class="app-container">
                    <div class="dashboard-section">
                        <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                            <h1 class="section-title">
                                <i class="bi bi-people"></i>
                                Team Management
                            </h1>
                            <div>
                                <span class="me-3">${this.teamMembers.length}/${teamLimit} Users</span>
                                <button class="btn btn-primary d-flex align-items-center gap-2" 
                                        id="inviteUserBtn" ${!canAddMore ? 'disabled' : ''}>
                                    <i class="bi bi-person-plus"></i>
                                    Invite User
                                </button>
                            </div>
                        </div>

                        ${!canAddMore ? `
                            <div class="alert alert-warning">
                                <i class="bi bi-exclamation-triangle"></i>
                                You've reached your team member limit (${teamLimit}). 
                                <a href="#" onclick="authFlowApp.showPricingModal()" class="alert-link">Upgrade your plan</a> to add more team members.
                            </div>
                        ` : ''}

                        <div class="card">
                            <div class="card-header">
                                <span>Team Members</span>
                                <span class="badge bg-primary">${this.teamMembers.length}</span>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-dark table-hover">
                                        <thead>
                                            <tr>
                                                <th>User</th>
                                                <th>Role</th>
                                                <th>Status</th>
                                                <th>Last Active</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${this.teamMembers.map(user => `
                                                <tr>
                                                    <td>
                                                        <div class="d-flex align-items-center gap-2">
                                                            <div class="user-avatar-sm">${user.initials}</div>
                                                            <div>
                                                                <div class="user-name">${user.name}</div>
                                                                <div class="user-email">${user.email}</div>
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <span class="badge ${user.role === 'admin' ? 'bg-primary' : 'bg-secondary'}">
                                                            ${user.role}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span class="user-status-indicator ${user.status === 'online' ? 'online' : 'offline'}">
                                                            ${user.status === 'online' ? 'Online' : 'Offline'}
                                                        </span>
                                                    </td>
                                                    <td>${user.lastActive || 'Recently'}</td>
                                                    <td>
                                                        <div class="btn-group">
                                                            <button class="btn btn-sm btn-outline-primary" onclick="authFlowApp.editUser('${user.id}')">
                                                                <i class="bi bi-pencil"></i>
                                                            </button>
                                                            ${user.role !== 'admin' ? `
                                                                <button class="btn btn-sm btn-outline-danger" onclick="authFlowApp.removeUser('${user.id}')">
                                                                    <i class="bi bi-trash"></i>
                                                                </button>
                                                            ` : ''}
                                                        </div>
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="row mt-4">
                            <div class="col-lg-6">
                                <div class="card">
                                    <div class="card-header">
                                        <span>Role Permissions</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="permissions-list">
                                            <div class="permission-item">
                                                <h6><i class="bi bi-person-gear"></i> Administrator</h6>
                                                <ul>
                                                    <li>Full system access</li>
                                                    <li>Manage team members</li>
                                                    <li>View all security logs</li>
                                                    <li>Manage API keys</li>
                                                </ul>
                                            </div>
                                            <div class="permission-item">
                                                <h6><i class="bi bi-person-check"></i> Manager</h6>
                                                <ul>
                                                    <li>Add/remove accounts</li>
                                                    <li>Generate 2FA codes</li>
                                                    <li>View limited logs</li>
                                                    <li>No team management</li>
                                                </ul>
                                            </div>
                                            <div class="permission-item">
                                                <h6><i class="bi bi-person"></i> User</h6>
                                                <ul>
                                                    <li>Generate 2FA codes</li>
                                                    <li>View own activity</li>
                                                    <li>No administrative access</li>
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-lg-6">
                                <div class="card">
                                    <div class="card-header">
                                        <span>Invite New User</span>
                                    </div>
                                    <div class="card-body">
                                        <form id="inviteUserForm">
                                            <div class="form-group">
                                                <label class="form-label">Email Address</label>
                                                <input type="email" class="form-control" placeholder="colleague@agency.com" required>
                                            </div>
                                            <div class="form-group">
                                                <label class="form-label">Role</label>
                                                <select class="form-control">
                                                    <option value="user">User</option>
                                                    <option value="manager">Manager</option>
                                                    <option value="admin">Administrator</option>
                                                </select>
                                            </div>
                                            <button type="submit" class="btn btn-primary w-100">
                                                <i class="bi bi-send"></i>
                                                Send Invitation
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        `;
    }

    getApiKeysTemplate() {
        return `
            <div class="app-wrapper">
                <header class="app-header">
                    <div class="app-container">
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="#" data-route="dashboard" class="logo">
                                <i class="bi bi-shield-check"></i>
                                <span>AuthFlow Pro</span>
                            </a>
                            
                            <div class="d-flex align-items-center gap-4">
                                <nav class="d-flex gap-3 nav-menu">
                                    <a href="#" data-route="dashboard" class="nav-link">Dashboard</a>
                                    <a href="#" data-route="accounts" class="nav-link">Accounts</a>
                                    <a href="#" data-route="users" class="nav-link">Users</a>
                                    <a href="#" data-route="api-keys" class="nav-link active">API Keys</a>
                                    <a href="#" data-route="security-logs" class="nav-link">Security Logs</a>
                                </nav>
                                
                                <div class="dropdown">
                                    <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                        <span>${this.userData?.initials || 'JD'}</span>
                                    </div>
                                    <ul class="dropdown-menu dropdown-menu-dark">
                                        <li><a class="dropdown-item" href="#" data-route="settings"><i class="bi bi-gear"></i> Settings</a></li>
                                        <li><a class="dropdown-item text-danger" href="#" id="logoutBtn"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main class="app-container">
                    <div class="dashboard-section">
                        <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                            <h1 class="section-title">
                                <i class="bi bi-key"></i>
                                API Keys Management
                            </h1>
                            <button class="btn btn-primary d-flex align-items-center gap-2" id="generateApiKeyBtn">
                                <i class="bi bi-plus-circle"></i>
                                Generate New Key
                            </button>
                        </div>

                        ${!this.licenseManager.hasFeature('apiAccess') ? `
                            <div class="alert alert-warning">
                                <i class="bi bi-exclamation-triangle"></i>
                                API access is not available on your current plan. 
                                <a href="#" onclick="authFlowApp.showPricingModal()" class="alert-link">Upgrade to Professional</a> to enable API features.
                            </div>
                        ` : ''}

                        <div class="card">
                            <div class="card-header">
                                <span>Active API Keys</span>
                                <span class="badge bg-primary">${this.apiKeys.length}</span>
                            </div>
                            <div class="card-body">
                                ${this.apiKeys.length > 0 ? `
                                    <div class="api-keys-list">
                                        ${this.apiKeys.map(key => `
                                            <div class="api-key-item">
                                                <div class="api-key-info">
                                                    <div class="api-key-name">
                                                        <strong>${key.name}</strong>
                                                        <span class="api-key-value">${key.key}</span>
                                                    </div>
                                                    <div class="api-key-meta">
                                                        <span>Created: ${key.created}</span>
                                                        <span>Last used: ${key.lastUsed || 'Never'}</span>
                                                        <span class="badge ${key.active ? 'bg-success' : 'bg-secondary'}">
                                                            ${key.active ? 'Active' : 'Inactive'}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div class="api-key-actions">
                                                    <button class="btn btn-sm btn-outline-primary" onclick="authFlowApp.copyApiKey('${key.id}')">
                                                        <i class="bi bi-clipboard"></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-warning" onclick="authFlowApp.regenerateApiKey('${key.id}')">
                                                        <i class="bi bi-arrow-repeat"></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-danger" onclick="authFlowApp.revokeApiKey('${key.id}')">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </div>
                                            </div>
                                        `).join('')}
                                    </div>
                                ` : `
                                    <div class="empty-state">
                                        <i class="bi bi-key"></i>
                                        <h3>No API Keys</h3>
                                        <p>Generate your first API key to integrate with other applications</p>
                                        ${this.licenseManager.hasFeature('apiAccess') ? `
                                            <button class="btn btn-primary" id="generateFirstApiKeyBtn">
                                                <i class="bi bi-plus-circle"></i>
                                                Generate First API Key
                                            </button>
                                        ` : ''}
                                    </div>
                                `}
                            </div>
                        </div>

                        ${this.licenseManager.hasFeature('apiAccess') ? `
                            <div class="row mt-4">
                                <div class="col-lg-6">
                                    <div class="card">
                                        <div class="card-header">
                                            <span>API Documentation</span>
                                        </div>
                                        <div class="card-body">
                                            <h6>Available Endpoints:</h6>
                                            <div class="code-snippet">
                                                <code>
// Generate TOTP token<br>
POST /api/v1/tokens/generate<br>
{<br>
&nbsp;&nbsp;"accountId": "account_123",<br>
&nbsp;&nbsp;"apiKey": "your_api_key_here"<br>
}
                                                </code>
                                            </div>
                                            <div class="mt-3">
                                                <a href="#" class="btn btn-outline-primary">
                                                    <i class="bi bi-book"></i>
                                                    View Full Documentation
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-lg-6">
                                    <div class="card">
                                        <div class="card-header">
                                            <span>Usage Statistics</span>
                                        </div>
                                        <div class="card-body">
                                            <div class="usage-stats">
                                                <div class="usage-stat">
                                                    <div class="stat-value">${this.apiKeys.reduce((acc, key) => acc + key.usageCount, 0)}</div>
                                                    <div class="stat-label">Total API Calls</div>
                                                </div>
                                                <div class="usage-stat">
                                                    <div class="stat-value">24</div>
                                                    <div class="stat-label">Calls Today</div>
                                                </div>
                                                <div class="usage-stat">
                                                    <div class="stat-value">99.8%</div>
                                                    <div class="stat-label">Uptime</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                </main>
            </div>
        `;
    }

    getSecurityLogsTemplate() {
        return `
            <div class="app-wrapper">
                <header class="app-header">
                    <div class="app-container">
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="#" data-route="dashboard" class="logo">
                                <i class="bi bi-shield-check"></i>
                                <span>AuthFlow Pro</span>
                            </a>
                            
                            <div class="d-flex align-items-center gap-4">
                                <nav class="d-flex gap-3 nav-menu">
                                    <a href="#" data-route="dashboard" class="nav-link">Dashboard</a>
                                    <a href="#" data-route="accounts" class="nav-link">Accounts</a>
                                    <a href="#" data-route="users" class="nav-link">Users</a>
                                    <a href="#" data-route="api-keys" class="nav-link">API Keys</a>
                                    <a href="#" data-route="security-logs" class="nav-link active">Security Logs</a>
                                </nav>
                                
                                <div class="dropdown">
                                    <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                        <span>${this.userData?.initials || 'JD'}</span>
                                    </div>
                                    <ul class="dropdown-menu dropdown-menu-dark">
                                        <li><a class="dropdown-item" href="#" data-route="settings"><i class="bi bi-gear"></i> Settings</a></li>
                                        <li><a class="dropdown-item text-danger" href="#" id="logoutBtn"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main class="app-container">
                    <div class="dashboard-section">
                        <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                            <h1 class="section-title">
                                <i class="bi bi-shield-check"></i>
                                Security Logs
                            </h1>
                            <div class="d-flex gap-2">
                                <button class="btn btn-outline-primary" onclick="authFlowApp.exportLogs()">
                                    <i class="bi bi-download"></i>
                                    Export Logs
                                </button>
                                <button class="btn btn-outline-danger" onclick="authFlowApp.clearLogs()">
                                    <i class="bi bi-trash"></i>
                                    Clear Logs
                                </button>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header">
                                <span>Security Events</span>
                                <span class="badge bg-primary">${this.securityLogs.length} events</span>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-dark table-hover">
                                        <thead>
                                            <tr>
                                                <th>Time</th>
                                                <th>User</th>
                                                <th>Event</th>
                                                <th>IP Address</th>
                                                <th>Platform</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${this.securityLogs.map(log => `
                                                <tr>
                                                    <td>
                                                        <div class="event-time">${log.time}</div>
                                                        <div class="event-date">${log.date}</div>
                                                    </td>
                                                    <td>
                                                        <div class="d-flex align-items-center gap-2">
                                                            <div class="user-avatar-xs">${log.userInitials}</div>
                                                            <span>${log.user}</span>
                                                        </div>
                                                    </td>
                                                    <td>
                                                        <div class="event-action">${log.action}</div>
                                                        <div class="event-details">${log.details}</div>
                                                    </td>
                                                    <td>${log.ip || '192.168.1.1'}</td>
                                                    <td>
                                                        <span class="platform-badge">${log.platform}</span>
                                                    </td>
                                                    <td>
                                                        <span class="badge ${log.status === 'Success' ? 'bg-success' : 'bg-danger'}">
                                                            <i class="bi bi-${log.status === 'Success' ? 'check' : 'x'}"></i>
                                                            ${log.status}
                                                        </span>
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="row mt-4">
                            <div class="col-lg-4">
                                <div class="card">
                                    <div class="card-header">
                                        <span>Security Summary</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="security-summary">
                                            <div class="summary-item">
                                                <div class="summary-value">${this.securityLogs.filter(log => log.status === 'Success').length}</div>
                                                <div class="summary-label">Successful Events</div>
                                            </div>
                                            <div class="summary-item">
                                                <div class="summary-value">${this.securityLogs.filter(log => log.status === 'Failed').length}</div>
                                                <div class="summary-label">Failed Events</div>
                                            </div>
                                            <div class="summary-item">
                                                <div class="summary-value">${new Set(this.securityLogs.map(log => log.user)).size}</div>
                                                <div class="summary-label">Active Users</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-lg-8">
                                <div class="card">
                                    <div class="card-header">
                                        <span>Recent Activity Timeline</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="activity-timeline">
                                            ${this.securityLogs.slice(0, 8).map(log => `
                                                <div class="timeline-item ${log.status === 'Success' ? 'success' : 'failed'}">
                                                    <div class="timeline-marker"></div>
                                                    <div class="timeline-content">
                                                        <div class="timeline-action">${log.action}</div>
                                                        <div class="timeline-meta">${log.user} • ${log.time}</div>
                                                    </div>
                                                </div>
                                            `).join('')}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        `;
    }

    getSettingsTemplate() {
        const daysUntilExpiry = this.licenseManager.getDaysUntilExpiry();
        const licenseStatus = this.licenseManager.getLicenseStatus();
        
        return `
            <div class="app-wrapper">
                <header class="app-header">
                    <div class="app-container">
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="#" data-route="dashboard" class="logo">
                                <i class="bi bi-shield-check"></i>
                                <span>AuthFlow Pro</span>
                            </a>
                            
                            <div class="d-flex align-items-center gap-4">
                                <nav class="d-flex gap-3 nav-menu">
                                    <a href="#" data-route="dashboard" class="nav-link">Dashboard</a>
                                    <a href="#" data-route="accounts" class="nav-link">Accounts</a>
                                    <a href="#" data-route="users" class="nav-link">Users</a>
                                    <a href="#" data-route="api-keys" class="nav-link">API Keys</a>
                                    <a href="#" data-route="security-logs" class="nav-link">Security Logs</a>
                                </nav>
                                
                                <div class="dropdown">
                                    <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                        <span>${this.userData?.initials || 'JD'}</span>
                                    </div>
                                    <ul class="dropdown-menu dropdown-menu-dark">
                                        <li><a class="dropdown-item" href="#" data-route="settings"><i class="bi bi-gear"></i> Settings</a></li>
                                        <li><a class="dropdown-item text-danger" href="#" id="logoutBtn"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main class="app-container">
                    <div class="dashboard-section">
                        <h1 class="section-title">
                            <i class="bi bi-gear"></i>
                            Settings
                        </h1>

                        <div class="row">
                            <div class="col-lg-8">
                                <div class="card">
                                    <div class="card-header">
                                        <span>Account Settings</span>
                                    </div>
                                    <div class="card-body">
                                        <form id="accountSettingsForm">
                                            <div class="row">
                                                <div class="col-md-6">
                                                    <div class="form-group">
                                                        <label class="form-label">Full Name</label>
                                                        <input type="text" class="form-control" value="${this.userData?.name || 'John Doe'}" required>
                                                    </div>
                                                </div>
                                                <div class="col-md-6">
                                                    <div class="form-group">
                                                        <label class="form-label">Email Address</label>
                                                        <input type="email" class="form-control" value="${this.userData?.email || 'john@agency.com'}" required>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="form-group">
                                                <label class="form-label">Company/Agency</label>
                                                <input type="text" class="form-control" value="Digital Marketing Agency" required>
                                            </div>
                                            <div class="form-group">
                                                <label class="form-label">Timezone</label>
                                                <select class="form-control">
                                                    <option>UTC-8 (Pacific Time)</option>
                                                    <option>UTC-5 (Eastern Time)</option>
                                                    <option>UTC+0 (GMT)</option>
                                                    <option>UTC+1 (Central European Time)</option>
                                                </select>
                                            </div>
                                            <button type="submit" class="btn btn-primary">
                                                <i class="bi bi-check"></i>
                                                Save Changes
                                            </button>
                                        </form>
                                    </div>
                                </div>

                                <div class="card mt-4">
                                    <div class="card-header">
                                        <span>Security Settings</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="security-settings">
                                            <div class="setting-item">
                                                <div class="setting-info">
                                                    <h6>Two-Factor Authentication</h6>
                                                    <p>Add an extra layer of security to your account</p>
                                                </div>
                                                <div class="setting-action">
                                                    <button class="btn btn-outline-primary">Enable 2FA</button>
                                                </div>
                                            </div>
                                            <div class="setting-item">
                                                <div class="setting-info">
                                                    <h6>Session Timeout</h6>
                                                    <p>Automatically log out after period of inactivity</p>
                                                </div>
                                                <div class="setting-action">
                                                    <select class="form-control">
                                                        <option>15 minutes</option>
                                                        <option>30 minutes</option>
                                                        <option selected>1 hour</option>
                                                        <option>4 hours</option>
                                                    </select>
                                                </div>
                                            </div>
                                            <div class="setting-item">
                                                <div class="setting-info">
                                                    <h6>Login Notifications</h6>
                                                    <p>Get notified of new login attempts</p>
                                                </div>
                                                <div class="setting-action">
                                                    <div class="form-check form-switch">
                                                        <input class="form-check-input" type="checkbox" checked>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="col-lg-4">
                                <div class="card">
                                    <div class="card-header">
                                        <span>License Information</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="license-details">
                                            <div class="license-plan">
                                                <h4>${this.licenseManager.getPlanName(this.licenseManager.plan)}</h4>
                                                <div class="price">$${this.licenseManager.getPlanPrice(this.licenseManager.plan)}<span>/month</span></div>
                                            </div>
                                            <div class="license-features">
                                                <div class="feature-item">
                                                    <i class="bi bi-check"></i>
                                                    <span>${this.licenseManager.getAccountLimit()} Accounts</span>
                                                </div>
                                                <div class="feature-item">
                                                    <i class="bi bi-check"></i>
                                                    <span>${this.licenseManager.getTeamLimit()} Team Members</span>
                                                </div>
                                                <div class="feature-item">
                                                    <i class="bi bi-${this.licenseManager.hasFeature('apiAccess') ? 'check' : 'x'}"></i>
                                                    <span>API Access</span>
                                                </div>
                                                <div class="feature-item">
                                                    <i class="bi bi-${this.licenseManager.hasFeature('prioritySupport') ? 'check' : 'x'}"></i>
                                                    <span>Priority Support</span>
                                                </div>
                                            </div>
                                            <div class="license-status">
                                                <div class="status-item">
                                                    <span>Status:</span>
                                                    <strong class="${licenseStatus !== 'active' ? 'text-warning' : 'text-success'}">
                                                        ${licenseStatus.charAt(0).toUpperCase() + licenseStatus.slice(1)}
                                                    </strong>
                                                </div>
                                                <div class="status-item">
                                                    <span>Expires in:</span>
                                                    <strong>${daysUntilExpiry} days</strong>
                                                </div>
                                            </div>
                                            <button class="btn btn-primary w-100 mt-3" onclick="authFlowApp.showPricingModal()">
                                                <i class="bi bi-arrow-repeat"></i>
                                                Manage Subscription
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div class="card mt-4">
                                    <div class="card-header">
                                        <span>Danger Zone</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="danger-zone">
                                            <div class="danger-item">
                                                <h6>Export All Data</h6>
                                                <p>Download all your accounts and settings</p>
                                                <button class="btn btn-outline-warning" onclick="authFlowApp.exportAllData()">
                                                    <i class="bi bi-download"></i>
                                                    Export Data
                                                </button>
                                            </div>
                                            <div class="danger-item">
                                                <h6>Delete Account</h6>
                                                <p>Permanently delete your account and all data</p>
                                                <button class="btn btn-outline-danger" onclick="authFlowApp.deleteAccount()">
                                                    <i class="bi bi-trash"></i>
                                                    Delete Account
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        `;
    }

    // ============ PAGE INITIALIZERS ============

    initializePageScripts(page) {
        switch (page) {
            case 'license':
                this.initLicensePage();
                break;
            case 'login':
                this.initLoginPage();
                break;
            case 'register':
                this.initRegisterPage();
                break;
            case 'dashboard':
                this.initDashboard();
                break;
            case 'accounts':
                this.initAccountsPage();
                break;
            case 'users':
                this.initUsersPage();
                break;
            case 'api-keys':
                this.initApiKeysPage();
                break;
            case 'security-logs':
                this.initSecurityLogsPage();
                break;
            case 'settings':
                this.initSettingsPage();
                break;
        }
    }

    initLicensePage() {
        const form = document.getElementById('licenseForm');
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const key = document.getElementById('licenseKey').value.trim();
                const isValid = await this.licenseManager.validateLicense(key);
                
                if (isValid) {
                    this.navigate('login');
                } else {
                    this.showLicenseError('Invalid license key. Please check and try again.');
                }
            });
        }
    }

    initLoginPage() {
        const form = document.getElementById('loginForm');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.login();
            });
        }

        document.getElementById('loginEmail').value = 'demo@agency.com';
        document.getElementById('loginPassword').value = 'password';
    }

    initRegisterPage() {
        const form = document.getElementById('registerForm');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.register();
            });
        }
    }

    initDashboard() {
        this.updateActiveNav();
    }

    initAccountsPage() {
        this.updateActiveNav();
        
        const addAccountBtn = document.getElementById('addAccountBtn') || 
                             document.getElementById('addFirstAccountBtn');
        if (addAccountBtn) {
            addAccountBtn.addEventListener('click', () => {
                this.showAddAccountForm();
            });
        }
    }

    initUsersPage() {
        this.updateActiveNav();
        
        const inviteUserBtn = document.getElementById('inviteUserBtn');
        if (inviteUserBtn) {
            inviteUserBtn.addEventListener('click', () => {
                this.showInviteUserForm();
            });
        }
    }

    initApiKeysPage() {
        this.updateActiveNav();
        
        const generateBtn = document.getElementById('generateApiKeyBtn') || 
                           document.getElementById('generateFirstApiKeyBtn');
        if (generateBtn) {
            generateBtn.addEventListener('click', () => {
                this.showGenerateApiKeyForm();
            });
        }
    }

    initSecurityLogsPage() {
        this.updateActiveNav();
    }

    initSettingsPage() {
        this.updateActiveNav();
    }

    // ============ BUSINESS LOGIC ============

    login() {
        this.isAuthenticated = true;
        this.userData = {
            name: 'John Doe',
            email: 'john@agency.com',
            initials: 'JD',
            company: 'Digital Marketing Agency'
        };
        
        localStorage.setItem('authflow-authenticated', 'true');
        localStorage.setItem('authflow-user', JSON.stringify(this.userData));
        
        this.navigate('dashboard');
    }

    register() {
        this.login();
    }

    logout() {
        this.isAuthenticated = false;
        this.userData = null;
        localStorage.removeItem('authflow-authenticated');
        localStorage.removeItem('authflow-user');
        this.navigate('login');
    }

    loadData() {
        // Demo accounts
        this.accounts = [
            { 
                id: '1', 
                platform: 'x', 
                icon: 'twitter-x', 
                name: 'Marketing Agency', 
                username: '@marketingpro',
                secret: 'JBSWY3DPEHPK3PXP',
                issuer: 'Twitter'
            },
            { 
                id: '2', 
                platform: 'fb', 
                icon: 'facebook', 
                name: 'Brand Page', 
                username: 'facebook.com/brand',
                secret: 'JBSWY3DPEHPK3PXP',
                issuer: 'Facebook'
            },
            { 
                id: '3', 
                platform: 'google', 
                icon: 'google', 
                name: 'Google Workspace', 
                username: 'admin@agency.com',
                secret: 'JBSWY3DPEHPK3PXP',
                issuer: 'Google'
            }
        ];

        // Initialize real TOTP for each account
        this.accounts.forEach(account => {
            this.totpEngine.addAccount(
                account.id, 
                account.name, 
                account.secret, 
                account.issuer
            );
        });

        // Team members
        this.teamMembers = [
            { 
                id: '1', 
                name: 'John Doe', 
                email: 'john@agency.com', 
                role: 'admin', 
                initials: 'JD', 
                status: 'online',
                lastActive: '2 hours ago'
            },
            { 
                id: '2', 
                name: 'Alice Smith', 
                email: 'alice@agency.com', 
                role: 'manager', 
                initials: 'AS', 
                status: 'online',
                lastActive: '30 minutes ago'
            },
            { 
                id: '3', 
                name: 'Bob Johnson', 
                email: 'bob@agency.com', 
                role: 'user', 
                initials: 'BJ', 
                status: 'offline',
                lastActive: '1 day ago'
            }
        ];

        // API Keys
        this.apiKeys = [
            {
                id: '1',
                name: 'Production API',
                key: 'authflow_sk_live_1234567890abcdef',
                created: '2024-01-15',
                lastUsed: '2024-01-20',
                active: true,
                usageCount: 142
            },
            {
                id: '2',
                name: 'Development API',
                key: 'authflow_sk_test_abcdef1234567890',
                created: '2024-01-10',
                lastUsed: null,
                active: false,
                usageCount: 0
            }
        ];

        // Security logs
        this.securityLogs = [
            { 
                time: '10:23 AM', 
                date: '2024-01-20',
                user: 'John Doe', 
                userInitials: 'JD',
                action: 'Generated 2FA code', 
                details: 'Facebook account',
                platform: 'Facebook', 
                status: 'Success',
                icon: 'shield-check'
            },
            { 
                time: '09:45 AM', 
                date: '2024-01-20',
                user: 'Alice Smith', 
                userInitials: 'AS',
                action: 'Added new account', 
                details: 'Twitter account',
                platform: 'Instagram', 
                status: 'Success',
                icon: 'person-plus'
            },
            { 
                time: '09:30 AM', 
                date: '2024-01-20',
                user: 'Bob Johnson', 
                userInitials: 'BJ',
                action: 'Failed login attempt', 
                details: 'Invalid password',
                platform: 'Web', 
                status: 'Failed',
                icon: 'exclamation-triangle'
            },
            { 
                time: 'Yesterday', 
                date: '2024-01-19',
                user: 'John Doe', 
                userInitials: 'JD',
                action: 'Exported tokens', 
                details: 'All accounts',
                platform: 'Web', 
                status: 'Success',
                icon: 'download'
            }
        ];
    }

    updateActiveNav() {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('data-route') === this.currentPage) {
                link.classList.add('active');
            }
        });
    }

    showLicenseError(message) {
        const errorElement = document.getElementById('licenseError');
        const errorText = document.getElementById('licenseErrorText');
        if (errorElement && errorText) {
            errorText.textContent = message;
            errorElement.style.display = 'flex';
        }
    }

    showAddAccountForm() {
        const name = prompt('Enter account name:');
        const secret = prompt('Enter TOTP secret (base32):');
        
        if (name && secret) {
            const newAccount = {
                id: Date.now().toString(),
                platform: 'custom',
                icon: 'person-badge',
                name: name,
                username: 'Manual Entry',
                secret: secret,
                issuer: 'Custom'
            };
            
            this.accounts.push(newAccount);
            this.totpEngine.addAccount(newAccount.id, name, secret, 'Custom');
            this.navigate('accounts');
        }
    }

    removeAccount(accountId) {
        if (confirm('Are you sure you want to remove this account?')) {
            this.accounts = this.accounts.filter(acc => acc.id !== accountId);
            this.totpEngine.removeAccount(accountId);
            this.navigate('accounts');
        }
    }

    copyToken(accountId) {
        const tokenElement = document.getElementById(`token-${accountId}`);
        if (tokenElement) {
            const token = tokenElement.textContent.replace(/\s/g, '');
            navigator.clipboard.writeText(token).then(() => {
                const originalText = tokenElement.textContent;
                tokenElement.textContent = 'Copied!';
                setTimeout(() => {
                    tokenElement.textContent = originalText;
                }, 1000);
            });
        }
    }

    exportAllTokens() {
        const tokens = this.totpEngine.getAllAccounts().map(account => {
            const token = this.totpEngine.generateTOTP(account.secret);
            return `${account.name}: ${token}`;
        }).join('\n');
        
        const blob = new Blob([tokens], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'authflow-tokens.txt';
        a.click();
        URL.revokeObjectURL(url);
    }

    // New methods for enhanced functionality
    showPricingModal() {
        const modal = new bootstrap.Modal(document.getElementById('globalPricingModal'));
        modal.show();
    }

    selectPlan(plan) {
        alert(`Selected ${plan} plan for $${this.licenseManager.getPlanPrice(plan)}/month`);
    }

    showTerms() {
        alert('Terms of Service would be displayed here');
    }

    showPrivacy() {
        alert('Privacy Policy would be displayed here');
    }

    showInviteUserForm() {
        const email = prompt('Enter email address to invite:');
        const role = prompt('Enter role (user/manager/admin):', 'user');
        
        if (email && role) {
            const newUser = {
                id: Date.now().toString(),
                name: email.split('@')[0],
                email: email,
                role: role,
                initials: email.substring(0, 2).toUpperCase(),
                status: 'invited',
                lastActive: 'Never'
            };
            
            this.teamMembers.push(newUser);
            this.navigate('users');
        }
    }

    editUser(userId) {
        alert(`Edit user ${userId}`);
    }

    removeUser(userId) {
        if (confirm('Are you sure you want to remove this user?')) {
            this.teamMembers = this.teamMembers.filter(user => user.id !== userId);
            this.navigate('users');
        }
    }

    showGenerateApiKeyForm() {
        const name = prompt('Enter API key name:');
        if (name) {
            const newKey = {
                id: Date.now().toString(),
                name: name,
                key: 'authflow_sk_' + Math.random().toString(36).substr(2, 32),
                created: new Date().toISOString().split('T')[0],
                lastUsed: null,
                active: true,
                usageCount: 0
            };
            
            this.apiKeys.push(newKey);
            this.navigate('api-keys');
        }
    }

    copyApiKey(keyId) {
        const key = this.apiKeys.find(k => k.id === keyId);
        if (key) {
            navigator.clipboard.writeText(key.key).then(() => {
                alert('API key copied to clipboard!');
            });
        }
    }

    regenerateApiKey(keyId) {
        if (confirm('Are you sure you want to regenerate this API key? The old key will be invalidated.')) {
            const key = this.apiKeys.find(k => k.id === keyId);
            if (key) {
                key.key = 'authflow_sk_' + Math.random().toString(36).substr(2, 32);
                key.lastUsed = null;
                this.navigate('api-keys');
            }
        }
    }

    revokeApiKey(keyId) {
        if (confirm('Are you sure you want to revoke this API key?')) {
            this.apiKeys = this.apiKeys.filter(k => k.id !== keyId);
            this.navigate('api-keys');
        }
    }

    exportLogs() {
        const logs = this.securityLogs.map(log => 
            `${log.date} ${log.time} | ${log.user} | ${log.action} | ${log.status}`
        ).join('\n');
        
        const blob = new Blob([logs], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'authflow-security-logs.txt';
        a.click();
        URL.revokeObjectURL(url);
    }

    clearLogs() {
        if (confirm('Are you sure you want to clear all security logs? This action cannot be undone.')) {
            this.securityLogs = [];
            this.navigate('security-logs');
        }
    }

    exportAllData() {
        const data = {
            user: this.userData,
            accounts: this.accounts,
            teamMembers: this.teamMembers,
            apiKeys: this.apiKeys,
            settings: this.settings
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'authflow-backup.json';
        a.click();
        URL.revokeObjectURL(url);
    }

    deleteAccount() {
        if (confirm('Are you absolutely sure? This will permanently delete your account and all data. This action cannot be undone.')) {
            if (confirm('Type "DELETE" to confirm:')) {
                this.logout();
                alert('Account scheduled for deletion.');
            }
        }
    }
}

// ============ AUTHFLOW PRO - COMPLETE SPA PWA ============
// Enhanced with Bulk Import, Cookie Auth, Advanced Filtering & Performance Optimizations

// ============ ENCRYPTION SERVICE ============
class EncryptionService {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.key = null;
    }

    async generateKey() {
        if (!this.key) {
            this.key = await crypto.subtle.generateKey(
                { name: this.algorithm, length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
        }
        return this.key;
    }

    async encrypt(data) {
        const key = await this.generateKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(data);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: this.algorithm, iv: iv },
            key,
            encoded
        );

        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encrypted), iv.length);
        
        return btoa(String.fromCharCode(...result));
    }

    async decrypt(encryptedData) {
        try {
            const key = await this.generateKey();
            const data = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            const iv = data.slice(0, 12);
            const encrypted = data.slice(12);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: this.algorithm, iv: iv },
                key,
                encrypted
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }
}

// ============ BULK IMPORT MANAGER ============
class BulkImportManager {
    constructor() {
        this.encryption = new EncryptionService();
        this.batchSize = 50;
        this.maxFileSize = 10 * 1024 * 1024; // 10MB
    }

    validateCSV(content) {
        const lines = content.split('\n').filter(line => line.trim());
        if (lines.length < 2) return { valid: false, error: 'File is empty or has no data' };
        
        const headers = lines[0].toLowerCase().split(',').map(h => h.trim());
        const required = ['name', 'secret', 'platform'];
        const missing = required.filter(field => !headers.includes(field));
        
        if (missing.length > 0) {
            return { valid: false, error: `Missing required fields: ${missing.join(', ')}` };
        }
        
        return { valid: true, headers };
    }

    validateJSON(content) {
        try {
            const data = JSON.parse(content);
            if (!Array.isArray(data)) {
                return { valid: false, error: 'JSON must be an array of accounts' };
            }
            
            if (data.length === 0) {
                return { valid: false, error: 'No accounts found in JSON' };
            }

            const required = ['name', 'secret', 'platform'];
            const invalidAccounts = data.filter(account => 
                !required.every(field => account[field])
            );

            if (invalidAccounts.length > 0) {
                return { valid: false, error: `${invalidAccounts.length} accounts missing required fields` };
            }

            return { valid: true, data };
        } catch (error) {
            return { valid: false, error: 'Invalid JSON format' };
        }
    }

    parseCSV(content, headers) {
        const lines = content.split('\n').filter(line => line.trim());
        const headerMap = lines[0].split(',').map(h => h.trim().toLowerCase());
        
        return lines.slice(1).map((line, index) => {
            const values = this.parseCSVLine(line);
            const account = {};
            
            headerMap.forEach((header, i) => {
                if (values[i]) {
                    account[header] = values[i].trim();
                }
            });

            return {
                id: `imported_${Date.now()}_${index}`,
                name: account.name || 'Imported Account',
                secret: account.secret,
                platform: account.platform || 'custom',
                issuer: account.issuer || account.platform || 'Unknown',
                type: account.type || 'TOTP',
                group: account.group || 'default',
                username: account.username || '',
                cookies: account.cookies ? JSON.parse(account.cookies) : null,
                icon: this.getPlatformIcon(account.platform),
                added: new Date(),
                lastUsed: null
            };
        }).filter(account => account.secret); // Remove accounts without secrets
    }

    parseCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                result.push(current);
                current = '';
            } else {
                current += char;
            }
        }
        
        result.push(current);
        return result;
    }

    getPlatformIcon(platform) {
        const icons = {
            'reddit': 'reddit',
            'twitter': 'twitter-x',
            'facebook': 'facebook',
            'google': 'google',
            'instagram': 'instagram',
            'linkedin': 'linkedin',
            'github': 'github',
            'microsoft': 'microsoft',
            'apple': 'apple',
            'amazon': 'amazon'
        };
        return icons[platform?.toLowerCase()] || 'person-badge';
    }

    async processFile(file) {
        return new Promise((resolve, reject) => {
            if (file.size > this.maxFileSize) {
                reject(new Error('File size too large. Maximum 10MB allowed.'));
                return;
            }

            const reader = new FileReader();
            
            reader.onload = async (e) => {
                try {
                    const content = e.target.result;
                    let accounts = [];
                    let validation;

                    if (file.type === 'application/json' || file.name.endsWith('.json')) {
                        validation = this.validateJSON(content);
                        if (validation.valid) {
                            accounts = validation.data.map((account, index) => ({
                                id: `imported_${Date.now()}_${index}`,
                                name: account.name,
                                secret: account.secret,
                                platform: account.platform || 'custom',
                                issuer: account.issuer || account.platform || 'Unknown',
                                type: account.type || 'TOTP',
                                group: account.group || 'default',
                                username: account.username || '',
                                cookies: account.cookies || null,
                                icon: this.getPlatformIcon(account.platform),
                                added: new Date(),
                                lastUsed: null
                            }));
                        }
                    } else {
                        validation = this.validateCSV(content);
                        if (validation.valid) {
                            accounts = this.parseCSV(content, validation.headers);
                        }
                    }

                    if (!validation.valid) {
                        reject(new Error(validation.error));
                        return;
                    }

                    // Encrypt cookies if present
                    for (let account of accounts) {
                        if (account.cookies && typeof account.cookies === 'object') {
                            account.encryptedCookies = await this.encryption.encrypt(
                                JSON.stringify(account.cookies)
                            );
                            delete account.cookies;
                        }
                    }

                    resolve(accounts);
                } catch (error) {
                    reject(error);
                }
            };

            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    async processInBatches(accounts, progressCallback) {
        const results = {
            success: [],
            failed: [],
            total: accounts.length
        };

        for (let i = 0; i < accounts.length; i += this.batchSize) {
            const batch = accounts.slice(i, i + this.batchSize);
            
            for (const account of batch) {
                try {
                    // Validate TOTP secret format (basic validation)
                    if (account.type === 'TOTP' && !this.isValidSecret(account.secret)) {
                        throw new Error('Invalid TOTP secret format');
                    }

                    results.success.push(account);
                } catch (error) {
                    results.failed.push({
                        account,
                        error: error.message
                    });
                }
            }

            if (progressCallback) {
                progressCallback(i + batch.length, accounts.length);
            }

            // Small delay to prevent UI blocking
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        return results;
    }

    isValidSecret(secret) {
        // Basic Base32 validation (should only contain A-Z2-7 and = for padding)
        return /^[A-Z2-7]+=*$/.test(secret.toUpperCase());
    }

    getImportTemplate(format) {
        if (format === 'json') {
            return JSON.stringify([
                {
                    "name": "Account Name",
                    "secret": "JBSWY3DPEHPK3PXP",
                    "platform": "google",
                    "issuer": "Google",
                    "type": "TOTP",
                    "group": "work",
                    "username": "user@example.com"
                },
                {
                    "name": "Cookie Account",
                    "secret": "",
                    "platform": "reddit",
                    "type": "Cookie",
                    "group": "personal",
                    "username": "reddit_user",
                    "cookies": [
                        {
                            "name": "session",
                            "value": "encrypted_cookie_value",
                            "domain": ".reddit.com",
                            "path": "/",
                            "expires": "2024-12-31T23:59:59.000Z",
                            "secure": true,
                            "httponly": true
                        }
                    ]
                }
            ], null, 2);
        } else {
            return `name,secret,platform,issuer,type,group,username
Google Account,JBSWY3DPEHPK3PXP,google,Google,TOTP,work,user@example.com
Reddit Account,,reddit,Reddit,Cookie,personal,reddit_user`;
        }
    }
}

// ============ COOKIE MANAGER ============
class CookieManager {
    constructor() {
        this.encryption = new EncryptionService();
        this.platforms = {
            'reddit': { domains: ['.reddit.com', 'www.reddit.com'], icon: 'reddit' },
            'twitter': { domains: ['.twitter.com', '.x.com'], icon: 'twitter-x' },
            'facebook': { domains: ['.facebook.com'], icon: 'facebook' },
            'google': { domains: ['.google.com'], icon: 'google' },
            'instagram': { domains: ['.instagram.com'], icon: 'instagram' },
            'linkedin': { domains: ['.linkedin.com'], icon: 'linkedin' }
        };
    }

    async encryptCookies(cookies) {
        const encrypted = await this.encryption.encrypt(JSON.stringify(cookies));
        return encrypted;
    }

    async decryptCookies(encryptedData) {
        try {
            const decrypted = await this.encryption.decrypt(encryptedData);
            return decrypted ? JSON.parse(decrypted) : null;
        } catch (error) {
            console.error('Failed to decrypt cookies:', error);
            return null;
        }
    }

    validateCookie(cookie) {
        const required = ['name', 'value', 'domain'];
        const missing = required.filter(field => !cookie[field]);
        
        if (missing.length > 0) {
            return { valid: false, error: `Missing required fields: ${missing.join(', ')}` };
        }

        if (cookie.expires && isNaN(new Date(cookie.expires).getTime())) {
            return { valid: false, error: 'Invalid expiration date' };
        }

        return { valid: true };
    }

    getCookieExpiryStatus(expires) {
        if (!expires) return 'session';
        
        const expiryDate = new Date(expires);
        const now = new Date();
        const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
        
        if (daysUntilExpiry < 0) return 'expired';
        if (daysUntilExpiry < 7) return 'expiring';
        return 'valid';
    }

    formatCookieForExport(cookies) {
        return cookies.map(cookie => ({
            ...cookie,
            expires: cookie.expires ? new Date(cookie.expires).toISOString() : null,
            status: this.getCookieExpiryStatus(cookie.expires)
        }));
    }

    async copyCookiesToClipboard(cookies) {
        try {
            const cookieString = cookies.map(c => 
                `${c.name}=${c.value}; Domain=${c.domain}; Path=${c.path || '/'}; ${
                    c.expires ? `Expires=${new Date(c.expires).toUTCString()}; ` : ''
                }${c.secure ? 'Secure; ' : ''}${c.httponly ? 'HttpOnly; ' : ''}`
            ).join('\n');
            
            await navigator.clipboard.writeText(cookieString);
            return true;
        } catch (error) {
            console.error('Failed to copy cookies:', error);
            return false;
        }
    }
}

// ============ FILTER MANAGER ============
class FilterManager {
    constructor() {
        this.filters = {
            search: '',
            group: 'all',
            platform: 'all',
            type: 'all',
            sortBy: 'name',
            sortOrder: 'asc'
        };
    }

    applyFilters(accounts, filters) {
        this.filters = { ...this.filters, ...filters };
        
        return accounts.filter(account => {
            // Search filter
            if (this.filters.search) {
                const searchTerm = this.filters.search.toLowerCase();
                const searchable = [
                    account.name,
                    account.username,
                    account.issuer,
                    account.platform,
                    account.group
                ].join(' ').toLowerCase();
                
                if (!searchable.includes(searchTerm)) return false;
            }

            // Group filter
            if (this.filters.group !== 'all' && account.group !== this.filters.group) {
                return false;
            }

            // Platform filter
            if (this.filters.platform !== 'all' && account.platform !== this.filters.platform) {
                return false;
            }

            // Type filter
            if (this.filters.type !== 'all' && account.type !== this.filters.type) {
                return false;
            }

            return true;
        }).sort((a, b) => {
            // Sorting
            let aValue = a[this.filters.sortBy] || '';
            let bValue = b[this.filters.sortBy] || '';
            
            if (this.filters.sortBy === 'added') {
                aValue = new Date(aValue);
                bValue = new Date(bValue);
            }
            
            if (this.filters.sortOrder === 'asc') {
                return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
            } else {
                return aValue > bValue ? -1 : aValue < bValue ? 1 : 0;
            }
        });
    }

    getAvailableGroups(accounts) {
        const groups = new Set(accounts.map(acc => acc.group).filter(Boolean));
        return ['all', ...Array.from(groups).sort()];
    }

    getAvailablePlatforms(accounts) {
        const platforms = new Set(accounts.map(acc => acc.platform).filter(Boolean));
        return ['all', ...Array.from(platforms).sort()];
    }

    getAvailableTypes(accounts) {
        const types = new Set(accounts.map(acc => acc.type).filter(Boolean));
        return ['all', ...Array.from(types).sort()];
    }

    getFilterStats(accounts) {
        const filtered = this.applyFilters(accounts, this.filters);
        return {
            total: accounts.length,
            filtered: filtered.length,
            groups: this.getAvailableGroups(accounts).length - 1,
            platforms: this.getAvailablePlatforms(accounts).length - 1
        };
    }
}

// ============ LAZY TOKEN ENGINE ============
class LazyTOTPEngine extends RealTOTPEngine {
    constructor() {
        super();
        this.visibleAccounts = new Set();
        this.updateInterval = 1000;
        this.isRunning = false;
        this.lastUpdate = Date.now();
    }

    setVisibleAccounts(accountIds) {
        this.visibleAccounts = new Set(accountIds);
        
        // Start/stop updates based on visibility
        if (this.visibleAccounts.size > 0 && !this.isRunning) {
            this.startLazyUpdates();
        } else if (this.visibleAccounts.size === 0 && this.isRunning) {
            this.stopLazyUpdates();
        }
    }

    startLazyUpdates() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        const update = () => {
            if (!this.isRunning) return;
            
            const now = Date.now();
            const elapsed = now - this.lastUpdate;
            
            if (elapsed >= this.updateInterval) {
                this.updateVisibleTokens();
                this.lastUpdate = now;
            }
            
            requestAnimationFrame(update);
        };
        
        requestAnimationFrame(update);
    }

    stopLazyUpdates() {
        this.isRunning = false;
    }

    updateVisibleTokens() {
        this.visibleAccounts.forEach(accountId => {
            const account = this.accounts.get(accountId);
            if (!account) return;

            const token = this.generateTOTP(account.secret);
            const timeLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
            
            window.dispatchEvent(new CustomEvent('realTokenUpdate', {
                detail: {
                    accountId,
                    token: this.formatToken(token),
                    timeLeft,
                    valid: timeLeft > 3,
                    rawToken: token
                }
            }));
        });
    }

    // Override to use lazy updates
    startRealTimeUpdates(accountId) {
        // Don't start individual intervals - handled by lazy updates
    }

    addAccount(accountId, name, secret, issuer = 'Unknown', type = 'TOTP', group = 'default') {
        const account = {
            id: accountId,
            name,
            secret,
            issuer,
            type,
            group,
            backupCodes: this.generateBackupCodes(),
            added: new Date(),
            lastUsed: null
        };

        this.accounts.set(accountId, account);
        return account;
    }
}

// ============ ENHANCED AUTHFLOW SPA ============
class EnhancedAuthFlowSPA extends AuthFlowSPA {
    constructor() {
        super();
        this.bulkImportManager = new BulkImportManager();
        this.cookieManager = new CookieManager();
        this.filterManager = new FilterManager();
        this.totpEngine = new LazyTOTPEngine(); // Replace with lazy engine
        
        // Enhanced data structures
        this.accountGroups = new Map();
        this.cookieAccounts = new Map();
        
        this.initEnhancedFeatures();
    }

    initEnhancedFeatures() {
        this.setupBulkImport();
        this.setupEnhancedFiltering();
        this.setupCookieManagement();
    }

    // ============ BULK IMPORT SYSTEM ============

    setupBulkImport() {
        // This will be called when the accounts page is rendered
    }

    showBulkImportModal() {
        const modalHtml = `
            <div class="modal fade" id="bulkImportModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-upload"></i>
                                Bulk Import Accounts
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="import-options">
                                <div class="option-card active" data-format="json">
                                    <i class="bi bi-file-code"></i>
                                    <h6>JSON Import</h6>
                                    <p>Import from JSON format with full account data</p>
                                </div>
                                <div class="option-card" data-format="csv">
                                    <i class="bi bi-file-text"></i>
                                    <h6>CSV Import</h6>
                                    <p>Import from CSV with basic account information</p>
                                </div>
                            </div>

                            <div class="import-instructions">
                                <h6><i class="bi bi-info-circle"></i> Supported Format</h6>
                                <div class="code-preview" id="formatPreview">
                                    <!-- Dynamic content -->
                                </div>
                                <button class="btn btn-sm btn-outline-primary mt-2" onclick="authFlowApp.downloadTemplate()">
                                    <i class="bi bi-download"></i>
                                    Download Template
                                </button>
                            </div>

                            <div class="file-upload-area mt-4">
                                <input type="file" id="importFile" accept=".json,.csv" class="d-none">
                                <div class="upload-placeholder" id="uploadPlaceholder">
                                    <i class="bi bi-cloud-upload"></i>
                                    <p>Choose file or drag & drop here</p>
                                    <small>Supports JSON and CSV files (max 10MB)</small>
                                </div>
                                <div class="upload-preview" id="uploadPreview" style="display: none;">
                                    <div class="file-info">
                                        <i class="bi bi-file-text"></i>
                                        <div>
                                            <div class="file-name" id="fileName"></div>
                                            <div class="file-size" id="fileSize"></div>
                                        </div>
                                    </div>
                                    <button class="btn btn-sm btn-outline-danger" onclick="authFlowApp.clearFile()">
                                        <i class="bi bi-x"></i>
                                    </button>
                                </div>
                            </div>

                            <div class="import-options mt-4">
                                <div class="form-group">
                                    <label class="form-label">Default Group</label>
                                    <input type="text" class="form-control" id="defaultGroup" placeholder="work, personal, client1, etc.">
                                </div>
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="validateSecrets" checked>
                                    <label class="form-check-label">Validate TOTP secrets during import</label>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="startImportBtn" disabled>
                                <i class="bi bi-play-circle"></i>
                                Start Import
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Add modal to DOM if not exists
        if (!document.getElementById('bulkImportModal')) {
            document.body.insertAdjacentHTML('beforeend', modalHtml);
        }

        const modal = new bootstrap.Modal(document.getElementById('bulkImportModal'));
        this.setupImportModalEvents();
        modal.show();
    }

    setupImportModalEvents() {
        // Format selection
        document.querySelectorAll('.option-card').forEach(card => {
            card.addEventListener('click', () => {
                document.querySelectorAll('.option-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');
                this.updateFormatPreview(card.dataset.format);
            });
        });

        // File upload
        const fileInput = document.getElementById('importFile');
        const uploadPlaceholder = document.getElementById('uploadPlaceholder');
        const uploadPreview = document.getElementById('uploadPreview');

        uploadPlaceholder.addEventListener('click', () => fileInput.click());
        uploadPlaceholder.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadPlaceholder.classList.add('dragover');
        });
        uploadPlaceholder.addEventListener('dragleave', () => {
            uploadPlaceholder.classList.remove('dragover');
        });
        uploadPlaceholder.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadPlaceholder.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelect(files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFileSelect(e.target.files[0]);
            }
        });

        // Start import button
        document.getElementById('startImportBtn').addEventListener('click', () => {
            this.processBulkImport();
        });

        // Initial format preview
        this.updateFormatPreview('json');
    }

    updateFormatPreview(format) {
        const template = this.bulkImportManager.getImportTemplate(format);
        const preview = document.getElementById('formatPreview');
        
        if (format === 'json') {
            preview.innerHTML = `<pre><code>${template}</code></pre>`;
        } else {
            preview.textContent = template;
        }
    }

    handleFileSelect(file) {
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');
        const uploadPlaceholder = document.getElementById('uploadPlaceholder');
        const uploadPreview = document.getElementById('uploadPreview');
        const startImportBtn = document.getElementById('startImportBtn');

        fileName.textContent = file.name;
        fileSize.textContent = this.formatFileSize(file.size);
        
        uploadPlaceholder.style.display = 'none';
        uploadPreview.style.display = 'flex';
        startImportBtn.disabled = false;
    }

    clearFile() {
        const fileInput = document.getElementById('importFile');
        const uploadPlaceholder = document.getElementById('uploadPlaceholder');
        const uploadPreview = document.getElementById('uploadPreview');
        const startImportBtn = document.getElementById('startImportBtn');

        fileInput.value = '';
        uploadPlaceholder.style.display = 'flex';
        uploadPreview.style.display = 'none';
        startImportBtn.disabled = true;
    }

    async processBulkImport() {
        const fileInput = document.getElementById('importFile');
        const file = fileInput.files[0];
        const defaultGroup = document.getElementById('defaultGroup').value || 'imported';
        const validateSecrets = document.getElementById('validateSecrets').checked;

        if (!file) return;

        const modal = bootstrap.Modal.getInstance(document.getElementById('bulkImportModal'));
        modal.hide();

        // Show progress modal
        this.showImportProgress();

        try {
            // Parse file
            const accounts = await this.bulkImportManager.processFile(file);
            
            // Apply default group
            accounts.forEach(account => {
                if (!account.group || account.group === 'default') {
                    account.group = defaultGroup;
                }
            });

            // Process in batches
            const results = await this.bulkImportManager.processInBatches(
                accounts, 
                (processed, total) => {
                    this.updateImportProgress(processed, total);
                }
            );

            // Add successful accounts
            for (const account of results.success) {
                this.totpEngine.addAccount(
                    account.id,
                    account.name,
                    account.secret,
                    account.issuer,
                    account.type,
                    account.group
                );

                if (account.type === 'Cookie' && account.encryptedCookies) {
                    this.cookieAccounts.set(account.id, {
                        encryptedData: account.encryptedCookies,
                        platform: account.platform
                    });
                }
            }

            // Show results
            this.showImportResults(results);

        } catch (error) {
            this.showImportError(error.message);
        }
    }

    showImportProgress() {
        const progressHtml = `
            <div class="modal fade" id="importProgressModal" tabindex="-1" data-bs-backdrop="static">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-arrow-repeat spinner"></i>
                                Importing Accounts
                            </h5>
                        </div>
                        <div class="modal-body">
                            <div class="progress mb-3">
                                <div class="progress-bar" id="importProgressBar" style="width: 0%"></div>
                            </div>
                            <div class="text-center">
                                <div id="importStatus">Processing...</div>
                                <small class="text-muted" id="importCount">0/0 accounts</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        if (!document.getElementById('importProgressModal')) {
            document.body.insertAdjacentHTML('beforeend', progressHtml);
        }

        const modal = new bootstrap.Modal(document.getElementById('importProgressModal'));
        modal.show();
    }

    updateImportProgress(processed, total) {
        const progressBar = document.getElementById('importProgressBar');
        const importStatus = document.getElementById('importStatus');
        const importCount = document.getElementById('importCount');

        if (progressBar) {
            const percent = Math.round((processed / total) * 100);
            progressBar.style.width = `${percent}%`;
            importStatus.textContent = `Processed ${processed} of ${total} accounts`;
            importCount.textContent = `${processed}/${total} accounts`;
        }
    }

    showImportResults(results) {
        const progressModal = bootstrap.Modal.getInstance(document.getElementById('importProgressModal'));
        if (progressModal) progressModal.hide();

        const resultsHtml = `
            <div class="modal fade" id="importResultsModal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-check-circle text-success"></i>
                                Import Complete
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="import-summary">
                                <div class="summary-item success">
                                    <i class="bi bi-check-circle"></i>
                                    <div>
                                        <strong>${results.success.length}</strong>
                                        <span>Successful</span>
                                    </div>
                                </div>
                                <div class="summary-item failed">
                                    <i class="bi bi-x-circle"></i>
                                    <div>
                                        <strong>${results.failed.length}</strong>
                                        <span>Failed</span>
                                    </div>
                                </div>
                            </div>

                            ${results.failed.length > 0 ? `
                                <div class="failed-accounts mt-3">
                                    <h6>Failed Imports:</h6>
                                    <div class="failed-list">
                                        ${results.failed.slice(0, 5).map(failed => `
                                            <div class="failed-item">
                                                <div class="failed-name">${failed.account.name}</div>
                                                <div class="failed-error">${failed.error}</div>
                                            </div>
                                        `).join('')}
                                        ${results.failed.length > 5 ? `
                                            <div class="text-muted">... and ${results.failed.length - 5} more</div>
                                        ` : ''}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            ${results.failed.length > 0 ? `
                                <button type="button" class="btn btn-outline-primary" onclick="authFlowApp.downloadFailedReport(${JSON.stringify(results.failed)})">
                                    <i class="bi bi-download"></i>
                                    Download Failed Report
                                </button>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', resultsHtml);
        const modal = new bootstrap.Modal(document.getElementById('importResultsModal'));
        modal.show();

        // Refresh accounts page
        this.navigate('accounts');
    }

    // ============ ENHANCED ACCOUNT MANAGEMENT ============

    getEnhancedAccountsTemplate() {
        const stats = this.filterManager.getFilterStats(this.accounts);
        const groups = this.filterManager.getAvailableGroups(this.accounts);
        const platforms = this.filterManager.getAvailablePlatforms(this.accounts);
        const types = this.filterManager.getAvailableTypes(this.accounts);

        return `
            <div class="app-wrapper">
                <header class="app-header">
                    <div class="app-container">
                        <div class="d-flex justify-content-between align-items-center">
                            <a href="#" data-route="dashboard" class="logo">
                                <i class="bi bi-shield-check"></i>
                                <span>AuthFlow Pro</span>
                            </a>
                            
                            <div class="d-flex align-items-center gap-4">
                                <nav class="d-flex gap-3 nav-menu">
                                    <a href="#" data-route="dashboard" class="nav-link">Dashboard</a>
                                    <a href="#" data-route="accounts" class="nav-link">Accounts</a>
                                    <a href="#" data-route="users" class="nav-link active">Users</a>
                                    <a href="#" data-route="api-keys" class="nav-link">API Keys</a>
                                    <a href="#" data-route="security-logs" class="nav-link">Security Logs</a>
                                </nav>
                                
                                <div class="dropdown">
                                    <div class="user-avatar" id="userMenu" data-bs-toggle="dropdown">
                                        <span>${this.userData?.initials || 'JD'}</span>
                                    </div>
                                    <ul class="dropdown-menu dropdown-menu-dark">
                                        <li><a class="dropdown-item" href="#" data-route="settings"><i class="bi bi-gear"></i> Settings</a></li>
                                        <li><a class="dropdown-item text-danger" href="#" id="logoutBtn"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main class="app-container">
                    <div class="dashboard-section">
                        <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                            <h1 class="section-title">
                                <i class="bi bi-person-badge"></i>
                                Account Management
                            </h1>
                            <div class="d-flex gap-2">
                                <button class="btn btn-outline-primary" onclick="authFlowApp.showBulkImportModal()">
                                    <i class="bi bi-upload"></i>
                                    Bulk Import
                                </button>
                                <button class="btn btn-outline-primary" onclick="authFlowApp.exportAccounts()">
                                    <i class="bi bi-download"></i>
                                    Export
                                </button>
                                <button class="btn btn-primary" id="addAccountBtn">
                                    <i class="bi bi-plus-circle"></i>
                                    Add Account
                                </button>
                            </div>
                        </div>

                        <!-- Enhanced Filtering -->
                        <div class="card mb-4">
                            <div class="card-body">
                                <div class="row g-3">
                                    <div class="col-md-3">
                                        <label class="form-label">Search</label>
                                        <input type="text" class="form-control" id="searchFilter" 
                                               placeholder="Search accounts...">
                                    </div>
                                    <div class="col-md-2">
                                        <label class="form-label">Group</label>
                                        <select class="form-control" id="groupFilter">
                                            ${groups.map(group => `
                                                <option value="${group}">${group === 'all' ? 'All Groups' : group}</option>
                                            `).join('')}
                                        </select>
                                    </div>
                                    <div class="col-md-2">
                                        <label class="form-label">Platform</label>
                                        <select class="form-control" id="platformFilter">
                                            ${platforms.map(platform => `
                                                <option value="${platform}">${platform === 'all' ? 'All Platforms' : platform}</option>
                                            `).join('')}
                                        </select>
                                    </div>
                                    <div class="col-md-2">
                                        <label class="form-label">Type</label>
                                        <select class="form-control" id="typeFilter">
                                            ${types.map(type => `
                                                <option value="${type}">${type === 'all' ? 'All Types' : type}</option>
                                            `).join('')}
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <label class="form-label">Sort By</label>
                                        <select class="form-control" id="sortFilter">
                                            <option value="name">Name</option>
                                            <option value="added">Date Added</option>
                                            <option value="platform">Platform</option>
                                            <option value="group">Group</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="row mt-3">
                                    <div class="col-12">
                                        <div class="filter-stats">
                                            Showing <strong>${stats.filtered}</strong> of <strong>${stats.total}</strong> accounts
                                            <span class="text-muted">• ${stats.groups} groups • ${stats.platforms} platforms</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Accounts Grid -->
                        <div class="accounts-grid-enhanced" id="accountsGrid">
                            ${this.getFilteredAccounts().map(account => this.getEnhancedAccountCard(account)).join('')}
                        </div>
                    </div>
                </main>
            </div>
        `;
    }

    getEnhancedAccountCard(account) {
        const isCookieAccount = account.type === 'Cookie';
        const hasCookies = this.cookieAccounts.has(account.id);
        
        return `
            <div class="account-card-enhanced ${isCookieAccount ? 'cookie-account' : 'totp-account'}" 
                 data-account-id="${account.id}" 
                 data-group="${account.group}" 
                 data-platform="${account.platform}" 
                 data-type="${account.type}">
                
                <div class="account-header">
                    <div class="account-badge-group">${account.group}</div>
                    <div class="account-type-badge ${isCookieAccount ? 'cookie' : 'totp'}">
                        <i class="bi bi-${isCookieAccount ? 'shield-lock' : 'clock'}"></i>
                        ${isCookieAccount ? 'Cookie' : 'TOTP'}
                    </div>
                </div>

                <div class="account-content">
                    <div class="platform-icon platform-${account.platform}">
                        <i class="bi bi-${account.icon}"></i>
                    </div>
                    <div class="account-info">
                        <div class="account-name">${account.name}</div>
                        <div class="account-username">${account.username || account.issuer}</div>
                        <div class="account-meta">
                            <span class="meta-item">
                                <i class="bi bi-tags"></i>
                                ${account.group}
                            </span>
                            <span class="meta-item">
                                <i class="bi bi-${account.platform === 'custom' ? 'person-badge' : account.platform}"></i>
                                ${account.platform}
                            </span>
                        </div>
                    </div>
                </div>

                <div class="account-actions">
                    ${isCookieAccount ? this.getCookieActions(account) : this.getTOTPActions(account)}
                </div>

                ${!isCookieAccount ? `
                    <div class="token-section">
                        <div class="token-display">
                            <span class="token-code" id="token-${account.id}">Loading...</span>
                            <span class="token-timer" id="timer-${account.id}">Calculating...</span>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    getTOTPActions(account) {
        return `
            <button class="btn btn-sm btn-outline-primary" onclick="authFlowApp.copyToken('${account.id}')">
                <i class="bi bi-clipboard"></i>
            </button>
            <button class="btn btn-sm btn-outline-secondary" onclick="authFlowApp.showAccountDetails('${account.id}')">
                <i class="bi bi-info-circle"></i>
            </button>
            <button class="btn btn-sm btn-outline-danger" onclick="authFlowApp.removeAccount('${account.id}')">
                <i class="bi bi-trash"></i>
            </button>
        `;
    }

    getCookieActions(account) {
        const hasCookies = this.cookieAccounts.has(account.id);
        
        return `
            <button class="btn btn-sm btn-outline-success" onclick="authFlowApp.manageCookies('${account.id}')"
                    ${!hasCookies ? 'disabled' : ''}>
                <i class="bi bi-shield-lock"></i>
            </button>
            <button class="btn btn-sm btn-outline-secondary" onclick="authFlowApp.showAccountDetails('${account.id}')">
                <i class="bi bi-info-circle"></i>
            </button>
            <button class="btn btn-sm btn-outline-danger" onclick="authFlowApp.removeAccount('${account.id}')">
                <i class="bi bi-trash"></i>
            </button>
        `;
    }

    // ============ COOKIE MANAGEMENT ============

    setupCookieManagement() {
        // Cookie management event listeners
    }

    async manageCookies(accountId) {
        const cookieData = this.cookieAccounts.get(accountId);
        if (!cookieData) return;

        const cookies = await this.cookieManager.decryptCookies(cookieData.encryptedData);
        if (!cookies) {
            alert('Failed to decrypt cookies');
            return;
        }

        this.showCookieManager(accountId, cookies, cookieData.platform);
    }

    showCookieManager(accountId, cookies, platform) {
        const modalHtml = `
            <div class="modal fade" id="cookieManagerModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-shield-lock"></i>
                                Cookie Management
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="cookie-summary mb-4">
                                <div class="platform-icon platform-${platform}">
                                    <i class="bi bi-${this.cookieManager.platforms[platform]?.icon || 'shield-lock'}"></i>
                                </div>
                                <div>
                                    <h6>${this.getAccountById(accountId)?.name}</h6>
                                    <div class="cookie-count">${cookies.length} cookies stored</div>
                                </div>
                            </div>

                            <div class="cookie-list">
                                ${cookies.map((cookie, index) => `
                                    <div class="cookie-item ${this.cookieManager.getCookieExpiryStatus(cookie.expires)}">
                                        <div class="cookie-info">
                                            <div class="cookie-name">${cookie.name}</div>
                                            <div class="cookie-domain">${cookie.domain}</div>
                                            <div class="cookie-meta">
                                                <span>Expires: ${cookie.expires ? new Date(cookie.expires).toLocaleDateString() : 'Session'}</span>
                                                <span>•</span>
                                                <span>${cookie.secure ? 'Secure' : 'Not Secure'}</span>
                                                <span>•</span>
                                                <span>${cookie.httponly ? 'HTTP Only' : 'Not HTTP Only'}</span>
                                            </div>
                                        </div>
                                        <div class="cookie-actions">
                                            <button class="btn btn-sm btn-outline-primary" onclick="authFlowApp.copyCookieValue('${accountId}', ${index})">
                                                <i class="bi bi-clipboard"></i>
                                            </button>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-outline-primary" onclick="authFlowApp.exportCookies('${accountId}')">
                                <i class="bi bi-download"></i>
                                Export Cookies
                            </button>
                            <button type="button" class="btn btn-primary" onclick="authFlowApp.copyAllCookies('${accountId}')">
                                <i class="bi bi-clipboard-check"></i>
                                Copy All Cookies
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        if (!document.getElementById('cookieManagerModal')) {
            document.body.insertAdjacentHTML('beforeend', modalHtml);
        }

        const modal = new bootstrap.Modal(document.getElementById('cookieManagerModal'));
        modal.show();
    }

    async copyCookieValue(accountId, cookieIndex) {
        const cookieData = this.cookieAccounts.get(accountId);
        if (!cookieData) return;

        const cookies = await this.cookieManager.decryptCookies(cookieData.encryptedData);
        if (cookies && cookies[cookieIndex]) {
            await navigator.clipboard.writeText(cookies[cookieIndex].value);
            this.showToast('Cookie value copied to clipboard', 'success');
        }
    }

    async copyAllCookies(accountId) {
        const cookieData = this.cookieAccounts.get(accountId);
        if (!cookieData) return;

        const cookies = await this.cookieManager.decryptCookies(cookieData.encryptedData);
        if (cookies) {
            const success = await this.cookieManager.copyCookiesToClipboard(cookies);
            if (success) {
                this.showToast('All cookies copied to clipboard', 'success');
            } else {
                this.showToast('Failed to copy cookies', 'error');
            }
        }
    }

    async exportCookies(accountId) {
        const cookieData = this.cookieAccounts.get(accountId);
        if (!cookieData) return;

        const cookies = await this.cookieManager.decryptCookies(cookieData.encryptedData);
        if (cookies) {
            const exportData = this.cookieManager.formatCookieForExport(cookies);
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cookies-${accountId}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }
    }

    // ============ ENHANCED FILTERING ============

    setupEnhancedFiltering() {
        // Filtering will be handled in the accounts page initialization
    }

    getFilteredAccounts() {
        const filters = {
            search: document.getElementById('searchFilter')?.value || '',
            group: document.getElementById('groupFilter')?.value || 'all',
            platform: document.getElementById('platformFilter')?.value || 'all',
            type: document.getElementById('typeFilter')?.value || 'all',
            sortBy: document.getElementById('sortFilter')?.value || 'name',
            sortOrder: 'asc'
        };

        return this.filterManager.applyFilters(this.accounts, filters);
    }

    // ============ EXPORT FUNCTIONALITY ============

    exportAccounts() {
        const filteredAccounts = this.getFilteredAccounts();
        const exportData = filteredAccounts.map(account => ({
            name: account.name,
            secret: account.secret,
            platform: account.platform,
            issuer: account.issuer,
            type: account.type,
            group: account.group,
            username: account.username,
            added: account.added,
            lastUsed: account.lastUsed
        }));

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `authflow-accounts-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ============ UTILITY METHODS ============

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showToast(message, type = 'info') {
        // Simple toast implementation
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-content">
                <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    getAccountById(accountId) {
        return this.accounts.find(acc => acc.id === accountId);
    }

    // Override the original accounts template
    getAccountsTemplate() {
        return this.getEnhancedAccountsTemplate();
    }
}

// ============ INITIALIZE ENHANCED APP ============
document.addEventListener('DOMContentLoaded', () => {
    window.authFlowApp = new EnhancedAuthFlowSPA();
});

// ===== PARTICLE BACKGROUND - ADD THIS AT THE END OF YOUR app.js FILE =====

class ParticleBackground {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.mouse = { x: 0, y: 0 };
        
        this.init();
    }
    
    init() {
        this.canvas.className = 'particles-background';
        document.body.appendChild(this.canvas); // Fixed: actually add to body
        
        this.resize();
        this.createParticles();
        this.animate();
        
        window.addEventListener('resize', () => this.resize());
        window.addEventListener('mousemove', (e) => {
            this.mouse.x = e.clientX;
            this.mouse.y = e.clientY;
        });
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.createParticles(); // Recreate particles on resize
    }
    
    createParticles() {
        this.particles = [];
        const particleCount = Math.min(80, Math.floor(window.innerWidth / 15));
        
        for (let i = 0; i < particleCount; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                size: Math.random() * 3 + 1,
                speedX: Math.random() * 0.5 - 0.25,
                speedY: Math.random() * 0.5 - 0.25,
                color: `rgba(255, 255, 255, ${Math.random() * 0.4 + 0.1})`
            });
        }
    }
    
    animate() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Update and draw particles
        this.particles.forEach(particle => {
            particle.x += particle.speedX;
            particle.y += particle.speedY;
            
            // Wrap around edges
            if (particle.x > this.canvas.width) particle.x = 0;
            if (particle.x < 0) particle.x = this.canvas.width;
            if (particle.y > this.canvas.height) particle.y = 0;
            if (particle.y < 0) particle.y = this.canvas.height;
            
            // Mouse interaction
            const dx = particle.x - this.mouse.x;
            const dy = particle.y - this.mouse.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            if (distance < 100) {
                particle.x += (dx / distance) * 2;
                particle.y += (dy / distance) * 2;
            }
            
            // Draw particle
            this.ctx.beginPath();
            this.ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            this.ctx.fillStyle = particle.color;
            this.ctx.fill();
            
            // Draw connections between nearby particles
            this.particles.forEach(otherParticle => {
                const dx = particle.x - otherParticle.x;
                const dy = particle.y - otherParticle.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance < 150) {
                    this.ctx.beginPath();
                    this.ctx.strokeStyle = `rgba(90, 133, 133, ${0.2 * (1 - distance / 150)})`;
                    this.ctx.lineWidth = 0.5;
                    this.ctx.moveTo(particle.x, particle.y);
                    this.ctx.lineTo(otherParticle.x, otherParticle.y);
                    this.ctx.stroke();
                }
            });
        });
        
        requestAnimationFrame(() => this.animate());
    }
}

// Initialize particle background when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ParticleBackground();
});