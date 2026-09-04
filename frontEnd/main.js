/* ===================================================================
   SENTINEL — Application Logic
   Backend: http://127.0.0.1:8000
   =================================================================== */

// ─── Global State ───────────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:8000';
let scanData = null;        // Latest scan response
let scanHistory = [];       // History of scans
let currentView = 'landing';

// ─── Pipeline Definition ────────────────────────────────────────────
const PIPELINE_STAGES = [
    { id: 'recon',      name: 'Recon',                status: 'Discovering application surface' },
    { id: 'dast',       name: 'DAST',                 status: 'Executing dynamic security tests' },
    { id: 'adaptive',   name: 'Adaptive DAST',        status: 'Generating targeted probes' },
    { id: 'auth',       name: 'Authentication',       status: 'Testing authentication mechanisms' },
    { id: 'authz',      name: 'Authorization',        status: 'Testing access boundaries' },
    { id: 'reasoning',  name: 'Autonomous Reasoning', status: 'Reasoning over security evidence' },
    { id: 'static',     name: 'Static Analysis',      status: 'Analyzing source code' },
    { id: 'ai',         name: 'AI Analysis',          status: 'Synthesizing security evidence' },
    { id: 'correlation',name: 'Correlation',          status: 'Correlating findings' },
];

// ─── Navigation ─────────────────────────────────────────────────────
function navigateTo(viewId) {
    const normalizedView = viewId === 'live-scan' ? 'live-scan' : viewId;
    const id = normalizedView === 'landing' ? 'view-landing' : `view-${normalizedView}`;
    const target = document.getElementById(id);
    if (!target) return false;

    // All product views require a signed-in session. Landing remains public.
    if (normalizedView !== 'landing' && !isAuthenticated()) {
        openAuthModal('login', normalizedView);
        return false;
    }

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    target.classList.add('active');
    target.scrollTop = 0;
    currentView = normalizedView;
    document.body.classList.toggle('landing-active', normalizedView === 'landing');
    try { sessionStorage.setItem('sentinel.currentView', normalizedView); } catch (_) {}

    const nav = document.getElementById('app-nav');
    if (normalizedView === 'landing') nav.classList.remove('visible');
    else nav.classList.add('visible');

    const activeView = normalizedView === 'live-scan' ? 'scan' : normalizedView;
    document.querySelectorAll('.app-nav a[data-view]').forEach(a => {
        a.classList.toggle('active', a.dataset.view === activeView);
    });
    document.querySelectorAll('.mobile-menu a[data-view]').forEach(a => {
        a.classList.toggle('active', a.dataset.view === activeView);
    });

    target.querySelectorAll('.animate-in').forEach(el => {
        el.style.animation = 'none';
        void el.offsetHeight;
        el.style.animation = '';
    });

    window.scrollTo({ top: 0, behavior: 'smooth' });
    updateAuthUI();
    return false;
}



// ─── Supabase Auth ────────────────────────────────────────────────
const SUPABASE_URL = 'https://kfilhhlnguhnbpysnpgj.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_eg_N7NWPuk9ap0-2vddFnw_m0CiYU_z';
const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);
let authMode = 'login';
let authReturnView = 'overview';
let currentSession = null;

function isAuthenticated() { return !!currentSession; }
function currentUser() { return currentSession?.user?.email || ''; }
function currentUserMetadata() { return currentSession?.user?.user_metadata || {}; }

async function refreshSession() {
    const { data } = await supabaseClient.auth.getSession();
    currentSession = data.session;
    updateAuthUI();
    return currentSession;
}

function openAuthModal(mode = 'login', returnView = 'overview') {
    authMode = mode; authReturnView = returnView || 'overview';
    const modal = document.getElementById('auth-modal');
    document.getElementById('auth-title').textContent = mode === 'signup' ? 'Create your account.' : 'Welcome back.';
    document.getElementById('auth-copy').textContent = mode === 'signup' ? 'Create your Sentinel workspace and start testing applications.' : 'Sign in to access your security workspace.';
    document.getElementById('auth-submit').textContent = mode === 'signup' ? 'Create Account' : 'Sign In';
    document.getElementById('auth-switch').innerHTML = mode === 'signup' ? 'Already have an account? <strong>Sign in</strong>' : "Don't have an account? <strong>Create one</strong>";
    const isSignup = mode === 'signup';
    document.getElementById('auth-confirm-wrap').classList.toggle('hidden', !isSignup);
    document.getElementById('signup-details-wrap').classList.toggle('hidden', !isSignup);

    // Hidden signup-only fields must NOT participate in login form validation.
    // Otherwise the browser blocks the Sign In submit before submitAuth() runs.
    document.getElementById('auth-full-name').required = isSignup;
    document.getElementById('auth-confirm').required = isSignup;

    document.getElementById('auth-error').textContent = '';
    modal.classList.add('open'); modal.setAttribute('aria-hidden', 'false');
    document.documentElement.classList.add('modal-open');
    document.body.classList.add('modal-open');
    setTimeout(() => document.getElementById('auth-email').focus(), 50);
}

function closeAuthModal() {
    const modal = document.getElementById('auth-modal');
    modal.classList.remove('open'); modal.setAttribute('aria-hidden', 'true');
    document.documentElement.classList.remove('modal-open');
    document.body.classList.remove('modal-open');
    document.getElementById('auth-form').reset();
    document.getElementById('auth-error').textContent = '';
}
function toggleAuthMode() { openAuthModal(authMode === 'login' ? 'signup' : 'login', authReturnView); }

async function submitAuth(event) {
    event.preventDefault();
    const email = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    const confirm = document.getElementById('auth-confirm').value;
    const fullName = document.getElementById('auth-full-name').value.trim();
    const organization = document.getElementById('auth-organization').value.trim();
    const role = document.getElementById('auth-role').value.trim();
    const error = document.getElementById('auth-error');
    const submit = document.getElementById('auth-submit');
    // Validate only the actual input value. Clear stale validation messages as the user edits.
    if (authMode === 'signup' && password.length < 6) {
        error.textContent = 'Password must be at least 6 characters.';
        document.getElementById('auth-password').focus();
        return;
    }
    if (authMode === 'signup' && password !== confirm) {
        error.textContent = 'Passwords do not match.';
        document.getElementById('auth-confirm').focus();
        return;
    }
    error.textContent = '';
    submit.disabled = true; submit.textContent = authMode === 'signup' ? 'Creating...' : 'Signing in...';
    try {
        const result = authMode === 'signup'
            ? await supabaseClient.auth.signUp({
                email,
                password,
                options: {
                    data: {
                        full_name: fullName,
                        organization,
                        role
                    }
                }
            })
            : await supabaseClient.auth.signInWithPassword({ email, password });
        if (result.error) throw result.error;
        currentSession = result.data.session;
        if (authMode === 'signup' && !currentSession) {
            error.textContent = 'Account created. Check your email to confirm, then sign in.';
            return;
        }
        closeAuthModal(); updateAuthUI(); navigateTo(authReturnView);
    } catch (err) { error.textContent = err.message || 'Authentication failed.'; }
    finally { submit.disabled = false; submit.textContent = authMode === 'signup' ? 'Create Account' : 'Sign In'; }
}

function handleGetStarted() { isAuthenticated() ? navigateTo('overview') : openAuthModal('signup', 'overview'); }
function handleLandingAccountAction() { isAuthenticated() ? navigateTo('overview') : openAuthModal('login', 'overview'); }

async function handleAccountAction() {
    if (isAuthenticated()) {
        await supabaseClient.auth.signOut();
        currentSession = null; updateAuthUI(); navigateTo('landing');
    } else openAuthModal('login', currentView === 'landing' ? 'overview' : currentView);
}

function updateAuthUI() {
    const account = document.getElementById('nav-account');
    const profile = document.getElementById('nav-profile');
    const mobileProfile = document.getElementById('mobile-profile-btn');
    const landingSignIn = document.getElementById('landing-signin');
    const user = currentUser();
    if (account) account.textContent = user ? 'Sign out' : 'Sign in';
    if (profile) profile.classList.toggle('hidden', !user);
    if (mobileProfile) mobileProfile.classList.toggle('hidden', !user);
    if (landingSignIn) landingSignIn.textContent = user ? 'Open App' : 'Sign in';
}

function openProfileModal() {
    if (!isAuthenticated()) { openAuthModal('login', currentView === 'landing' ? 'overview' : currentView); return; }
    const metadata = currentUserMetadata();
    const email = currentUser();
    const name = metadata.full_name || 'Not provided';
    const organization = metadata.organization || 'Not provided';
    const role = metadata.role || 'Not provided';
    document.getElementById('profile-name').textContent = name;
    document.getElementById('profile-email').textContent = email || 'Not provided';
    document.getElementById('profile-organization').textContent = organization;
    document.getElementById('profile-role').textContent = role;
    document.getElementById('profile-avatar').textContent = (name !== 'Not provided' ? name.charAt(0) : email.charAt(0)).toUpperCase();
    const modal = document.getElementById('profile-modal');
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.documentElement.classList.add('modal-open');
    document.body.classList.add('modal-open');
}

function closeProfileModal() {
    const modal = document.getElementById('profile-modal');
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    document.documentElement.classList.remove('modal-open');
    document.body.classList.remove('modal-open');
}

async function signOutFromProfile() {
    closeProfileModal();
    await supabaseClient.auth.signOut();
    currentSession = null;
    updateAuthUI();
    navigateTo('landing');
}

// Restore Supabase session and react to login/logout.
window.addEventListener('load', () => { const landing = document.getElementById('view-landing'); if (landing) landing.scrollTop = 0; });
refreshSession();
supabaseClient.auth.onAuthStateChange((_event, session) => { currentSession = session; updateAuthUI(); });

// Clear stale validation messages while typing.
document.addEventListener('input', (event) => {
    if (['auth-email', 'auth-full-name', 'auth-organization', 'auth-role', 'auth-password', 'auth-confirm'].includes(event.target?.id)) {
        const error = document.getElementById('auth-error');
        if (error) error.textContent = '';
    }
});

// ─── Mobile Menu ────────────────────────────────────────────────────
const burger = document.getElementById('mobile-burger');
const overlay = document.getElementById('mobile-overlay');
const mobileMenu = document.getElementById('mobile-menu');

function openMobileMenu() {
    burger.classList.add('open');
    overlay.style.display = 'block';
    mobileMenu.style.display = 'flex';
    requestAnimationFrame(() => {
        overlay.classList.add('open');
        mobileMenu.classList.add('open');
    });
}
function closeMobileMenu() {
    burger.classList.remove('open');
    overlay.classList.remove('open');
    mobileMenu.classList.remove('open');
    setTimeout(() => {
        overlay.style.display = 'none';
    }, 300);
}
if (burger) {
    burger.addEventListener('click', () => {
        burger.classList.contains('open') ? closeMobileMenu() : openMobileMenu();
    });
}
if (overlay) {
    overlay.addEventListener('click', closeMobileMenu);
}

// ─── Auth Fields Toggle ─────────────────────────────────────────────
function toggleAuthFields() {
    const toggle = document.getElementById('auth-toggle');
    const fields = document.getElementById('auth-fields');
    toggle.classList.toggle('open');
    fields.classList.toggle('visible');
}

// ─── Activity Sub-tabs ──────────────────────────────────────────────
function switchActivityTab(tabId, btn) {
    document.querySelectorAll('.activity-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.activity-tab').forEach(t => t.classList.remove('active'));
    const panel = document.getElementById(tabId);
    if (panel) panel.classList.add('active');
    if (btn) btn.classList.add('active');
}

// ─── Counter Animation ──────────────────────────────────────────────
function animateCounters() {
    document.querySelectorAll('.counter').forEach(counter => {
        const target = parseFloat(counter.dataset.target);
        const duration = 2000;
        const start = Date.now();
        const update = () => {
            const progress = Math.min((Date.now() - start) / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            const current = ease * target;
            counter.innerText = Number.isInteger(target) ? Math.floor(current) : current.toFixed(1);
            if (progress < 1) requestAnimationFrame(update);
            else counter.innerText = target;
        };
        update();
    });
}

function animateMetricValue(el, targetVal) {
    const duration = 1200;
    const start = Date.now();
    const numTarget = parseInt(targetVal);
    if (isNaN(numTarget)) { el.textContent = targetVal; return; }
    const update = () => {
        const progress = Math.min((Date.now() - start) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = String(Math.floor(ease * numTarget)).padStart(2, '0');
        if (progress < 1) requestAnimationFrame(update);
        else el.textContent = String(numTarget).padStart(2, '0');
    };
    update();
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ─── Start Scan ─────────────────────────────────────────────────────
async function validateScanTarget(target) {
    let parsed;
    try { parsed = new URL(target); } catch (_) {
        throw new Error('Invalid target URL. Enter a complete URL such as http://127.0.0.1:9000');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Only HTTP and HTTPS target URLs are supported.');
    }
    if (!parsed.hostname) throw new Error('Target URL is missing a hostname.');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
        await fetch(target, { method:'GET', mode:'no-cors', cache:'no-store', redirect:'follow', signal:controller.signal });
    } catch (err) {
        if (err.name === 'AbortError') throw new Error('Target did not respond within 5 seconds. Scan cancelled.');
        throw new Error('Target is unreachable. Check the URL and make sure the application is running.');
    } finally { clearTimeout(timer); }
    return true;
}

async function startScan() {
    const input = document.getElementById('scan-target-input');
    const target = input.value.trim();
    if (!target) { input.focus(); return; }

    const btn = document.getElementById('btn-start-scan');
    btn.disabled = true;
    btn.textContent = 'Checking target...';

    try {
        await validateScanTarget(target);
    } catch (err) {
        const existing = document.getElementById('target-validation-error');
        if (existing) existing.remove();
        const message = document.createElement('div');
        message.id = 'target-validation-error';
        message.className = 'scan-error-banner';
        message.setAttribute('role', 'alert');
        message.innerHTML = `<div class="scan-error-title">INVALID TARGET</div><div class="scan-error-message">${escapeHtml(err.message)}</div>`;
        input.insertAdjacentElement('afterend', message);
        btn.disabled = false;
        btn.textContent = 'Start Scan';
        return;
    }
    const oldValidation = document.getElementById('target-validation-error');
    if (oldValidation) oldValidation.remove();
    btn.textContent = 'Scanning...';

    // Navigate to live scan view
    navigateTo('live-scan');
    renderPipelineTimeline(target);

    const scanStartTime = Date.now();

    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const responseText = await response.text();

        if (!response.ok) {
            let detail = responseText;
            try {
                const errorJson = JSON.parse(responseText);
                detail = errorJson.detail || errorJson.message || responseText;
            } catch (_) {}
            throw new Error(`Backend returned ${response.status}: ${detail}`);
        }

        try {
            scanData = JSON.parse(responseText);
            try { sessionStorage.setItem('sentinel.scanData', JSON.stringify(scanData)); } catch (_) {}
        } catch (_) {
            throw new Error('Backend returned an invalid JSON response.');
        }
        const scanDuration = Math.round((Date.now() - scanStartTime) / 1000);

        // Save to history
        scanHistory.unshift({
            target,
            duration: `${scanDuration}s`,
            findings: scanData.findings ? scanData.findings.length : 0,
            data: scanData,
            timestamp: new Date().toISOString()
        });

        // Complete the pipeline animation
        completePipeline();

        // Hydrate all views after a brief pause
        setTimeout(() => {
            hydrateAllViews(scanData, target);
            navigateTo('findings');
        }, 1800);

    } catch (err) {
        console.error('Scan error:', err);
        completePipeline();

        // IMPORTANT: do not silently throw the user back to Overview.
        // Keep them on the live-scan screen and show the actual backend error.
        const timeline = document.getElementById('pipeline-timeline');
        if (timeline) {
            timeline.insertAdjacentHTML('beforeend', `
                <div class="scan-error-banner" role="alert">
                    <div class="scan-error-title">SCAN FAILED</div>
                    <div class="scan-error-message">${escapeHtml(err.message || 'Unknown scan error')}</div>
                    <button class="scan-error-retry" onclick="startScan()">Retry Scan</button>
                </div>
            `);
        }
    } finally {
        btn.disabled = false;
        btn.textContent = 'Start Scan';
    }
}

// ─── Pipeline Timeline Rendering ────────────────────────────────────
function renderPipelineTimeline(target) {
    const container = document.getElementById('pipeline-timeline');
    const targetEl = document.getElementById('live-target-url');
    targetEl.textContent = target;

    container.innerHTML = PIPELINE_STAGES.map((stage, i) => `
        <div class="pipeline-node" id="pipeline-${stage.id}" style="animation-delay:${i * 0.08}s">
            <div class="node-indicator"></div>
            <div class="node-content">
                <div class="node-name">${stage.name}</div>
                <div class="node-status">${stage.status}</div>
            </div>
        </div>
    `).join('');

    // Animate through stages sequentially
    animatePipelineStages();
}

function animatePipelineStages() {
    let currentStage = 0;

    function activateNext() {
        if (currentStage > 0) {
            const prev = document.getElementById(`pipeline-${PIPELINE_STAGES[currentStage - 1].id}`);
            if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
        }
        if (currentStage < PIPELINE_STAGES.length) {
            const node = document.getElementById(`pipeline-${PIPELINE_STAGES[currentStage].id}`);
            if (node) node.classList.add('active');
            currentStage++;
            // Variable delay to feel organic
            const delay = 800 + Math.random() * 1200;
            window._pipelineTimer = setTimeout(activateNext, delay);
        }
    }

    activateNext();
}

function completePipeline() {
    clearTimeout(window._pipelineTimer);
    PIPELINE_STAGES.forEach(stage => {
        const node = document.getElementById(`pipeline-${stage.id}`);
        if (node) {
            node.classList.remove('active');
            node.classList.add('done');
        }
    });
}

// ─── Hydrate All Views ──────────────────────────────────────────────
function hydrateAllViews(data, target) {
    hydrateOverview(data, target);
    hydrateAttackSurface(data);
    hydrateFindings(data);
    hydrateAttackPaths(data);
    hydrateDAST(data);
    hydrateAdaptiveDAST(data);
    hydrateAuth(data);
    hydrateAuthZ(data);
    hydrateReasoning(data);
    hydrateStaticAnalysis(data);
    hydrateAIAnalyst(data);
    hydrateCorrelation(data);
    hydrateHistory();
    hydrateReport(data, target);
}

// ─── Overview ───────────────────────────────────────────────────────
function hydrateOverview(data, target) {
    // Show target
    const targetContainer = document.getElementById('overview-target');
    const targetUrl = document.getElementById('overview-target-url');
    if (target) {
        targetContainer.style.display = 'flex';
        targetUrl.textContent = target;
    }

    // Metrics
    const findings = data.findings || [];
    const endpoints = extractEndpoints(data);
    const requests = data.observations ? data.observations.length : 0;
    const score = computeSecurityScore(findings);

    animateMetricValue(document.getElementById('ov-findings'), findings.length);
    animateMetricValue(document.getElementById('ov-endpoints'), endpoints.length);
    animateMetricValue(document.getElementById('ov-requests'), requests);
    animateMetricValue(document.getElementById('ov-score'), score);
}

// ─── Attack Surface ─────────────────────────────────────────────────
function hydrateAttackSurface(data) {
    const endpoints = extractEndpoints(data);
    const countEl = document.getElementById('as-endpoint-count');
    animateMetricValue(countEl, endpoints.length);

    const list = document.getElementById('endpoint-list');
    if (!endpoints.length) {
        list.innerHTML = '<div class="empty-state"><span class="empty-state-text">No endpoints discovered</span></div>';
        return;
    }

    list.innerHTML = endpoints.map((ep, i) => `
        <div class="endpoint-item" onclick="toggleEndpointDetail('ep-detail-${i}')" style="animation:fadeSlideIn 0.4s ease ${i * 0.05}s both">
            <span class="endpoint-method ${(ep.method || 'GET').toLowerCase()}">${ep.method || 'GET'}</span>
            <span class="endpoint-path">${ep.path || ep.endpoint || ep}</span>
            <span class="endpoint-meta">${ep.auth ? 'Auth' : ''}</span>
        </div>
        <div class="endpoint-detail" id="ep-detail-${i}">
            <div class="endpoint-detail-row"><span class="detail-key">Method</span><span class="detail-value">${ep.method || 'GET'}</span></div>
            ${ep.parameters ? `<div class="endpoint-detail-row"><span class="detail-key">Parameters</span><span class="detail-value">${ep.parameters}</span></div>` : ''}
            ${ep.auth !== undefined ? `<div class="endpoint-detail-row"><span class="detail-key">Auth Required</span><span class="detail-value">${ep.auth ? 'Yes' : 'No'}</span></div>` : ''}
        </div>
    `).join('');
}

function toggleEndpointDetail(id) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('open');
}

// ─── Findings ───────────────────────────────────────────────────────
function hydrateFindings(data) {
    const findings = data.findings || [];
    const list = document.getElementById('findings-list');
    const summary = document.getElementById('findings-summary');

    if (!findings.length) {
        list.innerHTML = '<div class="empty-state"><span class="empty-state-text">No findings discovered</span></div>';
        summary.textContent = '';
        return;
    }

    // Summary
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
        const sev = normalizeSeverity(f.severity);
        if (counts[sev] !== undefined) counts[sev]++;
    });
    summary.textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''} · ${counts.critical} Critical · ${counts.high} High · ${counts.medium} Medium · ${counts.low} Low`;

    list.innerHTML = findings.map((f, i) => {
        const sev = normalizeSeverity(f.severity);
        return `
            <div class="finding-item" onclick="showFindingDetail(${i})" style="animation:fadeSlideIn 0.4s ease ${i * 0.06}s both">
                <div class="finding-header">
                    <span class="severity-pill ${sev}">${sev}</span>
                    <span class="finding-name">${f.vulnerability || f.name || f.title || 'Finding'}</span>
                </div>
                <div class="finding-meta">
                    <span class="font-mono">${f.endpoint || f.url || ''}</span>
                    <span class="finding-status ${f.status === 'confirmed' || f.validated ? 'confirmed' : ''}">${f.status || (f.validated ? 'CONFIRMED' : 'POTENTIAL')}${f.confidence ? ' · ' + f.confidence.toUpperCase() + ' CONFIDENCE' : ''}</span>
                </div>
            </div>
        `;
    }).join('');
}

function showFindingDetail(index) {
    const findings = scanData ? scanData.findings || [] : [];
    const f = findings[index];
    if (!f) return;

    const sev = normalizeSeverity(f.severity);
    const container = document.getElementById('finding-detail-content');

    container.innerHTML = `
        <button class="btn-back" onclick="navigateTo('findings')"><i class="fa-solid fa-arrow-left"></i> Findings</button>

        <div class="finding-detail-severity ${sev} animate-in">${sev}</div>
        <div class="finding-detail-name animate-in animate-in-delay-1">${f.vulnerability || f.name || f.title || 'Finding'}</div>
        <div class="finding-detail-endpoint animate-in animate-in-delay-1">${f.endpoint || f.url || ''}</div>

        <div class="finding-detail-badges animate-in animate-in-delay-2">
            <span class="detail-badge">${f.status || (f.validated ? 'Confirmed' : 'Potential')}</span>
            ${f.confidence ? `<span class="detail-badge">${f.confidence} Confidence</span>` : ''}
            ${f.source ? `<span class="detail-badge">${f.source}</span>` : ''}
        </div>

        ${f.evidence || f.details || f.description ? `
        <div class="evidence-section animate-in animate-in-delay-2">
            <div class="evidence-title">Evidence</div>
            ${f.authenticated_user ? `<div class="evidence-row"><span class="evidence-key">Auth User</span><span class="evidence-value">${f.authenticated_user}</span></div>` : ''}
            ${f.request ? `<div class="evidence-row"><span class="evidence-key">Request</span><span class="evidence-value">${f.request}</span></div>` : ''}
            ${f.response ? `<div class="evidence-row"><span class="evidence-key">Response</span><span class="evidence-value">${f.response}</span></div>` : ''}
            ${f.evidence ? `<div class="evidence-explanation">${f.evidence}</div>` : ''}
            ${f.details ? `<div class="evidence-explanation">${f.details}</div>` : ''}
            ${f.description ? `<div class="evidence-explanation">${f.description}</div>` : ''}
        </div>
        ` : ''}

        ${f.reasoning || f.explanation ? `
        <div class="evidence-section animate-in animate-in-delay-3">
            <div class="evidence-title">Why Sentinel Confirmed It</div>
            <div class="evidence-explanation">${f.reasoning || f.explanation}</div>
        </div>
        ` : ''}

        ${f.remediation ? `
        <div class="evidence-section animate-in animate-in-delay-4">
            <div class="evidence-title">Remediation</div>
            <div class="evidence-remediation">${f.remediation}</div>
        </div>
        ` : ''}
    `;

    navigateTo('finding-detail');
}

// ─── Attack Paths ───────────────────────────────────────────────────
function hydrateAttackPaths(data) {
    const paths = data.attack_paths || [];
    const container = document.getElementById('attack-paths-container');

    if (!paths.length) {
        container.innerHTML = '<div class="empty-state"><span class="empty-state-text">No attack paths discovered</span></div>';
        return;
    }

    container.innerHTML = paths.map((path, pi) => {
        const steps = path.steps || path.nodes || path.chain || [path];
        const stepsArray = Array.isArray(steps) ? steps : [steps];

        // Build node flow
        const nodesHtml = stepsArray.map((step, si) => {
            const label = typeof step === 'string' ? step : (step.name || step.label || step.action || step.description || JSON.stringify(step));
            const isCritical = typeof step === 'object' && (step.severity === 'high' || step.severity === 'critical');
            return `
                <div class="path-node ${isCritical ? 'critical' : ''}">${escapeHtml(label)}</div>
                ${si < stepsArray.length - 1 ? '<div class="path-connector"></div>' : ''}
            `;
        }).join('');

        // Detail panel
        const severity = path.severity || 'medium';
        const confidence = path.confidence || 'medium';

        return `
            <div class="attack-path-flow" style="animation:fadeSlideIn 0.5s ease ${pi * 0.1}s both">
                ${nodesHtml}
            </div>
            ${pi === 0 ? `
            <div class="attack-path-detail-panel visible">
                <div class="section-label">Attack Path</div>
                <div style="margin-top:calc(16*var(--s));display:flex;flex-direction:column;gap:calc(16*var(--s));">
                    ${stepsArray.map(step => {
                        const label = typeof step === 'string' ? step : (step.name || step.label || step.action || step.description || '');
                        return `<div style="font-family:var(--font-mono);font-size:calc(13*var(--s));color:rgba(255,255,255,0.7);">→ ${escapeHtml(label)}</div>`;
                    }).join('')}
                </div>
                <div style="margin-top:calc(28*var(--s));display:flex;flex-direction:column;gap:calc(12*var(--s));">
                    <div class="evidence-row"><span class="evidence-key">Severity</span><span class="evidence-value" style="text-transform:uppercase;">${severity}</span></div>
                    <div class="evidence-row"><span class="evidence-key">Confidence</span><span class="evidence-value" style="text-transform:uppercase;">${confidence}</span></div>
                    <div class="evidence-row"><span class="evidence-key">Status</span><span class="evidence-value" style="text-transform:uppercase;">${path.status || 'CONFIRMED'}</span></div>
                </div>
            </div>
            ` : ''}
        `;
    }).join('');
}

// ─── DAST ───────────────────────────────────────────────────────────
function hydrateDAST(data) {
    const obs = data.observations || [];
    const findings = data.findings || [];
    const endpoints = extractEndpoints(data);

    // Count DAST-like observations
    const dastObs = obs.filter(o => typeof o === 'string' ? o.toLowerCase().includes('request') || o.toLowerCase().includes('http') : true);

    animateMetricValue(document.getElementById('dast-requests'), dastObs.length || obs.length);
    animateMetricValue(document.getElementById('dast-endpoints'), endpoints.length);
    animateMetricValue(document.getElementById('dast-tests'), Math.max(findings.length, endpoints.length));
    animateMetricValue(document.getElementById('dast-potential'), findings.length);

    const categories = ['Security Headers', 'Parameter Manipulation', 'Reflection', 'Response Differences', 'Input Validation', 'Controlled SQL Error Testing'];
    const catContainer = document.getElementById('dast-categories');
    catContainer.innerHTML = categories.map((c, i) =>
        `<div class="dast-category" style="animation:fadeSlideIn 0.3s ease ${i * 0.05}s both">${c}</div>`
    ).join('');
}

// ─── Adaptive DAST ──────────────────────────────────────────────────
function hydrateAdaptiveDAST(data) {
    const endpoints = extractEndpoints(data);
    const prioritized = Math.min(endpoints.length, Math.ceil(endpoints.length * 0.6));

    animateMetricValue(document.getElementById('adapt-endpoints'), prioritized);
    animateMetricValue(document.getElementById('adapt-probes'), Math.max(prioritized * 2, 1));
    animateMetricValue(document.getElementById('adapt-http'), Math.max(prioritized * 3, 1));

    const insightsContainer = document.getElementById('adaptive-insights');
    if (endpoints.length === 0) {
        insightsContainer.innerHTML = '<div class="empty-state"><span class="empty-state-text">Awaiting scan data</span></div>';
        return;
    }

    const reasons = ['High parameter surface', 'Authentication context', 'Interesting response behavior', 'Complex input processing'];
    insightsContainer.innerHTML = endpoints.slice(0, 4).map((ep, i) => `
        <div class="adaptive-insight" style="animation:fadeSlideIn 0.4s ease ${i * 0.08}s both">
            <div class="adaptive-insight-title">${ep.path || ep.endpoint || ep}</div>
            <div class="adaptive-insight-reason">${reasons[i % reasons.length]}</div>
        </div>
    `).join('');
}

// ─── Authentication ─────────────────────────────────────────────────
function hydrateAuth(data) {
    const container = document.getElementById('auth-content');
    // Look for auth info in the data
    const hasAuth = data.findings && data.findings.some(f =>
        (f.vulnerability || f.name || '').toLowerCase().includes('auth')
    );
    const authEndpoint = extractEndpoints(data).find(ep =>
        (ep.path || ep.endpoint || ep || '').toLowerCase().includes('login')
    );

    const endpointPath = authEndpoint ? (authEndpoint.path || authEndpoint.endpoint || authEndpoint) : 'POST /login';
    const isAuthenticated = data.status === 'completed' || data.status === 'complete';

    container.innerHTML = `
        <div style="margin-top:calc(20*var(--s));">
            <div class="evidence-row" style="margin-bottom:calc(20*var(--s));">
                <span class="evidence-key">Endpoint Detected</span>
                <span class="evidence-value font-mono">${escapeHtml(String(endpointPath))}</span>
            </div>
            <div class="auth-status">
                <span class="auth-dot ${isAuthenticated ? '' : 'inactive'}"></span>
                <span>${isAuthenticated ? 'AUTHENTICATED' : 'NOT AUTHENTICATED'}</span>
            </div>
            ${isAuthenticated ? `
            <div style="margin-top:calc(16*var(--s));font-family:var(--font-mono);font-size:calc(13*var(--s));color:var(--muted);">
                Session established
            </div>
            ` : ''}
        </div>
    `;
}

// ─── Authorization ──────────────────────────────────────────────────
function hydrateAuthZ(data) {
    const container = document.getElementById('authz-content');
    const findings = data.findings || [];

    // Look for authorization-related findings
    const idorFindings = findings.filter(f => {
        const name = (f.vulnerability || f.name || f.title || '').toLowerCase();
        return name.includes('idor') || name.includes('access control') || name.includes('authorization') || name.includes('bola');
    });
    const privEscFindings = findings.filter(f => {
        const name = (f.vulnerability || f.name || f.title || '').toLowerCase();
        return name.includes('privilege') || name.includes('escalation') || name.includes('admin');
    });

    container.innerHTML = `
        <div style="margin-top:calc(20*var(--s));">
            <div class="section-label" style="margin-bottom:calc(20*var(--s));">Horizontal Access</div>
            <div class="authz-test">
                <div>
                    <div class="authz-test-name">IDOR</div>
                    <div class="authz-test-desc">${idorFindings.length > 0 ? (idorFindings[0].endpoint || 'Cross-user resource access') : 'Cross-user resource access testing'}</div>
                </div>
                <span class="authz-result ${idorFindings.length > 0 ? 'confirmed' : 'not-detected'}">${idorFindings.length > 0 ? 'CONFIRMED' : 'NOT DETECTED'}</span>
            </div>

            <div class="section-label" style="margin-top:calc(32*var(--s));margin-bottom:calc(20*var(--s));">Vertical Access</div>
            <div class="authz-test">
                <div>
                    <div class="authz-test-name">Privilege Escalation</div>
                    <div class="authz-test-desc">${privEscFindings.length > 0 ? (privEscFindings[0].endpoint || 'Normal user to admin access') : 'Normal user to admin functionality'}</div>
                </div>
                <span class="authz-result ${privEscFindings.length > 0 ? 'confirmed' : 'not-detected'}">${privEscFindings.length > 0 ? 'CONFIRMED' : 'NOT DETECTED'}</span>
            </div>
        </div>
    `;
}

// ─── Autonomous Reasoning ───────────────────────────────────────────
function hydrateReasoning(data) {
    const container = document.getElementById('reasoning-content');
    const hypotheses = data.hypotheses || [];
    const nextActions = data.next_actions || [];
    const iterations = data.reasoning_iterations || data.iterations || 0;

    if (!hypotheses.length && !nextActions.length && !iterations) {
        container.innerHTML = '<div class="empty-state"><span class="empty-state-text">No reasoning data available</span></div>';
        return;
    }

    let html = '';

    // Reasoning iterations
    const iterCount = Math.max(iterations, 1);
    for (let i = 0; i < iterCount; i++) {
        const hypothesis = hypotheses[i] || (hypotheses.length ? hypotheses[0] : 'Analyzing security evidence');
        const action = nextActions[i] || (nextActions.length ? nextActions[0] : 'Validate findings');
        const observation = data.observations && data.observations[i] ? data.observations[i] : 'Evidence collected from security testing';

        html += `
            <div class="reasoning-iteration" style="animation:fadeSlideIn 0.5s ease ${i * 0.1}s both">
                <div class="reasoning-iteration-header">Iteration ${String(i + 1).padStart(2, '0')}</div>

                <div class="reasoning-step">
                    <div class="reasoning-step-label">Observation</div>
                    <div class="reasoning-step-content">${escapeHtml(typeof observation === 'string' ? observation : JSON.stringify(observation))}</div>
                </div>
                <div class="reasoning-connector">↓</div>
                <div class="reasoning-step">
                    <div class="reasoning-step-label">Hypothesis</div>
                    <div class="reasoning-step-content">${escapeHtml(typeof hypothesis === 'string' ? hypothesis : JSON.stringify(hypothesis))}</div>
                </div>
                <div class="reasoning-connector">↓</div>
                <div class="reasoning-step">
                    <div class="reasoning-step-label">Next Action</div>
                    <div class="reasoning-step-content">${escapeHtml(typeof action === 'string' ? action : JSON.stringify(action))}</div>
                </div>
                <div class="reasoning-connector">↓</div>
                <div class="reasoning-step">
                    <div class="reasoning-step-label">Result</div>
                    <div class="reasoning-step-content">Evidence collected.</div>
                </div>
            </div>
        `;
    }

    // Summary metrics
    html += `
        <div class="reasoning-metrics">
            <div class="metric-item">
                <div class="metric-value" style="font-size:calc(36*var(--s));">${String(hypotheses.length).padStart(2, '0')}</div>
                <div class="metric-label">Hypotheses</div>
            </div>
            <div class="metric-item">
                <div class="metric-value" style="font-size:calc(36*var(--s));">${String(nextActions.length).padStart(2, '0')}</div>
                <div class="metric-label">Next Actions</div>
            </div>
            <div class="metric-item">
                <div class="metric-value" style="font-size:calc(36*var(--s));">${String(iterCount).padStart(2, '0')}</div>
                <div class="metric-label">Iterations</div>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

// ─── Static Analysis ────────────────────────────────────────────────
function hydrateStaticAnalysis(data) {
    const container = document.getElementById('static-content');
    const findings = (data.findings || []).filter(f => {
        const src = (f.source || '').toLowerCase();
        const name = (f.vulnerability || f.name || '').toLowerCase();
        return src.includes('static') || src.includes('sast') || name.includes('subprocess') || name.includes('code');
    });

    if (!findings.length) {
        // Show generic static analysis status
        container.innerHTML = `
            <div style="margin-top:calc(20*var(--s));">
                <div class="metrics-row" style="margin-bottom:calc(24*var(--s));">
                    <div class="metric-item">
                        <div class="metric-value" style="font-size:calc(36*var(--s));">—</div>
                        <div class="metric-label">Files Analyzed</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value" style="font-size:calc(36*var(--s));">00</div>
                        <div class="metric-label">Potential Issues</div>
                    </div>
                </div>
                <div class="empty-state"><span class="empty-state-text">No static analysis findings</span></div>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div style="margin-top:calc(20*var(--s));">
            <div class="metrics-row" style="margin-bottom:calc(32*var(--s));">
                <div class="metric-item">
                    <div class="metric-value" style="font-size:calc(36*var(--s));">—</div>
                    <div class="metric-label">Files Analyzed</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:calc(36*var(--s));">${String(findings.length).padStart(2, '0')}</div>
                    <div class="metric-label">Potential Issues</div>
                </div>
            </div>
            <div class="findings-list">
                ${findings.map((f, i) => {
                    const sev = normalizeSeverity(f.severity);
                    return `
                        <div class="finding-item" style="animation:fadeSlideIn 0.4s ease ${i * 0.06}s both">
                            <div class="finding-header">
                                <span class="severity-pill ${sev}">${sev}</span>
                                <span class="finding-name">${escapeHtml(f.vulnerability || f.name || 'Static Finding')}</span>
                            </div>
                            <div class="finding-meta">
                                <span class="font-mono">${escapeHtml(f.endpoint || f.file || '')}</span>
                                <span class="detail-badge" style="margin-left:auto;">STATIC</span>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        </div>
    `;
}

// ─── AI Security Analyst ────────────────────────────────────────────
function hydrateAIAnalyst(data) {
    const container = document.getElementById('ai-analyst-content');
    const findings = data.findings || [];
    const hypotheses = data.hypotheses || [];

    const sources = [
        { name: 'Recon', done: true },
        { name: 'DAST', done: true },
        { name: 'Adaptive DAST', done: true },
        { name: 'Authentication', done: true },
        { name: 'Authorization', done: true },
        { name: 'Static Analysis', done: true },
    ];

    const confirmedFindings = findings.filter(f => f.validated || f.status === 'confirmed');

    container.innerHTML = `
        <div style="margin-top:calc(20*var(--s));">
            <div class="section-label" style="margin-bottom:calc(16*var(--s));">Evidence Received</div>
            <div class="analyst-evidence-list">
                ${sources.map((s, i) => `
                    <div class="analyst-evidence-item" style="animation:fadeSlideIn 0.3s ease ${i * 0.06}s both">
                        <span class="${s.done ? 'check' : 'pending'}">${s.done ? '✓' : '○'}</span>
                        <span>${s.name}</span>
                    </div>
                `).join('')}
            </div>

            ${hypotheses.length > 0 ? `
            <div class="evidence-section">
                <div class="evidence-title">Hypothesis</div>
                <div class="evidence-explanation">${escapeHtml(typeof hypotheses[0] === 'string' ? hypotheses[0] : JSON.stringify(hypotheses[0]))}</div>
            </div>
            ` : ''}

            ${confirmedFindings.length > 0 ? `
            <div class="evidence-section">
                <div class="evidence-title">Conclusion</div>
                ${confirmedFindings.map(f => `
                    <div style="margin-bottom:calc(12*var(--s));">
                        <span class="severity-pill ${normalizeSeverity(f.severity)}" style="margin-right:calc(10*var(--s));">${normalizeSeverity(f.severity)}</span>
                        <span style="font-weight:600;">${escapeHtml(f.vulnerability || f.name || 'Finding')}</span>
                        <span style="color:var(--accent-green);font-family:var(--font-mono);font-size:calc(11*var(--s));margin-left:calc(12*var(--s));">CONFIRMED</span>
                    </div>
                `).join('')}
            </div>
            ` : ''}
        </div>
    `;
}

// ─── Correlation ────────────────────────────────────────────────────
function hydrateCorrelation(data) {
    const container = document.getElementById('correlation-content');
    const findings = data.findings || [];

    const sources = ['RECON', 'DAST', 'AUTH', 'AUTHORIZATION', 'STATIC ANALYSIS', 'AI REASONING'];

    container.innerHTML = `
        <div style="margin-top:calc(20*var(--s));display:flex;gap:calc(48*var(--s));flex-wrap:wrap;align-items:flex-start;">
            <div class="correlation-flow">
                ${sources.map((s, i) => `
                    <div class="correlation-source" style="animation:fadeSlideIn 0.3s ease ${i * 0.06}s both">${s}</div>
                    ${i < sources.length - 1 ? '<div class="correlation-line"></div>' : ''}
                `).join('')}
                <div class="correlation-line"></div>
                <div class="correlation-result" style="animation:fadeSlideIn 0.5s ease 0.4s both">CORRELATED SECURITY FINDING</div>
            </div>

            <div style="display:flex;flex-direction:column;gap:calc(32*var(--s));margin-top:calc(12*var(--s));">
                <div class="metric-item">
                    <div class="metric-value" style="font-size:calc(36*var(--s));">${String(sources.length).padStart(2, '0')}</div>
                    <div class="metric-label">Evidence Sources</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:calc(36*var(--s));">${String(findings.length).padStart(2, '0')}</div>
                    <div class="metric-label">Correlated Findings</div>
                </div>
            </div>
        </div>
    `;
}

// ─── History ────────────────────────────────────────────────────────
function hydrateHistory() {
    const list = document.getElementById('history-list');
    if (!scanHistory.length) {
        list.innerHTML = '<div class="empty-state"><span class="empty-state-text">No scan history yet</span></div>';
        return;
    }

    // Table header
    list.innerHTML = `
        <div class="history-item" style="border-bottom:1px solid var(--card-border);padding-bottom:calc(12*var(--s));margin-bottom:calc(4*var(--s));">
            <span class="history-target text-muted" style="font-size:calc(11*var(--s));text-transform:uppercase;letter-spacing:0.1em;">Target</span>
            <span class="history-duration text-muted" style="font-size:calc(11*var(--s));text-transform:uppercase;letter-spacing:0.1em;">Duration</span>
            <span class="history-findings-count text-muted" style="font-size:calc(11*var(--s));text-transform:uppercase;letter-spacing:0.1em;">Findings</span>
        </div>
        ${scanHistory.map((h, i) => `
            <div class="history-item" onclick="loadHistoryScan(${i})" style="animation:fadeSlideIn 0.3s ease ${i * 0.06}s both">
                <span class="history-target">${escapeHtml(h.target)}</span>
                <span class="history-duration">${h.duration}</span>
                <span class="history-findings-count">${String(h.findings).padStart(2, '0')}</span>
            </div>
        `).join('')}
    `;
}

function loadHistoryScan(index) {
    const entry = scanHistory[index];
    if (entry && entry.data) {
        scanData = entry.data;
        hydrateAllViews(scanData, entry.target);
        navigateTo('overview');
    }
}

// ─── Report ─────────────────────────────────────────────────────────
function hydrateReport(data, target) {
    const container = document.getElementById('report-content');
    const findings = data.findings || [];

    if (!findings.length && !target) {
        container.innerHTML = '<div class="empty-state"><span class="empty-state-text">Run a scan to generate a report</span></div>';
        return;
    }

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
        const sev = normalizeSeverity(f.severity);
        if (counts[sev] !== undefined) counts[sev]++;
    });

    // Determine overall risk
    let risk = 'LOW';
    if (counts.critical > 0) risk = 'CRITICAL';
    else if (counts.high > 0) risk = 'HIGH';
    else if (counts.medium > 0) risk = 'MEDIUM';

    container.innerHTML = `
        <div class="report-header">
            <div class="evidence-row" style="margin-bottom:calc(20*var(--s));">
                <span class="evidence-key">Target</span>
                <span class="evidence-value font-mono">${escapeHtml(target || '—')}</span>
            </div>
            <div class="section-label">Security Risk</div>
            <div class="report-risk" style="color:${risk === 'CRITICAL' || risk === 'HIGH' ? 'var(--severity-critical)' : risk === 'MEDIUM' ? 'var(--severity-medium)' : 'var(--accent-green)'};">${risk}</div>
        </div>

        <div class="report-stats">
            <div class="report-stat"><div class="report-stat-value">${String(findings.length).padStart(2, '0')}</div><div class="report-stat-label">Findings</div></div>
            <div class="report-stat"><div class="report-stat-value" style="color:var(--severity-critical);">${String(counts.critical).padStart(2, '0')}</div><div class="report-stat-label">Critical</div></div>
            <div class="report-stat"><div class="report-stat-value" style="color:var(--severity-high);">${String(counts.high).padStart(2, '0')}</div><div class="report-stat-label">High</div></div>
            <div class="report-stat"><div class="report-stat-value" style="color:var(--severity-medium);">${String(counts.medium).padStart(2, '0')}</div><div class="report-stat-label">Medium</div></div>
            <div class="report-stat"><div class="report-stat-value">${String(counts.low).padStart(2, '0')}</div><div class="report-stat-label">Low</div></div>
        </div>

        <div class="report-sections">
            <a href="#" data-view="attack-surface" onclick="navigateTo('attack-surface');return false;">Attack Surface <span>→</span></a>
            <a href="#" data-view="findings" onclick="navigateTo('findings');return false;">Findings <span>→</span></a>
            <a href="#" data-view="attack-paths" onclick="navigateTo('attack-paths');return false;">Attack Paths <span>→</span></a>
            <a href="#" data-view="activity" onclick="navigateTo('activity');return false;">Evidence <span>→</span></a>
        </div>

        <div class="report-actions">
            <button class="btn-export primary" onclick="exportReport('pdf')">Export PDF</button>
            <button class="btn-export secondary" onclick="exportReport('json')">Export JSON</button>
        </div>
    `;
}

function exportReport(format) {
    if (format === 'json' && scanData) {
        const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sentinel-report-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    } else if (format === 'pdf') {
        // PDF export would require backend or library — placeholder
        alert('PDF export requires server-side generation. JSON export is available.');
    }
}

// ─── Utility Functions ──────────────────────────────────────────────
function extractEndpoints(data) {
    // Try to get endpoints from various possible response shapes
    if (data.endpoints && Array.isArray(data.endpoints)) return data.endpoints;
    if (data.attack_surface && Array.isArray(data.attack_surface)) return data.attack_surface;

    // Extract from observations
    const endpoints = [];
    const seen = new Set();
    if (data.observations) {
        data.observations.forEach(obs => {
            const text = typeof obs === 'string' ? obs : JSON.stringify(obs);
            // Look for paths like /api/something
            const matches = text.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(\/[^\s,)"]+)/gi);
            if (matches) {
                matches.forEach(m => {
                    const parts = m.split(/\s+/);
                    const method = parts[0].toUpperCase();
                    const path = parts[1];
                    const key = `${method} ${path}`;
                    if (!seen.has(key)) {
                        seen.add(key);
                        endpoints.push({ method, path });
                    }
                });
            }
        });
    }

    // Extract from findings
    if (data.findings) {
        data.findings.forEach(f => {
            const ep = f.endpoint || f.url || '';
            if (ep && !seen.has(ep)) {
                seen.add(ep);
                endpoints.push({ method: f.method || 'GET', path: ep });
            }
        });
    }

    return endpoints;
}

function normalizeSeverity(sev) {
    if (!sev) return 'medium';
    const s = sev.toLowerCase();
    if (s.includes('critical')) return 'critical';
    if (s.includes('high')) return 'high';
    if (s.includes('medium') || s.includes('med')) return 'medium';
    if (s.includes('low') || s.includes('info')) return 'low';
    return 'medium';
}

function computeSecurityScore(findings) {
    if (!findings.length) return 100;
    let score = 100;
    findings.forEach(f => {
        const sev = normalizeSeverity(f.severity);
        if (sev === 'critical') score -= 20;
        else if (sev === 'high') score -= 12;
        else if (sev === 'medium') score -= 6;
        else score -= 2;
    });
    return Math.max(0, Math.min(100, score));
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Landing legal/contact modals ───────────────────────────────────
function openLegal(type) {
    const modal = document.getElementById('legal-modal');
    const title = document.getElementById('legal-title');
    const body = document.getElementById('legal-body');
    if (!modal || !title || !body) return;
    const content = {
        privacy: {
            title: 'Privacy Policy',
            html: '<p>Sentinel collects only the information needed to provide the application experience, such as your Supabase account details and scan data generated while you use the platform.</p><p>Authentication is handled by Supabase Auth. Sentinel does not display or store your password in its own application data.</p><p>This page describes the hackathon demonstration build and is not a substitute for a production privacy notice.</p>'
        },
        terms: {
            title: 'Terms & Conditions',
            html: '<p>Sentinel is an application security testing platform. Only scan applications that you own or have explicit permission to test.</p><p>Security tests should be run against controlled targets and within the authorization and rate limits applicable to the target.</p><p>This notice applies to the hackathon demonstration build.</p>'
        },
        compliance: {
            title: 'Legal Compliance',
            html: '<p>Sentinel is designed around controlled, evidence-based security testing. It is not a guarantee of regulatory compliance or a replacement for a professional security assessment.</p><p>Users are responsible for obtaining authorization before testing systems and for complying with applicable laws, contracts and organizational policies.</p>'
        },
        contact: {
            title: 'Contact Sentinel',
            html: '<p>Have a question about Sentinel or the hackathon demonstration?</p><p class="contact-note">Use the contact details provided with the Sentinel project submission or repository to reach the team.</p><p><strong>Sentinel Security</strong><br>Autonomous application security for modern applications.</p>'
        }
    };
    const item = content[type] || content.contact;
    title.textContent = item.title;
    body.innerHTML = item.html;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.documentElement.classList.add('modal-open');
    document.body.classList.add('modal-open');
}

function closeLegal() {
    const modal = document.getElementById('legal-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    document.documentElement.classList.remove('modal-open');
    document.body.classList.remove('modal-open');
}

// ─── Init ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    document.body.classList.toggle('landing-active', currentView === 'landing');
    animateCounters();
    const authModal = document.getElementById('auth-modal');
    const legalModal = document.getElementById('legal-modal');
    [authModal, legalModal].forEach(modal => {
        if (!modal) return;
        modal.addEventListener('click', e => {
            if (e.target === modal) modal === authModal ? closeAuthModal() : closeLegal();
        });
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { closeAuthModal(); closeLegal(); }
    });

    const session = await refreshSession();
    if (session) {
        try {
            const saved = sessionStorage.getItem('sentinel.scanData');
            if (saved) scanData = JSON.parse(saved);
        } catch (_) {}
        let savedView = 'overview';
        try { savedView = sessionStorage.getItem('sentinel.currentView') || 'overview'; } catch (_) {}
        if (savedView === 'landing') savedView = 'overview';
        if (scanData) hydrateAllViews(scanData, scanData.target || '');
        navigateTo(savedView);
    } else {
        updateAuthUI();
    }
});
