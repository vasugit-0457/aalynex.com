// Each login/logout invalidates callbacks and in-flight sync from the previous session.
window._accountSessionEpoch = window._accountSessionEpoch || 0;
function cleanupAccountRealtime() {
  if (window.axChatV2?.enabled) { try { window.axChatV2.cleanup(); } catch (_) {} }
  clearTimeout(window._rtProjTimer);
  window._rtProjTimer = null;
  if (typeof stopChatPolling === 'function') stopChatPolling();
  const channels = [window._accountMasterChannel,
    typeof currentChatChannel !== 'undefined' ? currentChatChannel : null];
  window._accountMasterChannel = null;
  window.realtimeInitialized = false;
  if (typeof currentChatChannel !== 'undefined') currentChatChannel = null;
  if (typeof currentConversationId !== 'undefined') currentConversationId = null;
  if (typeof currentChatUserId !== 'undefined') currentChatUserId = null;
  if (typeof isSubscribing !== 'undefined') isSubscribing = false;
  if (typeof onlineUsers !== 'undefined') onlineUsers.clear();
  if (typeof renderedMessageIds !== 'undefined') renderedMessageIds.clear();
  for (const channel of new Set(channels.filter(Boolean))) {
    try { Promise.resolve(supaClient.removeChannel(channel)).catch(() => {}); } catch (_) {}
  }
}

// ═══════════════════════════════════════════════
//  AUTH — login / signup / OTP, loginSuccess (+ realtime), logout
// ═══════════════════════════════════════════════

let loginRole = 'creator', signupRole = 'creator';

function switchTab(t) {
  document.getElementById('form-login').style.display  = t === 'login'  ? '' : 'none';
  document.getElementById('form-signup').style.display = t === 'signup' ? '' : 'none';
  document.getElementById('tab-login').className  = 'auth-tab' + (t === 'login'  ? ' active' : '');
  document.getElementById('tab-signup').className = 'auth-tab' + (t === 'signup' ? ' active' : '');
  document.getElementById('login-err').style.display  = 'none';
  document.getElementById('signup-err').style.display = 'none';
}
function setLRole(r) {
  loginRole = r;
  document.getElementById('lr-c').className = 'role-btn' + (r === 'creator'    ? ' ac' : '');
  document.getElementById('lr-f').className = 'role-btn' + (r === 'freelancer' ? ' af' : '');
}
function setSRole(r) {
  signupRole = r;
  document.getElementById('sr-c').className = 'role-btn' + (r === 'creator'    ? ' ac' : '');
  document.getElementById('sr-f').className = 'role-btn' + (r === 'freelancer' ? ' af' : '');
  document.getElementById('su-creator-extra').style.display = r === 'creator' ? '' : 'none';
}
function setBtn(id, loading, text) {
  const btn = document.getElementById(id);
  if (!btn) return;
  if (loading) {
    if (!btn.dataset.origText) btn.dataset.origText = btn.innerHTML;
    btn.classList.add('btn-loading'); btn.disabled = true; btn.textContent = text || '...';
  } else {
    btn.classList.remove('btn-loading'); btn.disabled = false;
    if (btn.dataset.origText) { btn.innerHTML = btn.dataset.origText; delete btn.dataset.origText; }
  }
}

// Account onboarding V2: explicit success gates; passwords stay in JS memory only.
const AX_AUTH_MIN_PASSWORD_LENGTH = 12;
let _signupVerifiedUserId = null;
let _signupPasswordApplied = false;
let _signupRecoveryUserId = null;
let _signupStage = 'start'; // start | otp | verified
let _signupBusy = false;
let _signupResendUntil = 0;
let _signupResendTicker = null;
let _signupResendBusy = false;

function axPasswordIssue(value) {
  const password = String(value || '');
  if (password.length < AX_AUTH_MIN_PASSWORD_LENGTH)
    return 'Use at least 12 characters for your password.';
  if (!password.trim() || /^(.)\1{11,}$/.test(password))
    return 'Choose a unique password or long passphrase.';
  return '';
}
function axUpdatePasswordStrength() {
  const field = document.getElementById('su-pw');
  const output = document.getElementById('su-pw-strength');
  if (!field || !output) return;
  const pw = field.value;
  const groups = [/[a-z]/.test(pw), /[A-Z]/.test(pw), /\d/.test(pw), /[^a-zA-Z0-9]/.test(pw)]
    .filter(Boolean).length;
  const strength = !pw || pw.length < 12 ? 'weak'
    : pw.length >= 16 && groups >= 3 ? 'strong' : 'fair';
  output.dataset.strength = strength;
  output.textContent = !pw ? 'Use at least 12 characters. A unique passphrase works well.'
    : axPasswordIssue(pw) || (strength === 'strong'
      ? 'Strong length and character variety.'
      : 'Good length. A longer unique passphrase is even better.');
}
function toggleAuthPassword(inputId, button) {
  const input = document.getElementById(inputId);
  if (!input || !button) return;
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  button.textContent = show ? 'Hide' : 'Show';
  button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  button.setAttribute('aria-pressed', String(show));
}
function axAuthSignupError(message) {
  const err = document.getElementById('signup-err');
  if (!err) return;
  err.textContent = message;
  err.style.display = 'flex';
}
function axAuthSignupInput() {
  const name = document.getElementById('su-name').value.trim();
  const phoneRaw = document.getElementById('su-phone').value.trim();
  const email = document.getElementById('su-email').value.trim().toLowerCase();
  const pw = document.getElementById('su-pw').value;
  const pw2 = document.getElementById('su-pw2').value;
  const profession = document.getElementById('su-profession').value;
  const platform = document.getElementById('su-platform')?.value || '';
  if (name.length < 2) throw Error('Enter your full name (at least 2 characters).');
  if (!validateEmailFmt(email)) throw Error('Enter a valid email address.');
  const issue = axPasswordIssue(pw);
  if (issue) throw Error(issue);
  if (pw !== pw2) throw Error('The confirmation password does not match.');
  let phone = '';
  if (phoneRaw) {
    const result = validatePhone(phoneRaw);
    if (!result.ok) throw Error(result.msg);
    phone = result.phone;
  }
  return { name, phone, email, pw, profession, platform, role: signupRole };
}
function axSetSignupButton() {
  const btn = document.getElementById('signup-btn');
  if (!btn) return;
  if (_signupStage === 'start') {
    btn.textContent = 'Create Account →';
    btn.onclick = doSignup;
  } else {
    btn.textContent = _signupStage === 'otp' ? 'Verify & Create Account' : 'Complete Account';
    btn.onclick = doSignupVerifyOTP;
  }
}
function axUpdateSignupResendButton() {
  const btn = document.getElementById('signup-resend-btn');
  if (!btn) return;
  const seconds = Math.max(0, Math.ceil((_signupResendUntil - Date.now()) / 1000));
  btn.disabled = _signupResendBusy || seconds > 0;
  btn.textContent = seconds > 0 ? 'Resend code in ' + seconds + 's' : 'Resend code';
  if (!seconds && _signupResendTicker) {
    clearInterval(_signupResendTicker);
    _signupResendTicker = null;
  }
}
function axStartSignupResendCooldown() {
  _signupResendUntil = Date.now() + 60000;
  if (_signupResendTicker) clearInterval(_signupResendTicker);
  axUpdateSignupResendButton();
  _signupResendTicker = setInterval(axUpdateSignupResendButton, 1000);
}
function axRenderSignupOTP() {
  if (document.getElementById('signup-otp-fg')) return;
  const el = document.createElement('div');
  el.className = 'fg';
  el.id = 'signup-otp-fg';
  el.innerHTML = '<label for="signup-otp">6-digit verification code</label>' +
    '<input id="signup-otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" ' +
    'autocomplete="one-time-code" placeholder="Enter your 6-digit code"/>' +
    '<div class="ax-auth-otp-actions"><span>Check your inbox and spam folder.</span>' +
    '<button type="button" class="ax-auth-otp-resend" id="signup-resend-btn" ' +
    'onclick="resendSignupOTP()">Resend code</button></div>' +
    '<div class="ax-auth-otp-notice" id="signup-resend-note" role="status"></div>';
  const btn = document.getElementById('signup-btn');
  btn.parentElement.insertBefore(el, btn);
}
async function resendSignupOTP() {
  if (_signupBusy || _signupResendBusy || _signupStage !== 'otp' ||
      !_signupOtpData.email || Date.now() < _signupResendUntil) return;
  _signupResendBusy = true;
  axUpdateSignupResendButton();
  const label = document.getElementById('signup-resend-note');
  if (label) label.textContent = '';
  try {
    const { error } = await supaClient.auth.signInWithOtp({
      email: _signupOtpData.email, options: { shouldCreateUser: false }
    });
    if (error) throw error;
    axStartSignupResendCooldown();
    if (label) label.textContent = 'New code requested. Check your email.';
  } catch (_) {
    if (label) label.textContent = 'Could not resend now. Please try again shortly.';
    _signupResendUntil = Date.now() + 15000;
  } finally {
    _signupResendBusy = false;
    axUpdateSignupResendButton();
  }
}
// Recover an email-verified Supabase user that has no Aalynex profile.
// No guessed role/profile record is automatically created.
function showVerifiedSignupRecovery(user) {
  if (!user?.id || !user.email || !user.email_confirmed_at) return false;
  _signupRecoveryUserId = user.id;
  _signupVerifiedUserId = user.id;
  _signupPasswordApplied = false;
  _signupOtpData = {};
  _signupStage = 'start';
  showScreen('screen-auth');
  switchTab('signup');
  const email = document.getElementById('su-email');
  email.value = user.email;
  email.readOnly = true;
  const note = document.getElementById('su-recovery-note');
  note.textContent = 'Your email is already verified, but account setup is incomplete. ' +
    'Choose your role, enter your details and set a new password to finish safely.';
  note.style.display = 'block';
  const metaRole = user.user_metadata?.role;
  setSRole(metaRole === 'freelancer' ? 'freelancer' : 'creator');
  if (typeof user.user_metadata?.name === 'string')
    document.getElementById('su-name').value = user.user_metadata.name;
  axSetSignupButton();
  return true;
}

async function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const pw = document.getElementById('login-pw').value;
  const errEl = document.getElementById('login-err');
  errEl.style.display = 'none';

  if (!email || !pw) {
    errEl.textContent = 'Please fill in all fields.';
    errEl.style.display = 'flex'; return;
  }
  if (!validateEmailFmt(email)) {
    errEl.textContent = 'Please enter a valid email address.';
    errEl.style.display = 'flex'; return;
  }

  setBtn('login-btn', true, 'Logging in...');

  function loginFail(msg) {
    setBtn('login-btn', false);
    errEl.textContent = msg || 'Invalid credentials.';
    errEl.style.display = 'flex';
    document.getElementById('login-pw').value = '';
  }

  if (!supaClient) {
    loginFail('Login requires a connection. Please try again.');
    return;
  }

  try {
    const { data, error } = await supaClient.auth.signInWithPassword({ email, password: pw });

    if (error || !data.user) {
      loginFail('Invalid email or password.');
      return;
    }

    if (!data.user.email_confirmed_at) {
      await supaClient.auth.signOut();
      loginFail('Please verify your email before logging in.');
      return;
    }

    const { data: profile, error: pErr } = await supaClient
      .from('profiles').select(AX_PROFILE_PUBLIC_FIELDS).eq('id', data.user.id).single();

    if (pErr || !profile) {
      await supaClient.auth.signOut();
      loginFail('Invalid credentials.');
      return;
    }

    if (profile.role !== loginRole) {
      await supaClient.auth.signOut();
      loginFail('Invalid credentials.');
      return;
    }

    let ownPhone = '';
    try { ownPhone = await axGetOwnPhone(); } catch (e) { console.warn('Own phone unavailable', e); }
    const u = {
      id: profile.id,
      name: profile.name || email.split('@')[0],
      email: data.user.email,
      phone: ownPhone,
      role: profile.role,
      profession: profile.profession || '',
      platform: profile.platform || '',
      avatar: (profile.name || email).charAt(0).toUpperCase(),
      createdAt: new Date(profile.created_at).getTime(),
      skills: profile.skills || [],
      portfolio_links: profile.portfolio_links || {},
      resume_url: profile.resume_url || '',
      photo_url: profile.photo_url || '',
      experience: profile.experience || [],
      upiId: profile.upi_id || '',
      bankAccountName: profile.bank_account_name || '',
      bankAccountNumber: profile.bank_account_number || '',
      ifscCode: profile.ifsc_code || ''
    };

    setBtn('login-btn', false);
    loginSuccess(u);
    showToast(`Welcome back, ${u.name.split(' ')[0]}!`, 'ok', '👋');
  } catch (e) {
    console.warn('Login error', e);
    loginFail('Login failed. Please check your connection and try again.');
  }
}

// Initial step: create an OTP challenge; never mark the account ready yet.
async function doSignup() {
  if (_signupBusy) return;
  const errEl = document.getElementById('signup-err');
  errEl.style.display = 'none';
  let fields;
  try { fields = axAuthSignupInput(); }
  catch (e) { axAuthSignupError(e.message); return; }
  if (!supaClient) { axAuthSignupError('Signup requires an internet connection.'); return; }

  _signupBusy = true;
  setBtn('signup-btn', true, 'Checking account...');
  try {
    // A verified account without a profile can safely resume onboarding.
    // Never let an existing profile be overwritten or its role changed here.
    const { data: { user } } = await supaClient.auth.getUser();
    if (user?.email_confirmed_at) {
      if (String(user.email || '').toLowerCase() !== fields.email)
        throw Error('You are signed in to another email. Please log out before signing up.');
      const { data: profile, error: lookupError } = await supaClient.from('profiles')
        .select('id,role').eq('id', user.id).maybeSingle();
      if (lookupError) throw Error('Could not check account. Try again.');
      if (profile) throw Error('This email already has an account. Please use Login.');
      _signupVerifiedUserId = user.id;
      _signupRecoveryUserId = user.id;
      _signupPasswordApplied = false;
      _signupOtpData = fields;
      _signupStage = 'verified';
      await axFinishVerifiedSignup();
      return;
    }

    // Send email OTP before creating profile or setting a password.
    _signupOtpData = fields;
    _signupVerifiedUserId = null;
    _signupPasswordApplied = false;
    setBtn('signup-btn', true, 'Sending verification code...');
    const { error } = await supaClient.auth.signInWithOtp({
      email: fields.email, options: { shouldCreateUser: true }
    });
    if (error) {
      if (/rate limit|too many/i.test(error.message || ''))
        throw Error('Too many requests. Please try again shortly.');
      throw Error('Could not send verification code. Check your email and try again.');
    }
    _signupStage = 'otp';
    axRenderSignupOTP();
    axStartSignupResendCooldown();
    document.getElementById('signup-otp')?.focus();
  } catch (e) {
    axAuthSignupError(e.message || 'Could not start signup. Please try again.');
  } finally {
    _signupBusy = false;
    setBtn('signup-btn', false);
    axSetSignupButton();
  }
}

async function axFinishVerifiedSignup() {
  if (!_signupVerifiedUserId || !_signupOtpData.email)
    throw Error('Verification session expired. Please restart signup.');
  // Validate again at finalization; users may edit fields after requesting OTP.
  const fields = axAuthSignupInput();
  if (fields.email !== _signupOtpData.email)
    throw Error('Email changed after verification. Please restart signup.');
  if (_signupStage === 'verified' && fields.role !== _signupOtpData.role)
    throw Error('Role changed after verification. Select the original role or restart signup.');

  const { data: { user }, error: userError } = await supaClient.auth.getUser();
  if (userError || !user || user.id !== _signupVerifiedUserId ||
      !user.email_confirmed_at ||
      String(user.email || '').toLowerCase() !== fields.email)
    throw Error('Your verified session expired. Please verify your email again.');

  // Avoid ever changing an existing account through the signup form.
  const { data: existing, error: lookupError } = await supaClient.from('profiles')
    .select('id,role').eq('id', user.id).maybeSingle();
  if (lookupError) throw Error('Could not check profile. Please retry.');
  if (existing) throw Error('Account is already set up. Please log in.');

  if (!_signupPasswordApplied) {
    const { error: pwError } = await supaClient.auth.updateUser({
      password: fields.pw,
      data: {
        name: fields.name,
        phone: fields.phone,
        role: fields.role, // Display metadata only; DB profile.role is authoritative.
        profession: fields.profession,
        platform: fields.platform
      }
    });
    if (pwError) throw Error(pwError.message || 'Password could not be saved. Try again.');
    _signupPasswordApplied = true;
  }

  // INSERT only; never UPSERT over an established profile/account role.
  const { data: profile, error: profileError } = await supaClient.from('profiles')
    .insert({
      id: user.id, name: fields.name, phone: fields.phone, role: fields.role,
      profession: fields.profession, platform: fields.platform,
      avatar: fields.name.charAt(0).toUpperCase()
    }).select('id,role').single();
  if (profileError || !profile || profile.id !== user.id || profile.role !== fields.role)
    throw Error('Email verified, but profile setup is incomplete. Click Complete Account to retry.');

  const u = {
    id: profile.id, name: fields.name, email: fields.email, phone: fields.phone,
    role: profile.role, profession: fields.profession, platform: fields.platform,
    avatar: fields.name.charAt(0).toUpperCase(), createdAt: Date.now(),
    skills: [], portfolio_links: {}, resume_url: '', photo_url: '', experience: []
  };

  // Login only after BOTH password and server-backed profile have succeeded.
  const users = DB.users();
  if (!users.find(x => x.id === u.id)) users.push({ ...u });
  DB.saveUsers(users);
  _resetSignupForm();
  loginSuccess(u);
  showToast('Your Aalynex account is ready!', 'ok', '');
}

async function doSignupVerifyOTP() {
  if (_signupBusy) return;
  const errEl = document.getElementById('signup-err');
  errEl.style.display = 'none';
  if (_signupStage !== 'verified') {
    const otp = (document.getElementById('signup-otp')?.value || '').trim();
    if (!/^\d{6}$/.test(otp)) {
      axAuthSignupError('Enter the 6-digit verification code.');
      return;
    }
    if (!_signupOtpData?.email) {
      axAuthSignupError('Your signup details expired. Please restart signup.');
      return;
    }
  }
  _signupBusy = true;
  setBtn('signup-btn', true, 'Verifying account...');
  try {
    if (_signupStage !== 'verified') {
      const token = document.getElementById('signup-otp').value.trim();
      const { data, error } = await supaClient.auth.verifyOtp({
        email: _signupOtpData.email, token, type: 'email'
      });
      if (error || !data?.user) {
        document.getElementById('signup-otp').value = '';
        throw Error('Invalid or expired code. Check your email or resend.');
      }
      _signupVerifiedUserId = data.user.id;
      _signupStage = 'verified';
    }
    await axFinishVerifiedSignup();
  } catch (e) {
    axAuthSignupError(e.message || 'Account setup failed. Please retry.');
  } finally {
    _signupBusy = false;
    setBtn('signup-btn', false);
    axSetSignupButton();
  }
}

function _resetSignupForm() {
  // Clear sensitive state on success. Never persist OTP or password in storage.
  if (_signupResendTicker) clearInterval(_signupResendTicker);
  _signupResendTicker = null;
  _signupResendUntil = 0;
  _signupVerifiedUserId = null;
  _signupRecoveryUserId = null;
  _signupPasswordApplied = false;
  _signupOtpData = {};
  _signupStage = 'start';
  const email = document.getElementById('su-email');
  if (email) email.readOnly = false;
  for (const id of ['su-pw', 'su-pw2', 'signup-otp']) {
    const field = document.getElementById(id);
    if (field) field.value = '';
  }
  const note = document.getElementById('su-recovery-note');
  if (note) note.style.display = 'none';
  document.getElementById('signup-otp-fg')?.remove();
  axUpdatePasswordStrength();
  axSetSignupButton();
}

async function loginSuccess(u) {
  const sessionEpoch = ++window._accountSessionEpoch;
  cleanupAccountRealtime();
  const ownsSession = () => window._accountSessionEpoch === sessionEpoch && CU && CU.id === u.id;
  resetPremiumSession();
  CU = u;
  DB.setCurrentUser(u);

  if (u.role === 'creator') {
    document.getElementById('c-nav-name').textContent  = u.name.split(' ')[0];
    document.getElementById('c-sb-name').textContent   = u.name;
    document.getElementById('c-sb-avatar').textContent = u.avatar || u.name.charAt(0).toUpperCase();
    document.getElementById('c-sb-role').textContent   = 'Creator · ' + (u.platform || '');
    showScreen('screen-creator');
    document.getElementById('c-main').innerHTML = `
      <div style="padding:32px 0;">
        <div style="height:28px;width:200px;background:var(--bg2);border-radius:8px;margin-bottom:24px;animation:pulse 1.5s infinite;"></div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px;">
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
        </div>
        <div style="height:18px;width:140px;background:var(--bg2);border-radius:6px;margin-bottom:12px;animation:pulse 1.5s infinite;"></div>
        <div style="height:64px;background:var(--bg2);border-radius:14px;margin-bottom:8px;animation:pulse 1.5s infinite;"></div>
        <div style="height:64px;background:var(--bg2);border-radius:14px;margin-bottom:8px;animation:pulse 1.5s infinite;"></div>
      </div>`;
  } else {
    document.getElementById('f-nav-name').textContent  = u.name.split(' ')[0];
    document.getElementById('f-sb-name').textContent   = u.name;
    document.getElementById('f-sb-avatar').textContent = u.avatar || u.name.charAt(0).toUpperCase();
    document.getElementById('f-sb-role').textContent   = 'Freelancer · ' + (u.profession || '');
    showScreen('screen-freelancer');
    document.getElementById('f-main').innerHTML = `
      <div style="padding:32px 0;">
        <div style="height:28px;width:200px;background:var(--bg2);border-radius:8px;margin-bottom:24px;animation:pulse 1.5s infinite;"></div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;">
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
          <div style="height:90px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
        </div>
        <div style="height:64px;background:var(--bg2);border-radius:14px;margin-bottom:8px;animation:pulse 1.5s infinite;"></div>
        <div style="height:64px;background:var(--bg2);border-radius:14px;animation:pulse 1.5s infinite;"></div>
      </div>`;
    if (u.photo_url) { updateAvatarsEverywhere(); }
  }

  // ⚡ FAST DASHBOARD: pehle sirf core data (profiles + projects + attachments)
  // load karo taaki dashboard TURANT dikhe. Messages + S3 signing (heavy) background me.
  await syncFromSupabase(u, { coreOnly: true });
  if (!ownsSession()) return;

  if (u.role === 'freelancer') {
    await loadFreelancerProfile();
    if (!ownsSession()) return;
    renderF('home');
    checkFProfileCompletion();
  } else {
    await loadFreelancerProfile();
    if (!ownsSession()) return;
    updateAvatarsEverywhere();
    renderC('home');
    // Mobile-to-web safe project deep link. NAVIGATION ONLY: never auto-start/charge checkout.
    try {
      const params = new URLSearchParams(window.location.search);
      const id = params.get('checkoutProject');
      if (id && /^[A-Za-z0-9_-]{1,128}$/.test(id)) {
        const project = DB.projects().find(p => String(p.id)===id &&
          String(p.creatorId)===String(u.id) && !!p.freelancerId && p.status!=='open');
        if(project && ownsSession() && typeof switchChat==='function') {
          cPage('chat',document.querySelector('#screen-creator .nav-item[data-page="chat"]'));
          setTimeout(()=>{if(ownsSession()&&currentCreatorPage==='chat')void switchChat(u.id,project.freelancerId);},30);
        } else if (ownsSession()) showToast('Project checkout link needs project verification. Open My Projects.','info','');
      }
      if (id) window.history.replaceState(null,'',window.location.pathname+window.location.hash);
    } catch (_) { /* no automatic payment action */ }
  }

  // Background: full sync (messages / chat previews) — dashboard ko block nahi karta.
  syncFromSupabase(u).then(() => {
    if (ownsSession() && typeof updateChatSidebarPreviews === 'function') updateChatSidebarPreviews();
  }).catch(() => {});

  // 🟢 MASTER REAL-TIME SYSTEM (single channel, no duplicate connections)
  if (supaClient && !window.realtimeInitialized) {
    window.realtimeInitialized = true;
    const masterChannel = supaClient.channel('aalynex_master_' + sessionEpoch + '_' + u.id);
    window._accountMasterChannel = masterChannel;
    // Opt-in V2: account-wide incoming receipts. Existing messaging listeners stay intact.
    if (window.axChatV2?.enabled) {
      masterChannel.on('postgres_changes', {
        event: 'INSERT', schema: 'public', table: 'messages',
        filter: 'receiver_id=eq.' + u.id
      }, payload => {
        if (ownsSession()) window.axChatV2.onIncoming(payload);
      });
    }

    masterChannel
      // 1. Projects
      .on('postgres_changes', { event: '*', schema: 'public', table: 'projects' }, payload => {
        if (!ownsSession()) return;
        // Debounce bursts + re-render the ACTUAL current page (globally tracked),
        // taaki Profile/Earnings dekhte waqt dashboard flash na ho.
        clearTimeout(window._rtProjTimer);
        window._rtProjTimer = setTimeout(() => {
          if (!ownsSession()) return;
          syncFromSupabase(u).then(() => {
            if (!ownsSession()) return;
            // quiet repaint: a realtime row change on ANY project fires this, so it
// must not flash the page when the visible data did not actually change
if (CU.role === 'creator' && currentCreatorPage !== 'chat') renderC(currentCreatorPage || 'home', true);
else if (CU.role === 'freelancer' && currentFreelancerPage !== 'chat') renderF(currentFreelancerPage || 'home', true);
          });
        }, 400);
      })
      // 2. Presence (online/offline)
      .on('presence', { event: 'sync' }, () => {
        if (!ownsSession()) return;
        const state = masterChannel.presenceState();
        onlineUsers.clear();
        for (const id in state) {
          if (state[id][0]?.user_id) onlineUsers.add(state[id][0].user_id);
        }
        updateChatHeaderPresence();
        if (window.axChatV2?.enabled) void window.axChatV2.refreshPresence();
      })
      // 3. Subscribe + track self
      .subscribe(async (status) => {
        if (!ownsSession()) return;
        const statusText = document.getElementById('chat-status-text');
        const dot = document.getElementById('chat-online-dot');
        if (status === 'SUBSCRIBED') {
          if (statusText) { statusText.textContent = 'Online'; statusText.style.color = 'var(--green)'; }
          if (dot) dot.style.background = 'var(--green)';
          try { await masterChannel.track({ user_id: u.id }); } catch (_) {}
        } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
          if (statusText) { statusText.textContent = 'Connecting...'; statusText.style.color = 'var(--yellow)'; }
          if (dot) dot.style.background = 'var(--yellow)';
        }
      });
  }
  if (window.axChatV2?.enabled) {
    try { window.axChatV2.onLogin(u); } catch (_) { /* Legacy auth remains usable. */ }
  }
}

function logout() {
  showModal('Log Out', 'Are you sure you want to log out?', async () => {
    ++window._accountSessionEpoch;
    cleanupAccountRealtime();
    resetPremiumSession();
    CU = null; activeManageProjectId = null; currentChatUserId = null;
    DB.logout();
    if (supaClient) {
      try { await supaClient.auth.signOut(); } catch (_) {}
    }
        showScreen('screen-landing');
    showToast('Logged out successfully', 'info', '');
  });
  document.getElementById('modal-confirm').textContent = 'Log Out';
}

/* ---- FORGOT PASSWORD (OTP based, retry-safe) ---- */
let _resetEmail = '';
let _resetVerifiedUserId = null;
let _resetBusy = false;
let _resetResendUntil = 0;
let _resetResendTicker = null;
let _resetResendBusy = false;

function axUpdateResetResend() {
  const btn = document.getElementById('reset-resend-btn');
  if (!btn) return;
  const wait = Math.max(0, Math.ceil((_resetResendUntil - Date.now()) / 1000));
  btn.disabled = _resetResendBusy || wait > 0;
  btn.textContent = wait ? 'Resend code in ' + wait + 's' : 'Resend code';
  if (!wait && _resetResendTicker) {
    clearInterval(_resetResendTicker);
    _resetResendTicker = null;
  }
}
function axStartResetResendCooldown() {
  _resetResendUntil = Date.now() + 60000;
  if (_resetResendTicker) clearInterval(_resetResendTicker);
  axUpdateResetResend();
  _resetResendTicker = setInterval(axUpdateResetResend, 1000);
}
async function resendResetOTP() {
  if (!_resetEmail || _resetBusy || _resetResendBusy || _resetVerifiedUserId ||
      Date.now() < _resetResendUntil) return;
  _resetResendBusy = true;
  axUpdateResetResend();
  try {
    const { error } = await supaClient.auth.signInWithOtp({
      email: _resetEmail, options: { shouldCreateUser: false }
    });
    if (error) throw error;
    axStartResetResendCooldown();
    const notice = document.getElementById('reset-otp-note');
    if (notice) notice.textContent = 'Code requested. Check your inbox.';
  } catch (_) {
    _resetResendUntil = Date.now() + 15000;
    const notice = document.getElementById('reset-otp-note');
    if (notice) notice.textContent = 'Please wait before requesting another code.';
  } finally {
    _resetResendBusy = false;
    axUpdateResetResend();
  }
}
async function doForgotPassword() {
  const email = document.getElementById('login-email').value.trim().toLowerCase();
  const errEl = document.getElementById('login-err');
  errEl.style.display = 'none';
  if (!validateEmailFmt(email)) {
    errEl.textContent = 'Enter your email above first, then select Forgot password.';
    errEl.style.display = 'flex'; return;
  }
  if (!supaClient) {
    errEl.textContent = 'Reset requires an internet connection.';
    errEl.style.display = 'flex'; return;
  }
  setBtn('login-btn', true, 'Sending code...');
  try {
    const { error } = await supaClient.auth.signInWithOtp({
      email, options: { shouldCreateUser: false }
    });
    if (error) {
      errEl.textContent = 'Could not request a code right now. Try again shortly.';
      errEl.style.display = 'flex'; return;
    }
    _resetEmail = email;
    _resetVerifiedUserId = null;
    const body = '<p class="ax-auth-otp-notice">Enter the 6-digit code sent to <b>' +
      escapeHtml(email) + '</b>, then choose a new password.</p>' +
      '<div class="fg"><label for="reset-otp">Verification code</label>' +
      '<input id="reset-otp" type="text" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" ' +
      'autocomplete="one-time-code" placeholder="6-digit code"/></div>' +
      '<div class="fg"><label for="reset-pw">New password</label>' +
      '<div class="ax-auth-pw-row"><input type="password" id="reset-pw" autocomplete="new-password" ' +
      'placeholder="At least 12 characters"/><button class="ax-auth-toggle-pw" type="button" ' +
      'onclick="toggleAuthPassword(\'reset-pw\',this)" aria-label="Show password">Show</button></div></div>' +
      '<div class="fg"><label for="reset-pw2">Confirm new password</label>' +
      '<div class="ax-auth-pw-row"><input type="password" id="reset-pw2" autocomplete="new-password" ' +
      'placeholder="Re-enter password"/><button type="button" class="ax-auth-toggle-pw" ' +
      'onclick="toggleAuthPassword(\'reset-pw2\',this)" aria-label="Show password">Show</button></div></div>' +
      '<div class="ax-auth-otp-actions"><span id="reset-otp-note" role="status">' +
      'Check your inbox and spam folder.</span><button class="ax-auth-otp-resend" ' +
      'id="reset-resend-btn" type="button" onclick="resendResetOTP()">Resend code</button></div>' +
      '<div id="reset-err" class="alert alert-e" style="display:none;"></div>';
    showModal('Reset Your Password', body, () => {});
    const btn = document.getElementById('modal-confirm');
    if (btn) { btn.textContent = 'Reset Password'; btn.onclick = doResetVerifyOTP; }
    axStartResetResendCooldown();
  } catch (_) {
    errEl.textContent = 'Could not send verification code. Please try again.';
    errEl.style.display = 'flex';
  } finally {
    setBtn('login-btn', false);
  }
}

async function doResetVerifyOTP() {
  if (_resetBusy) return;
  const otp = (document.getElementById('reset-otp')?.value || '').trim();
  const pw = document.getElementById('reset-pw')?.value || '';
  const pw2 = document.getElementById('reset-pw2')?.value || '';
  const errEl = document.getElementById('reset-err');
  const showErr = message => {
    if (errEl) { errEl.textContent = message; errEl.style.display = 'flex'; }
  };
  if (errEl) errEl.style.display = 'none';
  if (!_resetVerifiedUserId && !/^\d{6}$/.test(otp)) {
    showErr('Enter the 6-digit verification code.'); return;
  }
  const issue = axPasswordIssue(pw);
  if (issue) { showErr(issue); return; }
  if (pw !== pw2) { showErr('Passwords do not match.'); return; }

  _resetBusy = true;
  const submit = document.getElementById('modal-confirm');
  if (submit) submit.disabled = true;
  try {
    if (!_resetVerifiedUserId) {
      const { data, error } = await supaClient.auth.verifyOtp({
        email: _resetEmail, token: otp, type: 'email'
      });
      if (error || !data?.user) {
        document.getElementById('reset-otp').value = '';
        throw Error('Invalid or expired code. Please try again.');
      }
      _resetVerifiedUserId = data.user.id;
    }
    const { data: { user }, error: userError } = await supaClient.auth.getUser();
    if (userError || !user || user.id !== _resetVerifiedUserId ||
        String(user.email || '').toLowerCase() !== _resetEmail)
      throw Error('Your verified session expired. Please request another code.');

    const { error: pwErr } = await supaClient.auth.updateUser({ password: pw });
    if (pwErr) throw Error(pwErr.message || 'Could not save the new password.');
    await supaClient.auth.signOut();
    _resetEmail = '';
    _resetVerifiedUserId = null;
    if (_resetResendTicker) clearInterval(_resetResendTicker);
    _resetResendTicker = null;
    closeModal();
    showToast('Password updated! Log in with the new password.', 'ok', '');
  } catch (e) {
    showErr(e.message || 'Something went wrong. Please try again.');
  } finally {
    _resetBusy = false;
    if (submit) submit.disabled = false;
  }
}
