import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const authSource = readFileSync(new URL('../js/auth.js', import.meta.url), 'utf8');
const mainSource = readFileSync(new URL('../js/main.js', import.meta.url), 'utf8');
const index = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const styles = readFileSync(new URL('../css/ax-auth-security.css', import.meta.url), 'utf8');
const sql = readFileSync(new URL('../supabase/migrations/202611181500_secure_profile_identity_and_role.sql', import.meta.url), 'utf8');

const from = authSource.indexOf('const AX_AUTH_MIN_PASSWORD_LENGTH = 12;');
const to = authSource.indexOf('async function loginSuccess(u) {', from);
assert.ok(from >= 0 && to > from);
const resetStart = authSource.indexOf('/* ---- FORGOT PASSWORD (OTP based, retry-safe) ---- */');
assert.ok(resetStart > to, 'password reset handlers must exist');
const section = authSource.slice(from, to) + '\n' + authSource.slice(resetStart);
const ME = '11111111-1111-4111-8111-111111111111';
const EMAIL = 'new-user@example.com';
const goodPassword = 'UniquePassphrase_2026!';

function fixture(options = {}) {
  const state = {
    elements: new Map(), logins: [], toasts: [], screens: [], tabs: [], otpRequests: [],
    verifies: [], profileInserts: [], passwordSaves: [], signOuts: 0,
    user: options.user || null, existingProfile: options.existingProfile || null,
    failPassword: !!options.failPassword, failProfile: !!options.failProfile,
    failLookup: !!options.failLookup, verifyError: !!options.verifyError,
    signupRole: options.role || 'creator', intervals: [], closed: 0, modalHTML: ''
  };
  function el(id,value='') {
    if (state.elements.has(id)) return state.elements.get(id);
    const e = {
      id, value, type: id.includes('pw')?'password':'text',
      style:{display:''}, dataset:{}, className:'', disabled:false,
      textContent:'', innerHTML:'', readOnly:false,
      focus(){}, setAttribute(k,v){this[k]=v;},
      classList:{add(){},remove(){}}, remove(){state.elements.delete(this.id);},
      parentElement:{insertBefore(node){state.elements.set(node.id,node);}}
    };
    state.elements.set(id,e);
    return e;
  }
  for(const id of ['login-email','login-pw','login-err','login-btn',
    'su-name','su-phone','su-email','su-pw','su-pw2',
    'su-profession','su-platform','su-pw-strength','su-recovery-note',
    'signup-err','signup-btn','signup-otp','signup-resend-btn','signup-resend-note',
    'reset-otp','reset-pw','reset-pw2','reset-err','reset-resend-btn',
    'reset-otp-note','modal-confirm']) el(id);
  el('su-name').value = 'Aalynex Test';
  el('su-email').value = EMAIL;
  el('su-pw').value = goodPassword;
  el('su-pw2').value = goodPassword;
  el('su-profession').value = 'Video Editor';
  el('su-platform').value = 'YouTube';
  el('login-email').value = EMAIL;
  el('signup-otp').value = '123456';
  el('reset-otp').value = '123456';
  el('reset-pw').value = goodPassword;
  el('reset-pw2').value = goodPassword;
  const doc = {getElementById:id=>state.elements.get(id)||null,
    createElement(tag){
      const node=el('_new_'+state.elements.size);
      node.id='new';
      node.tagName=tag;
      return node;
    }
  };
  const client = {
    auth: {
      async getUser(){return {data:{user:state.user},error:null};},
      async signInWithOtp(request){state.otpRequests.push(request);return {error:null};},
      async verifyOtp(request) {
        state.verifies.push(request);
        if (state.verifyError) return {data:{user:null},error:{message:'Invalid OTP'}};
        if (!state.user) state.user={id:ME,email:EMAIL,email_confirmed_at:'2026-11-18T00:00:00Z'};
        return {data:{user:state.user},error:null};
      },
      async updateUser(update){
        state.passwordSaves.push(update);
        return {error:state.failPassword ? {message:'Password update rejected'}:null};
      },
      async signOut(){state.signOuts++;state.user=null;return {error:null};}
    },
    from(table) {
      assert.equal(table,'profiles');
      return {
        select(){return this;},
        eq(){return this;},
        async maybeSingle(){
          return {data:state.existingProfile,error:state.failLookup?{message:'lookup failed'}:null};
        },
        insert(row){
          state.profileInserts.push(row);
          return {
            select(){return this;},
            async single() {
              if (state.failProfile) return {data:null,error:{message:'insert blocked'}};
              state.existingProfile={id:row.id,role:row.role};
              return {data:state.existingProfile,error:null};
            }
          };
        }
      };
    }
  };
  const storage=[];
  const DB={users:()=>storage,saveUsers:arr=>{storage.splice(0,storage.length,...arr);}};
  const fake={window:{},document:doc,supaClient:client,DB,validateEmailFmt:email=>/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email),
    validatePhone:()=>({ok:true,phone:'9999999999'}),
    showScreen:id=>state.screens.push(id),
    switchTab:id=>state.tabs.push(id),
    setSRole(role){state.signupRole=role;},
    showToast:(...args)=>state.toasts.push(args),
    loginSuccess:u=>state.logins.push(u),
    setBtn:(id,busy,label)=>{el(id).disabled=busy;if(label)el(id).textContent=label;},
    setInterval(fn){state.intervals.push(fn);return state.intervals.length;},
    clearInterval(){},Date,escapeHtml:v=>String(v).replaceAll('&','&amp;').replaceAll('<','&lt;'),
    showModal(title,body){state.modalHTML=body;},
    closeModal(){state.closed++;}
  };
  const factory = new Function('scope', 'with(scope){\nlet _signupOtpData = {};\nlet signupRole = ' +
    JSON.stringify(state.signupRole) + ';\n' + section +
    '\nreturn {doSignup,doSignupVerifyOTP,axPasswordIssue,axUpdatePasswordStrength,' +
    'toggleAuthPassword,resendSignupOTP,showVerifiedSignupRecovery,' +
    'doForgotPassword,doResetVerifyOTP,resendResetOTP,axAuthSignupInput};\n}');
  return {api:factory(fake),el,state,fake};
}

test('new password policy needs 12+ characters and confirm password', () => {
  const {api,el}=fixture();
  assert.match(api.axPasswordIssue('123456'),/12 characters/);
  assert.equal(api.axPasswordIssue(goodPassword),'');
  el('su-pw2').value='wrong-password';
  assert.throws(()=>api.axAuthSignupInput(),/confirmation password/);
});
test('password field Show/Hide is keyboard-safe and updates aria labels',()=>{
  const {api,el}=fixture();
  const button={textContent:'Show',setAttribute(k,v){this[k]=v;}};
  api.toggleAuthPassword('su-pw',button);
  assert.equal(el('su-pw').type,'text');
  assert.equal(button['aria-pressed'],'true');
  api.toggleAuthPassword('su-pw',button);
  assert.equal(el('su-pw').type,'password');
  assert.equal(button['aria-pressed'],'false');
});
test('signup requests email OTP but never saves password/profile before verification',async()=>{
  const {api,state}=fixture();
  await api.doSignup();
  assert.equal(state.otpRequests.length,1);
  assert.equal(state.otpRequests[0].options.shouldCreateUser,true);
  assert.equal(state.profileInserts.length,0);
  assert.equal(state.passwordSaves.length,0);
  assert.equal(state.logins.length,0);
});
test('invalid OTP cannot create profile or sign in',async()=>{
  const {api,state,el}=fixture({verifyError:true});
  await api.doSignup();
  await api.doSignupVerifyOTP();
  assert.equal(state.verifies.length,1);
  assert.equal(state.logins.length,0);
  assert.equal(state.profileInserts.length,0);
  assert.match(el('signup-err').textContent,/Invalid or expired/);
});
test('password update error stops signup with a retryable verified session',async()=>{
  const {api,state,el}=fixture({failPassword:true});
  await api.doSignup();
  await api.doSignupVerifyOTP();
  assert.equal(state.passwordSaves.length,1);
  assert.equal(state.profileInserts.length,0);
  assert.equal(state.logins.length,0);
  assert.match(el('signup-err').textContent,/Password update rejected/);
  state.failPassword=false;
  await api.doSignupVerifyOTP();
  assert.equal(state.verifies.length,1,'no need to consume OTP again');
  assert.equal(state.logins.length,1);
});
test('failed profile insert does not admit user; successful retry does not update password twice',async()=>{
  const {api,state,el}=fixture({failProfile:true});
  await api.doSignup();
  await api.doSignupVerifyOTP();
  assert.equal(state.logins.length,0);
  assert.equal(state.passwordSaves.length,1);
  assert.equal(state.profileInserts.length,1);
  assert.match(el('signup-err').textContent,/profile setup is incomplete/);
  state.failProfile=false;
  await api.doSignupVerifyOTP();
  assert.equal(state.passwordSaves.length,1);
  assert.equal(state.profileInserts.length,2);
  assert.equal(state.logins.length,1);
});
test('successful new account creates one own role/profile and reaches dashboard once',async()=>{
  const {api,state}=fixture({role:'freelancer'});
  await api.doSignup();await api.doSignupVerifyOTP();
  assert.equal(state.profileInserts.length,1);
  assert.equal(state.profileInserts[0].role,'freelancer');
  assert.equal(state.profileInserts[0].id,ME);
  assert.equal(state.logins.length,1);
  assert.equal(state.logins[0].role,'freelancer');
});
test('verified session missing a profile resumes without sending another OTP',async()=>{
  const {api,state}=fixture({user:{id:ME,email:EMAIL,email_confirmed_at:'2026-11-18T00:00:00Z'}});
  await api.doSignup();
  assert.equal(state.otpRequests.length,0);
  assert.equal(state.logins.length,1);
});
test('verified session with an existing profile is never overwritten',async()=>{
  const {api,state,el}=fixture({
    user:{id:ME,email:EMAIL,email_confirmed_at:'2026-11-18T00:00:00Z'},
    existingProfile:{id:ME,role:'creator'}
  });
  await api.doSignup();
  assert.equal(state.otpRequests.length,0);
  assert.equal(state.passwordSaves.length,0);
  assert.equal(state.profileInserts.length,0);
  assert.equal(state.logins.length,0);
  assert.match(el('signup-err').textContent,/already has an account/);
});
test('verified session for another email cannot be hijacked through signup',async()=>{
  const {api,state,el}=fixture({
    user:{id:ME,email:'other@example.com',email_confirmed_at:'2026-11-18T00:00:00Z'}
  });
  await api.doSignup();
  assert.equal(state.otpRequests.length,0);
  assert.equal(state.profileInserts.length,0);
  assert.match(el('signup-err').textContent,/another email/);
});
test('OTP resend uses existing-account setting and client-side cooldown',async()=>{
  const {api,state}=fixture();
  await api.doSignup();
  await api.resendSignupOTP();
  assert.equal(state.otpRequests.length,1,'cooldown blocks immediate resend');
});
test('missing-profile restoration shows a verified recovery screen without creating data',()=>{
  const {api,state,el}=fixture();
  assert.equal(api.showVerifiedSignupRecovery({id:ME,email:EMAIL,email_confirmed_at:'now'}),true);
  assert.equal(el('su-email').readOnly,true);
  assert.equal(el('su-email').value,EMAIL);
  assert.ok(state.tabs.includes('signup'));
  assert.equal(state.profileInserts.length,0);
});
test('forgot password sends OTP with shouldCreateUser=false',async()=>{
  const {api,state}=fixture();
  await api.doForgotPassword();
  assert.equal(state.otpRequests[0].options.shouldCreateUser,false);
  assert.match(state.modalHTML,/reset-pw2/);
  assert.match(state.modalHTML,/toggleAuthPassword/);
});
test('password reset verifies OTP once, retries password failure and signs out after success',async()=>{
  const {api,state,el}=fixture({failPassword:true});
  await api.doForgotPassword();
  await api.doResetVerifyOTP();
  assert.equal(state.verifies.length,1);
  assert.equal(state.signOuts,0);
  assert.match(el('reset-err').textContent,/Password update rejected/);
  state.failPassword=false;
  await api.doResetVerifyOTP();
  assert.equal(state.verifies.length,1);
  assert.equal(state.signOuts,1);
  assert.equal(state.closed,1);
});
test('weak reset password or mismatch never consumes OTP',async()=>{
  const {api,state,el}=fixture();
  await api.doForgotPassword();
  el('reset-pw').value='short';
  await api.doResetVerifyOTP();
  assert.equal(state.verifies.length,0);
  el('reset-pw').value=goodPassword;
  el('reset-pw2').value='different';
  await api.doResetVerifyOTP();
  assert.equal(state.verifies.length,0);
});
test('role/ID protection stays server-side and migration is additive',()=>{
  assert.match(sql,/current_user IN \('authenticated','anon'\)/);
  assert.match(sql,/NEW\.role IS DISTINCT FROM OLD\.role/);
  assert.match(sql,/NEW\.id IS DISTINCT FROM OLD\.id/);
  assert.match(sql,/SECURITY INVOKER/);
  assert.doesNotMatch(sql,/DELETE FROM public\.profiles|UPDATE public\.profiles|DROP TABLE/i);
});
test('main restores verified missing profile and rejects query errors',()=>{
  assert.match(mainSource,/maybeSingle\(\)/);
  assert.match(mainSource,/if \(profileError\) throw profileError/);
  assert.match(mainSource,/showVerifiedSignupRecovery\(user\)/);
});
test('auth UI contains confirm-password, show/hide, resend, and no Google login',()=>{
  assert.match(index,/id="su-pw2"/);
  assert.match(index,/id="su-pw-strength"/);
  assert.match(index,/toggleAuthPassword\('login-pw'/);
  assert.match(index,/ax-auth-security\.css\?v=aalynex-auth-secure-20261118/);
  assert.match(styles,/ax-auth-recovery-note/);
  assert.doesNotMatch(index,/signInWithOAuth|google-signin|Google Sign In/);
});


test('after the 60-second cooldown resend requests an OTP without creating a user again',async()=>{
  const {api,state,fake}=fixture();
  const initial=Date.now();
  fake.Date=class TestClock extends Date { static now(){return initial+61000;} };
  await api.doSignup();
  fake.Date=class TestClockLater extends Date { static now(){return initial+122000;} };
  await api.resendSignupOTP();
  assert.equal(state.otpRequests.length,2);
  assert.equal(state.otpRequests[1].options.shouldCreateUser,false);
});
test('unconfirmed account must not be finalized through recovery shortcut',()=>{
  const {api,state}=fixture();
  assert.equal(api.showVerifiedSignupRecovery({id:ME,email:EMAIL,email_confirmed_at:null}),false);
  assert.equal(state.logins.length,0);
  assert.equal(state.profileInserts.length,0);
});
test('invalid signup form sends neither an OTP nor a password to the server',async()=>{
  const {api,el,state}=fixture();
  el('su-pw').value='short';
  await api.doSignup();
  assert.equal(state.otpRequests.length,0);
  assert.equal(state.passwordSaves.length,0);
  assert.equal(state.profileInserts.length,0);
  assert.equal(state.logins.length,0);
});
