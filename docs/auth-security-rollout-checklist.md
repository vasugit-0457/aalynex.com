# Aalynex Auth Security — Release Checklist

## Automated changes in this release

- Existing email/password login and Creator/Freelancer dashboards stay intact.
- Signup uses an email OTP (6 digits), explicit 12+ character password and matching confirmation, and waits for both Supabase Auth password update and a persisted profile record before showing the dashboard.
- The signup form never upserts or rewrites a previously registered user profile.
- Verified Supabase users without a profile get a safe, manual completion screen; no role is silently guessed or inserted.
- OTP resend is throttled client-side to 60 seconds, in addition to Supabase server rate limiting.
- Reset password requires an email OTP and matching new password, with retry after an OTP has been used.
- Logged-in users cannot update their profile primary key, account role, or creation time through the Data API. New profiles accept only `creator` and `freelancer`. This protection is enforced by a SECURITY INVOKER PostgreSQL trigger.
- Existing 83 Auth accounts, 79 profile records, chat histories, projects, payment and media delivery data must remain unchanged.

## Dashboard settings to verify manually (not changed by this PR)

These are **server-side Supabase Auth settings**. Frontend validation alone is not security enforcement.

1. **Email OTP template:** In Supabase Dashboard → Authentication → Email Templates → Magic Link / OTP, ensure the email actually contains `{{ .Token }}` (six digits), not just `{{ .ConfirmationURL }}`. The current frontend verifies the token with `verifyOtp({type:'email'})`.
2. **Minimum password length:** In Supabase Dashboard → Authentication → Settings / Password Security, align the server minimum with the frontend policy (12 characters). Test existing logins when raising the minimum; some existing weak-password accounts may be affected by policy changes.
3. **Leaked password protection:** Enable in the Supabase Auth security settings **if the project's plan supports it** (currently listed as Pro and above). The Security Advisor warning cannot be resolved from the available connector settings API.
4. **Abuse prevention:** Verify server-side OTP / auth rate limits, CAPTCHA configuration and approved Site URL / redirect URL configuration. A browser countdown alone does not prevent automated OTP abuse.
5. **Email deliverability:** Confirm SMTP sender/domain and email OTP limits before releasing broadly.

## Real user-flow QA after GitHub Pages deployment

- Existing Mamun and Vasu accounts: sign in with the **original** password, correct roles, logout, refresh and sign in again.
- New creator signup: send OTP, enter code, create password/profile, logout, then email/password login. Test password Show/Hide and Confirm Password.
- New freelancer signup: same as creator, verify correct Freelancer dashboard.
- Incorrect / expired OTP: no dashboard or incomplete profile becomes accessible.
- Profile insert failure: error, retry in verified session, no duplicate account.
- Forgot Password: valid 6-digit OTP, password confirmation, change password, sign out, log in with new password.
- Signed-in verified account lacking a profile: complete account setup rather than treating it as invalid credentials.
- Direct profile role/ID update attempt must fail. Normal profile edits must work.
- Verify old chat messages, read ticks, typing, Reply, file sharing, projects and payments.
- **Rollback plan:** revert upstream frontend PR if onboarding UI breaks. The role-lock database migration is additive; do not remove the trigger without an explicit security review.

## Not shipped in this release

- Google Sign In — deliberately excluded.
- TOTP-based MFA (2FA) — must be designed with AAL2 session enforcement and backend authorization before exposing controls, otherwise it gives a false sense of security.

Supabase references: https://supabase.com/docs/guides/auth/password-security and https://supabase.com/docs/guides/auth/auth-email-templates
