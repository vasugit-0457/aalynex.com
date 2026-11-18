-- Aalynex authentication hardening — additive and repeatable.
-- Existing creator/freelancer roles and profile records are not rewritten.

-- Every newly created profile must use a supported account role.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conrelid = 'public.profiles'::regclass
      AND conname = 'ax_auth_profile_valid_role'
  ) THEN
    ALTER TABLE public.profiles
      ADD CONSTRAINT ax_auth_profile_valid_role
      CHECK (role IS NOT NULL AND role IN ('creator','freelancer')) NOT VALID;
  END IF;
END;
$$;

-- All existing 79 profiles were checked before rollout; validate rather than
-- leaving a permanently unvalidated constraint.
ALTER TABLE public.profiles VALIDATE CONSTRAINT ax_auth_profile_valid_role;

CREATE OR REPLACE FUNCTION public.ax_auth_lock_profile_identity()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = ''
AS $$
BEGIN
  -- Authenticated Data API clients may edit public profile details but must
  -- not reassign their primary key, account role, or creation timestamp.
  -- Explicit privileged maintenance sessions (postgres/service_role) retain
  -- the ability to perform audited account migration when necessary.
  IF current_user IN ('authenticated','anon')
     AND (
       NEW.id IS DISTINCT FROM OLD.id
       OR NEW.role IS DISTINCT FROM OLD.role
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
     )
  THEN
    RAISE EXCEPTION 'Account identity and role cannot be changed from the client'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.ax_auth_lock_profile_identity() FROM PUBLIC, anon, authenticated;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid='public.profiles'::regclass
      AND tgname='ax_auth_lock_profile_identity_trg'
  ) THEN
    CREATE TRIGGER ax_auth_lock_profile_identity_trg
      BEFORE UPDATE ON public.profiles
      FOR EACH ROW EXECUTE FUNCTION public.ax_auth_lock_profile_identity();
  END IF;
END;
$$;
