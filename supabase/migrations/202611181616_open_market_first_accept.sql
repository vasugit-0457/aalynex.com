-- Open Market opt-in; previous invite-only projects stay private by default.
ALTER TABLE public.projects ADD COLUMN IF NOT EXISTS open_market boolean NOT NULL DEFAULT false;
ALTER TABLE public.projects ADD COLUMN IF NOT EXISTS market_ready boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS ax_projects_open_market_active_idx ON public.projects(created_at DESC)
 WHERE open_market IS TRUE AND market_ready IS TRUE AND status = 'open' AND freelancer_id IS NULL;

-- Public listings are visible only to authenticated profiles with freelancer role.
-- Existing participants/invitation policies remain unchanged.
DROP POLICY IF EXISTS "projects_open_market_freelancers_read" ON public.projects;
CREATE POLICY "projects_open_market_freelancers_read" ON public.projects
 FOR SELECT TO authenticated USING (
  open_market IS TRUE AND market_ready IS TRUE
  AND status = 'open' AND freelancer_id IS NULL
  AND creator_id IS DISTINCT FROM (SELECT auth.uid())
  AND EXISTS (SELECT 1 FROM public.profiles pf
    WHERE pf.id = (SELECT auth.uid()) AND pf.role = 'freelancer')
 );

-- Intentionally narrow SECURITY DEFINER RPC: only validated freelancer, one conditional UPDATE.
-- Permissions are explicitly restricted to authenticated accounts; no arbitrary row writes.
CREATE OR REPLACE FUNCTION public.ax_claim_open_market_project(p_project_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
DECLARE v_actor uuid := (SELECT auth.uid()); v_claimed_id text;
BEGIN
 IF v_actor IS NULL THEN
   RAISE EXCEPTION 'Sign in required' USING ERRCODE = '42501';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM public.profiles pf
    WHERE pf.id = v_actor AND pf.role = 'freelancer') THEN
   RAISE EXCEPTION 'Only freelancer accounts can accept Open Market projects' USING ERRCODE = '42501';
 END IF;
 UPDATE public.projects p SET freelancer_id = v_actor, status = 'ongoing'
  WHERE p.id = p_project_id AND p.open_market IS TRUE AND p.market_ready IS TRUE
    AND p.status = 'open' AND p.freelancer_id IS NULL
    AND p.creator_id IS DISTINCT FROM v_actor
  RETURNING p.id INTO v_claimed_id;
 RETURN v_claimed_id IS NOT NULL;
END;
$fn$;
REVOKE ALL ON FUNCTION public.ax_claim_open_market_project(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ax_claim_open_market_project(text) FROM anon;
GRANT EXECUTE ON FUNCTION public.ax_claim_open_market_project(text) TO authenticated;
