ALTER TABLE __SCHEMA__.receiver_inbox
  ADD COLUMN sender_attempt_no bigint,
  ADD COLUMN sender_lease_token text;

UPDATE __SCHEMA__.receiver_inbox r
SET sender_attempt_no=o.attempt_count,
    sender_lease_token=COALESCE(o.lease_token,
      (SELECT a.lease_token FROM __SCHEMA__.outbox_attempts a
       WHERE a.tenant_scope=o.tenant_scope AND a.outbox_id=o.outbox_id
       ORDER BY a.attempt_no DESC LIMIT 1))
FROM __SCHEMA__.outbox o
WHERE o.tenant_scope=r.tenant_scope AND o.dispatch_id=r.dispatch_id;

ALTER TABLE __SCHEMA__.receiver_inbox
  ALTER COLUMN sender_attempt_no SET NOT NULL,
  ALTER COLUMN sender_lease_token SET NOT NULL,
  ADD CONSTRAINT receiver_sender_attempt_positive CHECK(sender_attempt_no > 0),
  ADD CONSTRAINT receiver_sender_token_bounded CHECK(octet_length(sender_lease_token) BETWEEN 1 AND 256);

CREATE POLICY internal_claim_receiver ON __SCHEMA__.receiver_inbox FOR SELECT
 USING (current_user = '__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');

CREATE OR REPLACE FUNCTION __SCHEMA__.claim_outbox_bounded(now_ms bigint, owner_id text, token_id text, until_ms bigint)
RETURNS TABLE(tenant_scope text,outbox_id bigint,dispatch_id text,task_id text,attempt_no bigint,max_attempts bigint,payload_json text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 RETURN QUERY
 WITH candidate AS (
   SELECT o.tenant_scope,o.outbox_id,
     (o.state='leased' AND o.lease_until<=now_ms AND o.attempt_count>=o.max_attempts) AS was_final
   FROM __SCHEMA__.outbox o
   WHERE (o.state='pending' AND o.available_at<=now_ms AND o.attempt_count<o.max_attempts)
      OR (o.state='leased' AND o.lease_until<=now_ms AND
         (o.attempt_count<o.max_attempts OR NOT EXISTS (
            SELECT 1 FROM __SCHEMA__.receiver_inbox r
            WHERE r.tenant_scope=o.tenant_scope AND r.dispatch_id=o.dispatch_id
              AND r.task_id=o.task_id AND r.state='processing' AND r.lease_until>now_ms)))
   ORDER BY o.available_at,o.outbox_id FOR UPDATE SKIP LOCKED LIMIT 1
 ), claimed AS (
   UPDATE __SCHEMA__.outbox o SET state='leased',
     attempt_count=CASE WHEN o.attempt_count<o.max_attempts THEN o.attempt_count+1 ELSE o.attempt_count END,
     lease_owner=owner_id,lease_token=token_id,lease_until=until_ms,updated_at=now_ms
   FROM candidate c WHERE o.tenant_scope=c.tenant_scope AND o.outbox_id=c.outbox_id
   RETURNING o.tenant_scope,o.outbox_id,o.dispatch_id,o.task_id,o.attempt_count,o.max_attempts,o.payload_json,c.was_final
 ), attempt AS (
   INSERT INTO __SCHEMA__.outbox_attempts(tenant_scope,outbox_id,attempt_no,lease_token,started_at)
   SELECT c.tenant_scope,c.outbox_id,c.attempt_count,token_id,now_ms FROM claimed c
   ON CONFLICT ON CONSTRAINT outbox_attempts_pkey DO UPDATE
     SET lease_token=EXCLUDED.lease_token,started_at=EXCLUDED.started_at,
         finished_at=NULL,outcome=NULL,error=NULL,next_attempt_at=NULL
   RETURNING outbox_attempts.tenant_scope,outbox_attempts.outbox_id,outbox_attempts.attempt_no
 ), receiver_fence AS (
   UPDATE __SCHEMA__.receiver_inbox r SET sender_lease_token=token_id
   FROM claimed c
   WHERE c.was_final AND r.tenant_scope=c.tenant_scope AND r.dispatch_id=c.dispatch_id
     AND r.task_id=c.task_id AND r.sender_attempt_no=c.attempt_count
   RETURNING r.tenant_scope,r.dispatch_id
 )
 SELECT a.tenant_scope,a.outbox_id,c.dispatch_id,c.task_id,
   CASE WHEN c.was_final THEN -a.attempt_no ELSE a.attempt_no END,
   c.max_attempts,c.payload_json
 FROM attempt a JOIN claimed c ON c.tenant_scope=a.tenant_scope AND c.outbox_id=a.outbox_id;
END $$;
