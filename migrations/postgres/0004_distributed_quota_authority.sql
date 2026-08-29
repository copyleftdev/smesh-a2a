CREATE TABLE __SCHEMA__.quota_policy_versions(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 policy_id text NOT NULL CHECK(octet_length(policy_id) BETWEEN 1 AND 128),
 policy_revision bigint NOT NULL CHECK(policy_revision>0),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 canonical_json text NOT NULL CHECK(octet_length(canonical_json)<=262144 AND __SCHEMA__.json_text_valid(canonical_json)),
 lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('active','draining','retired')),
 retired_at bigint CHECK(retired_at IS NULL OR retired_at>0),
 created_at bigint NOT NULL CHECK(created_at>0),
 PRIMARY KEY(tenant_scope,policy_id,policy_revision),
 UNIQUE(tenant_scope,policy_digest)
);
CREATE UNIQUE INDEX quota_policy_one_active ON __SCHEMA__.quota_policy_versions(tenant_scope) WHERE lifecycle='active';

CREATE TABLE __SCHEMA__.quota_policy_reconciliation_audits(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 reconciliation_id text NOT NULL CHECK(octet_length(reconciliation_id)=71),
 old_policy_revision bigint NOT NULL CHECK(old_policy_revision>0),
 old_policy_digest text NOT NULL CHECK(octet_length(old_policy_digest)=71),
 new_policy_revision bigint NOT NULL CHECK(new_policy_revision>0),
 new_policy_digest text NOT NULL CHECK(octet_length(new_policy_digest)=71),
 actor_digest text NOT NULL CHECK(octet_length(actor_digest)=71),
 reason_digest text NOT NULL CHECK(octet_length(reason_digest)=71),
 action text NOT NULL CHECK(action='drain'),
 targets_json text NOT NULL CHECK(__SCHEMA__.json_text_valid(targets_json)),
 effective_at bigint NOT NULL CHECK(effective_at>0),
 created_at bigint NOT NULL CHECK(created_at>0),
 PRIMARY KEY(tenant_scope,reconciliation_id),
 UNIQUE(tenant_scope,old_policy_digest,new_policy_digest)
);

CREATE TABLE __SCHEMA__.quota_intents(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 binding_digest text NOT NULL CHECK(octet_length(binding_digest)=71),
 account_id text NOT NULL CHECK(octet_length(account_id) BETWEEN 1 AND 64),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 256),
 operation text NOT NULL CHECK(octet_length(operation) BETWEEN 1 AND 64),
 semantic_id text NOT NULL CHECK(octet_length(semantic_id) BETWEEN 1 AND 256),
 policy_id text NOT NULL,
 policy_revision bigint NOT NULL,
 policy_digest text NOT NULL,
 task_id text CHECK(task_id IS NULL OR octet_length(task_id) BETWEEN 1 AND 4096),
 created_at bigint NOT NULL CHECK(created_at>0),
 retention_until bigint GENERATED ALWAYS AS (CASE WHEN task_id IS NULL THEN created_at+86400000 END) STORED,
 PRIMARY KEY(tenant_scope,binding_digest),
 UNIQUE(tenant_scope,operation,semantic_id),
 FOREIGN KEY(tenant_scope,policy_id,policy_revision) REFERENCES __SCHEMA__.quota_policy_versions(tenant_scope,policy_id,policy_revision) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT
);

CREATE TABLE __SCHEMA__.quota_buckets(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 scope_kind text NOT NULL CHECK(scope_kind IN ('tenant','account','principal')),
 scope_id text NOT NULL CHECK(octet_length(scope_id) BETWEEN 1 AND 256),
 operation text NOT NULL CHECK(octet_length(operation) BETWEEN 1 AND 64),
 dimension text NOT NULL CHECK(octet_length(dimension) BETWEEN 1 AND 64),
 algorithm text NOT NULL CHECK(algorithm IN ('fixedWindow','tokenBucket','gauge')),
 window_start bigint NOT NULL CHECK(window_start>=0),
 window_millis bigint CHECK(window_millis IS NULL OR window_millis>0),
 capacity bigint NOT NULL CHECK(capacity>0),
 used_units bigint NOT NULL CHECK(used_units>=0 AND used_units<=capacity),
 available_tokens bigint CHECK(available_tokens IS NULL OR available_tokens BETWEEN 0 AND capacity),
 last_refill_at bigint CHECK(last_refill_at IS NULL OR last_refill_at>0),
 refill_numerator bigint CHECK(refill_numerator IS NULL OR refill_numerator>0),
 refill_period_millis bigint CHECK(refill_period_millis IS NULL OR refill_period_millis>0),
 refill_remainder bigint CHECK(refill_remainder IS NULL OR refill_remainder>=0),
 updated_at bigint NOT NULL CHECK(updated_at>0),
 retention_until bigint GENERATED ALWAYS AS (updated_at+86400000) STORED,
 PRIMARY KEY(tenant_scope,policy_digest,scope_kind,scope_id,operation,dimension,window_start),
 CHECK((algorithm='tokenBucket' AND window_start=0 AND window_millis IS NOT NULL
        AND available_tokens IS NOT NULL AND last_refill_at IS NOT NULL
        AND refill_numerator=capacity AND refill_period_millis=window_millis
        AND refill_remainder BETWEEN 0 AND refill_period_millis-1)
    OR (algorithm<>'tokenBucket' AND available_tokens IS NULL AND last_refill_at IS NULL
        AND refill_numerator IS NULL AND refill_period_millis IS NULL AND refill_remainder IS NULL))
);
CREATE INDEX quota_buckets_scope_lookup ON __SCHEMA__.quota_buckets(tenant_scope,scope_kind,scope_id,operation,dimension,window_start DESC);

CREATE TABLE __SCHEMA__.quota_receipts(
 tenant_scope text NOT NULL,
 binding_digest text NOT NULL,
 scope_kind text NOT NULL,
 scope_id text NOT NULL,
 dimension text NOT NULL,
 algorithm text NOT NULL,
 window_start bigint NOT NULL,
 units bigint NOT NULL CHECK(units>0),
 capacity bigint NOT NULL CHECK(capacity>0),
 created_at bigint NOT NULL CHECK(created_at>0),
 retention_until bigint GENERATED ALWAYS AS (created_at+86400000) STORED,
 PRIMARY KEY(tenant_scope,binding_digest,scope_kind,scope_id,dimension),
 FOREIGN KEY(tenant_scope,binding_digest) REFERENCES __SCHEMA__.quota_intents(tenant_scope,binding_digest) ON DELETE RESTRICT
);
CREATE INDEX quota_receipts_scope_lookup ON __SCHEMA__.quota_receipts(tenant_scope,scope_kind,scope_id,dimension,created_at);

-- Per-call receipts are distinct from the immutable mutation intent above. A
-- semantic replay receives a fresh server invocation id and consumes current
-- request/input capacity without duplicating workflow reservations.
CREATE TABLE __SCHEMA__.quota_request_receipts(
 tenant_scope text NOT NULL,
 invocation_id text NOT NULL CHECK(octet_length(invocation_id)=71),
 mutation_binding_digest text NOT NULL CHECK(octet_length(mutation_binding_digest)=71),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 scope_kind text NOT NULL CHECK(scope_kind IN ('tenant','account','principal')),
 scope_id text NOT NULL,
 operation text NOT NULL,
 dimension text NOT NULL CHECK(dimension IN ('requestCount','inputBytes')),
 window_start bigint NOT NULL,
 units bigint NOT NULL CHECK(units>0),
 capacity bigint NOT NULL CHECK(capacity>0),
 created_at bigint NOT NULL CHECK(created_at>0),
 retention_until bigint GENERATED ALWAYS AS (created_at+86400000) STORED,
 PRIMARY KEY(tenant_scope,invocation_id,scope_kind,scope_id,dimension)
);
CREATE INDEX quota_request_receipts_mutation_lookup ON __SCHEMA__.quota_request_receipts(tenant_scope,mutation_binding_digest,created_at);

CREATE TABLE __SCHEMA__.quota_execution_reservations(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 reservation_id text NOT NULL CHECK(octet_length(reservation_id)=71),
 reservation_version bigint NOT NULL CHECK(reservation_version=1),
 binding_digest text NOT NULL CHECK(octet_length(binding_digest)=71),
 policy_id text NOT NULL CHECK(octet_length(policy_id) BETWEEN 1 AND 128),
 policy_revision bigint NOT NULL CHECK(policy_revision>0),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 account_id text NOT NULL CHECK(octet_length(account_id) BETWEEN 1 AND 64),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 256),
 operation text NOT NULL CHECK(operation IN ('taskCreate','taskContinue','sendStream')),
 task_id text NOT NULL,
 message_id text NOT NULL,
 dispatch_id text NOT NULL CHECK(octet_length(dispatch_id)=71),
 reserved_output_bytes bigint NOT NULL CHECK(reserved_output_bytes>0),
 reserved_event_count bigint NOT NULL CHECK(reserved_event_count>0),
 actual_output_bytes bigint CHECK(actual_output_bytes IS NULL OR actual_output_bytes BETWEEN 0 AND reserved_output_bytes),
 actual_event_count bigint CHECK(actual_event_count IS NULL OR actual_event_count BETWEEN 0 AND reserved_event_count),
 state text NOT NULL CHECK(state IN ('reserved','settled')),
 settlement_reason text,
 settled_at bigint,
 created_at bigint NOT NULL CHECK(created_at>0),
 retention_until bigint GENERATED ALWAYS AS (settled_at+86400000) STORED,
 PRIMARY KEY(tenant_scope,reservation_id),
 UNIQUE(tenant_scope,binding_digest),
 UNIQUE(tenant_scope,dispatch_id),
 FOREIGN KEY(tenant_scope,binding_digest) REFERENCES __SCHEMA__.quota_intents(tenant_scope,binding_digest) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_scope,task_id) REFERENCES __SCHEMA__.tasks(tenant_scope,task_id) ON DELETE RESTRICT,
 CHECK((state='reserved' AND actual_output_bytes IS NULL AND actual_event_count IS NULL AND settlement_reason IS NULL AND settled_at IS NULL)
    OR (state='settled' AND actual_output_bytes IS NOT NULL AND actual_event_count IS NOT NULL AND settlement_reason IS NOT NULL AND settled_at IS NOT NULL))
);
CREATE INDEX quota_execution_reservations_task_state ON __SCHEMA__.quota_execution_reservations(tenant_scope,task_id,state);
CREATE TRIGGER quota_execution_reservations_identity_immutable BEFORE UPDATE ON __SCHEMA__.quota_execution_reservations
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('tenant_scope','reservation_id','reservation_version','binding_digest','policy_id','policy_revision','policy_digest','account_id','principal_scope','operation','task_id','message_id','dispatch_id','reserved_output_bytes','reserved_event_count','created_at');

ALTER TABLE __SCHEMA__.outbox
 ADD COLUMN quota_binding_digest text,
 ADD COLUMN quota_reservation_id text,
 ADD COLUMN quota_reservation_version bigint,
 ADD COLUMN reserved_output_bytes bigint,
 ADD COLUMN reserved_event_count bigint;
ALTER TABLE __SCHEMA__.outbox
 ADD CONSTRAINT outbox_execution_reservation_fk FOREIGN KEY(tenant_scope,quota_reservation_id) REFERENCES __SCHEMA__.quota_execution_reservations(tenant_scope,reservation_id) ON DELETE RESTRICT,
 ADD CONSTRAINT outbox_execution_reservation_bounds CHECK(
   (quota_binding_digest IS NULL AND quota_reservation_id IS NULL AND quota_reservation_version IS NULL AND reserved_output_bytes IS NULL AND reserved_event_count IS NULL)
   OR (quota_binding_digest IS NOT NULL AND quota_reservation_id IS NOT NULL AND quota_reservation_version=1 AND reserved_output_bytes>0 AND reserved_event_count>0)
 );
CREATE TRIGGER outbox_execution_reservation_immutable BEFORE UPDATE ON __SCHEMA__.outbox
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('quota_binding_digest','quota_reservation_id','quota_reservation_version','reserved_output_bytes','reserved_event_count');

ALTER TABLE __SCHEMA__.receiver_inbox
 ADD COLUMN quota_binding_digest text,
 ADD COLUMN quota_reservation_id text,
 ADD COLUMN quota_reservation_version bigint,
 ADD COLUMN reserved_output_bytes bigint,
 ADD COLUMN reserved_event_count bigint,
 ADD COLUMN measured_output_bytes bigint,
 ADD COLUMN measured_event_count bigint,
 ADD CONSTRAINT receiver_execution_reservation_fk FOREIGN KEY(tenant_scope,quota_reservation_id) REFERENCES __SCHEMA__.quota_execution_reservations(tenant_scope,reservation_id) ON DELETE RESTRICT,
 ADD CONSTRAINT receiver_execution_reservation_bounds CHECK(
   (quota_binding_digest IS NULL AND quota_reservation_id IS NULL AND quota_reservation_version IS NULL AND reserved_output_bytes IS NULL AND reserved_event_count IS NULL)
   OR (quota_binding_digest IS NOT NULL AND quota_reservation_id IS NOT NULL AND quota_reservation_version=1 AND reserved_output_bytes>0 AND reserved_event_count>0)
 );
-- Revision-3 processing rows remain explicitly legacy-unreserved; migration never
-- fabricates a reservation or containment budget. Completed measurements are
-- reconstructed from the same canonical frame JSON bytes/events used at commit.
ALTER TABLE __SCHEMA__.receiver_inbox
 ADD CONSTRAINT receiver_execution_measurement_state CHECK(
   (state='processing' AND measured_output_bytes IS NULL AND measured_event_count IS NULL)
   OR (state='completed'
       AND measured_output_bytes IS NOT NULL
       AND measured_event_count IS NOT NULL
       AND measured_output_bytes>=0
       AND measured_event_count>=0)
 ) NOT VALID;
UPDATE __SCHEMA__.receiver_inbox r
 SET measured_output_bytes=COALESCE((SELECT sum(octet_length(f.frame_json))::bigint FROM __SCHEMA__.receiver_frames f WHERE f.tenant_scope=r.tenant_scope AND f.dispatch_id=r.dispatch_id),0),
     measured_event_count=(SELECT count(*)::bigint FROM __SCHEMA__.receiver_frames f WHERE f.tenant_scope=r.tenant_scope AND f.dispatch_id=r.dispatch_id)
 WHERE r.state='completed';
ALTER TABLE __SCHEMA__.receiver_inbox VALIDATE CONSTRAINT receiver_execution_measurement_state;
CREATE TRIGGER receiver_execution_reservation_immutable BEFORE UPDATE ON __SCHEMA__.receiver_inbox
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.reject_identity_change('quota_binding_digest','quota_reservation_id','quota_reservation_version','reserved_output_bytes','reserved_event_count');

CREATE SEQUENCE __SCHEMA__.outbox_served_sequence AS bigint;
CREATE TABLE __SCHEMA__.outbox_tenant_scheduler(
 tenant_scope text PRIMARY KEY CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 virtual_finish bigint NOT NULL DEFAULT 0 CHECK(virtual_finish>=0),
 served_sequence bigint NOT NULL DEFAULT 0 CHECK(served_sequence>=0),
 updated_at bigint NOT NULL CHECK(updated_at>0)
);
CREATE INDEX outbox_tenant_scheduler_eligible ON __SCHEMA__.outbox_tenant_scheduler(virtual_finish,served_sequence,tenant_scope);
INSERT INTO __SCHEMA__.outbox_tenant_scheduler(tenant_scope,updated_at)
 SELECT DISTINCT tenant_scope,__SCHEMA__.db_millis() FROM __SCHEMA__.outbox
 ON CONFLICT ON CONSTRAINT outbox_tenant_scheduler_pkey DO NOTHING;
CREATE FUNCTION __SCHEMA__.ensure_outbox_tenant_scheduler() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 INSERT INTO __SCHEMA__.outbox_tenant_scheduler(tenant_scope,updated_at)
 VALUES(NEW.tenant_scope,__SCHEMA__.db_millis()) ON CONFLICT ON CONSTRAINT outbox_tenant_scheduler_pkey DO NOTHING;
 RETURN NEW;
END $$;
CREATE TRIGGER outbox_ensure_tenant_scheduler AFTER INSERT ON __SCHEMA__.outbox
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.ensure_outbox_tenant_scheduler();
CREATE INDEX outbox_pending_tenant_due ON __SCHEMA__.outbox(tenant_scope,available_at,outbox_id) WHERE state='pending';
CREATE INDEX outbox_leased_tenant_due ON __SCHEMA__.outbox(tenant_scope,lease_until,outbox_id) WHERE state='leased';

CREATE TABLE __SCHEMA__.quota_allocations(
 tenant_scope text NOT NULL,
 binding_digest text NOT NULL,
 scope_kind text NOT NULL,
 scope_id text NOT NULL,
 dimension text NOT NULL CHECK(dimension IN ('concurrentActiveWork','concurrentStreams','concurrentSubscriptions','retainedAuthorityBytes')),
 task_id text NOT NULL,
 units bigint NOT NULL CHECK(units>0),
 state text NOT NULL CHECK(state IN ('active','released')),
 released_at bigint,
 release_reason text,
 retention_until bigint GENERATED ALWAYS AS (released_at+86400000) STORED,
 PRIMARY KEY(tenant_scope,binding_digest,scope_kind,scope_id,dimension),
 FOREIGN KEY(tenant_scope,binding_digest) REFERENCES __SCHEMA__.quota_intents(tenant_scope,binding_digest) ON DELETE RESTRICT,
 CHECK((state='active' AND released_at IS NULL AND release_reason IS NULL) OR (state='released' AND released_at IS NOT NULL AND release_reason IS NOT NULL))
);
CREATE INDEX quota_allocations_task_active ON __SCHEMA__.quota_allocations(tenant_scope,task_id,state,dimension);

CREATE TABLE __SCHEMA__.quota_leases(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 lease_id text NOT NULL CHECK(octet_length(lease_id)=71),
 lease_token text NOT NULL CHECK(octet_length(lease_token)=71),
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 binding_digest text NOT NULL CHECK(octet_length(binding_digest)=71),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 account_id text NOT NULL CHECK(octet_length(account_id) BETWEEN 1 AND 64),
 principal_scope text NOT NULL CHECK(octet_length(principal_scope) BETWEEN 1 AND 256),
 operation text NOT NULL CHECK(operation IN ('sendStream','subscribe','reconnect')),
 lease_kind text NOT NULL CHECK(lease_kind IN ('messageStream','taskSubscription')),
 resource_digest text NOT NULL CHECK(octet_length(resource_digest) BETWEEN 1 AND 256),
 lease_until bigint NOT NULL CHECK(lease_until>0),
 state text NOT NULL CHECK(state IN ('active','released','expired')),
 created_at bigint NOT NULL CHECK(created_at>0),
 updated_at bigint NOT NULL CHECK(updated_at>=created_at),
 retention_until bigint GENERATED ALWAYS AS (lease_until+86400000) STORED,
 PRIMARY KEY(tenant_scope,lease_id),
 UNIQUE(tenant_scope,lease_token),
 FOREIGN KEY(tenant_scope,binding_digest) REFERENCES __SCHEMA__.quota_intents(tenant_scope,binding_digest) ON DELETE RESTRICT
);
CREATE INDEX quota_leases_scope_active ON __SCHEMA__.quota_leases(tenant_scope,lease_kind,principal_scope,state,lease_until);

CREATE TABLE __SCHEMA__.quota_denial_audits(
 tenant_scope text NOT NULL,
 decision_key text NOT NULL CHECK(octet_length(decision_key)=71),
 content_digest text NOT NULL CHECK(octet_length(content_digest)=71),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 bucket_digest text NOT NULL CHECK(octet_length(bucket_digest)=71),
 reason_digest text NOT NULL CHECK(octet_length(reason_digest)=71),
 retry_after_seconds bigint NOT NULL CHECK(retry_after_seconds BETWEEN 1 AND 3600),
 denied_at bigint NOT NULL CHECK(denied_at>0),
 PRIMARY KEY(tenant_scope,decision_key)
);

CREATE TABLE __SCHEMA__.quota_override_audits(
 tenant_scope text NOT NULL,
 override_id text NOT NULL,
 actor_digest text NOT NULL,
 reason_digest text NOT NULL,
 scope_kind text NOT NULL CHECK(scope_kind IN ('tenant','account','principal')),
 scope_id_digest text NOT NULL,
 operation text NOT NULL,
 dimension text NOT NULL,
 old_limit bigint NOT NULL CHECK(old_limit>0),
 new_limit bigint NOT NULL CHECK(new_limit>0),
 policy_revision bigint NOT NULL CHECK(policy_revision>0),
 policy_digest text NOT NULL CHECK(octet_length(policy_digest)=71),
 effective_at bigint NOT NULL,
 expires_at bigint NOT NULL CHECK(expires_at>effective_at),
 created_at bigint NOT NULL,
 PRIMARY KEY(tenant_scope,override_id)
);

CREATE OR REPLACE FUNCTION __SCHEMA__.release_task_quota_allocations() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE reservation record; receipt record; actual_output bigint; actual_events bigint; changed bigint;
BEGIN
 IF OLD.state NOT IN ('"TASK_STATE_COMPLETED"','"TASK_STATE_FAILED"','"TASK_STATE_CANCELED"','"TASK_STATE_REJECTED"')
    AND NEW.state IN ('"TASK_STATE_COMPLETED"','"TASK_STATE_FAILED"','"TASK_STATE_CANCELED"','"TASK_STATE_REJECTED"','"TASK_STATE_INPUT_REQUIRED"','"TASK_STATE_AUTH_REQUIRED"') THEN
   WITH released AS (
     UPDATE __SCHEMA__.quota_allocations
        SET state='released',released_at=__SCHEMA__.db_millis(),release_reason='task-state'
      WHERE tenant_scope=NEW.tenant_scope AND task_id=NEW.task_id
        AND state='active' AND dimension='concurrentActiveWork'
      RETURNING scope_kind,scope_id,dimension,units,binding_digest
   )
   UPDATE __SCHEMA__.quota_buckets b
      SET used_units=GREATEST(b.used_units-r.units,0),updated_at=__SCHEMA__.db_millis()
     FROM released r, __SCHEMA__.quota_intents i
    WHERE i.tenant_scope=NEW.tenant_scope AND i.binding_digest=r.binding_digest
      AND b.tenant_scope=NEW.tenant_scope AND b.policy_digest=i.policy_digest
      AND b.scope_kind=r.scope_kind AND b.scope_id=r.scope_id
      AND b.operation=i.operation AND b.dimension=r.dimension AND b.window_start=0;

   FOR reservation IN
     SELECT reservation_id,binding_digest,dispatch_id FROM __SCHEMA__.quota_execution_reservations
      WHERE tenant_scope=NEW.tenant_scope AND task_id=NEW.task_id AND state='reserved' FOR UPDATE
   LOOP
     SELECT COALESCE((SELECT measured_output_bytes FROM __SCHEMA__.receiver_inbox
                      WHERE tenant_scope=NEW.tenant_scope AND dispatch_id=reservation.dispatch_id AND state='completed'),0),
            COALESCE((SELECT measured_event_count FROM __SCHEMA__.receiver_inbox
                      WHERE tenant_scope=NEW.tenant_scope AND dispatch_id=reservation.dispatch_id AND state='completed'),0)
       INTO actual_output,actual_events;
     UPDATE __SCHEMA__.quota_execution_reservations SET state='settled',
       actual_output_bytes=actual_output,actual_event_count=actual_events,
       settlement_reason='task-state',settled_at=__SCHEMA__.db_millis()
      WHERE tenant_scope=NEW.tenant_scope AND reservation_id=reservation.reservation_id AND state='reserved';
     FOR receipt IN
       SELECT r.scope_kind,r.scope_id,r.dimension,r.window_start,r.units,i.policy_digest,i.operation
         FROM __SCHEMA__.quota_receipts r JOIN __SCHEMA__.quota_intents i USING(tenant_scope,binding_digest)
        WHERE r.tenant_scope=NEW.tenant_scope AND r.binding_digest=reservation.binding_digest
          AND r.dimension IN ('outputBytes','eventCount')
     LOOP
       UPDATE __SCHEMA__.quota_buckets SET
         used_units=used_units-(receipt.units-CASE receipt.dimension WHEN 'outputBytes' THEN actual_output ELSE actual_events END),
         updated_at=__SCHEMA__.db_millis()
       WHERE tenant_scope=NEW.tenant_scope AND policy_digest=receipt.policy_digest
         AND scope_kind=receipt.scope_kind AND scope_id=receipt.scope_id AND operation=receipt.operation
         AND dimension=receipt.dimension AND window_start=receipt.window_start
         AND used_units>=receipt.units-CASE receipt.dimension WHEN 'outputBytes' THEN actual_output ELSE actual_events END;
       GET DIAGNOSTICS changed = ROW_COUNT;
       IF changed<>1 THEN RAISE EXCEPTION 'execution reservation task-state refund fence is stale'; END IF;
     END LOOP;
   END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER tasks_release_quota AFTER UPDATE OF state ON __SCHEMA__.tasks
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.release_task_quota_allocations();

CREATE FUNCTION __SCHEMA__.settle_terminal_execution_reservation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE actual_output bigint := 0; actual_events bigint := 0; binding text; receipt record; changed bigint;
BEGIN
 IF OLD.state IS DISTINCT FROM NEW.state AND NEW.state IN ('dead','superseded','delivered') AND NEW.quota_reservation_id IS NOT NULL THEN
   SELECT COALESCE((SELECT measured_output_bytes FROM __SCHEMA__.receiver_inbox
                    WHERE tenant_scope=NEW.tenant_scope AND dispatch_id=NEW.dispatch_id AND state='completed'),0),
          COALESCE((SELECT measured_event_count FROM __SCHEMA__.receiver_inbox
                    WHERE tenant_scope=NEW.tenant_scope AND dispatch_id=NEW.dispatch_id AND state='completed'),0)
     INTO actual_output,actual_events;
   UPDATE __SCHEMA__.quota_execution_reservations
      SET state='settled',actual_output_bytes=actual_output,actual_event_count=actual_events,
          settlement_reason='terminal-outbox',settled_at=__SCHEMA__.db_millis()
    WHERE tenant_scope=NEW.tenant_scope AND reservation_id=NEW.quota_reservation_id AND state='reserved'
    RETURNING binding_digest INTO binding;
   IF FOUND THEN
     FOR receipt IN
       SELECT r.scope_kind,r.scope_id,r.dimension,r.window_start,r.units,i.policy_digest,i.operation
         FROM __SCHEMA__.quota_receipts r JOIN __SCHEMA__.quota_intents i USING(tenant_scope,binding_digest)
        WHERE r.tenant_scope=NEW.tenant_scope AND r.binding_digest=binding
          AND r.dimension IN ('outputBytes','eventCount')
     LOOP
       UPDATE __SCHEMA__.quota_buckets SET
         used_units=used_units-(receipt.units-CASE receipt.dimension WHEN 'outputBytes' THEN actual_output ELSE actual_events END),
         updated_at=__SCHEMA__.db_millis()
       WHERE tenant_scope=NEW.tenant_scope AND policy_digest=receipt.policy_digest
         AND scope_kind=receipt.scope_kind AND scope_id=receipt.scope_id
         AND operation=receipt.operation AND dimension=receipt.dimension
         AND window_start=receipt.window_start
         AND used_units>=receipt.units-CASE receipt.dimension WHEN 'outputBytes' THEN actual_output ELSE actual_events END;
       GET DIAGNOSTICS changed = ROW_COUNT;
       IF changed<>1 THEN RAISE EXCEPTION 'execution reservation terminal refund fence is stale'; END IF;
     END LOOP;
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER outbox_settle_execution_reservation AFTER UPDATE OF state ON __SCHEMA__.outbox
 FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.settle_terminal_execution_reservation();

DROP FUNCTION __SCHEMA__.claim_outbox_bounded(bigint,text,text,bigint);
CREATE FUNCTION __SCHEMA__.claim_outbox_bounded(now_ms bigint, owner_id text, token_id text, until_ms bigint)
RETURNS TABLE(tenant_scope text,outbox_id bigint,dispatch_id text,task_id text,attempt_no bigint,max_attempts bigint,payload_json text,quota_binding_digest text,quota_reservation_id text,quota_reservation_version bigint,reserved_output_bytes bigint,reserved_event_count bigint,quota_policy_id text,quota_policy_revision bigint,quota_policy_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','claim-v1',true);
 RETURN QUERY
 WITH selected_tenant AS MATERIALIZED (
   SELECT s.tenant_scope FROM __SCHEMA__.outbox_tenant_scheduler s
    WHERE EXISTS (
      SELECT 1 FROM __SCHEMA__.outbox o WHERE o.tenant_scope=s.tenant_scope AND
       ((o.state='pending' AND o.available_at<=now_ms AND o.attempt_count<o.max_attempts)
        OR (o.state='leased' AND o.lease_until<=now_ms AND
           (o.attempt_count<o.max_attempts OR NOT EXISTS (
              SELECT 1 FROM __SCHEMA__.receiver_inbox r WHERE r.tenant_scope=o.tenant_scope
                AND r.dispatch_id=o.dispatch_id AND r.task_id=o.task_id
                AND r.state='processing' AND r.lease_until>now_ms)))))
    ORDER BY s.virtual_finish,s.served_sequence,s.tenant_scope
    FOR UPDATE OF s SKIP LOCKED LIMIT 1
 ), candidate AS (
   SELECT o.tenant_scope,o.outbox_id,
     (o.state='leased' AND o.lease_until<=now_ms AND o.attempt_count>=o.max_attempts) AS was_final
   FROM __SCHEMA__.outbox o JOIN selected_tenant s ON s.tenant_scope=o.tenant_scope
   WHERE (o.state='pending' AND o.available_at<=now_ms AND o.attempt_count<o.max_attempts)
      OR (o.state='leased' AND o.lease_until<=now_ms AND
         (o.attempt_count<o.max_attempts OR NOT EXISTS (
            SELECT 1 FROM __SCHEMA__.receiver_inbox r WHERE r.tenant_scope=o.tenant_scope
              AND r.dispatch_id=o.dispatch_id AND r.task_id=o.task_id
              AND r.state='processing' AND r.lease_until>now_ms)))
   ORDER BY o.available_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT 1
 ), claimed AS (
   UPDATE __SCHEMA__.outbox o SET state='leased',
     attempt_count=CASE WHEN o.attempt_count<o.max_attempts THEN o.attempt_count+1 ELSE o.attempt_count END,
     lease_owner=owner_id,lease_token=token_id,lease_until=until_ms,updated_at=now_ms
   FROM candidate c WHERE o.tenant_scope=c.tenant_scope AND o.outbox_id=c.outbox_id
   RETURNING o.tenant_scope,o.outbox_id,o.dispatch_id,o.task_id,o.attempt_count,o.max_attempts,o.payload_json,c.was_final,
     o.quota_binding_digest,o.quota_reservation_id,o.quota_reservation_version,o.reserved_output_bytes,o.reserved_event_count
 ), advanced AS (
   UPDATE __SCHEMA__.outbox_tenant_scheduler s SET virtual_finish=s.virtual_finish+1,
     served_sequence=nextval('__SCHEMA__.outbox_served_sequence'),updated_at=now_ms
    FROM claimed c WHERE s.tenant_scope=c.tenant_scope
   RETURNING s.served_sequence
 ), attempt AS (
   INSERT INTO __SCHEMA__.outbox_attempts(tenant_scope,outbox_id,attempt_no,lease_token,started_at)
   SELECT c.tenant_scope,c.outbox_id,c.attempt_count,token_id,now_ms FROM claimed c CROSS JOIN advanced
   ON CONFLICT ON CONSTRAINT outbox_attempts_pkey DO UPDATE
     SET lease_token=EXCLUDED.lease_token,started_at=EXCLUDED.started_at,
         finished_at=NULL,outcome=NULL,error=NULL,next_attempt_at=NULL
   RETURNING outbox_attempts.tenant_scope,outbox_attempts.outbox_id,outbox_attempts.attempt_no
 ), receiver_fence AS (
   UPDATE __SCHEMA__.receiver_inbox r SET sender_lease_token=token_id FROM claimed c
   WHERE c.was_final AND r.tenant_scope=c.tenant_scope AND r.dispatch_id=c.dispatch_id
     AND r.task_id=c.task_id AND r.sender_attempt_no=c.attempt_count
   RETURNING r.tenant_scope,r.dispatch_id
 )
 SELECT a.tenant_scope,a.outbox_id,c.dispatch_id,c.task_id,
   CASE WHEN c.was_final THEN -a.attempt_no ELSE a.attempt_no END,
   c.max_attempts,c.payload_json,c.quota_binding_digest,c.quota_reservation_id,
   c.quota_reservation_version,c.reserved_output_bytes,c.reserved_event_count,
   q.policy_id,q.policy_revision,q.policy_digest
 FROM attempt a JOIN claimed c ON c.tenant_scope=a.tenant_scope AND c.outbox_id=a.outbox_id
 LEFT JOIN __SCHEMA__.quota_execution_reservations q
   ON q.tenant_scope=c.tenant_scope AND q.reservation_id=c.quota_reservation_id;
END $$;

-- Retained authority uses one canonical representation for every durable row:
-- the UTF-8 byte length of PostgreSQL's deterministic jsonb object rendering.
-- Counter rows are deliberately outside the measured set, preventing recursion.
CREATE TABLE __SCHEMA__.retained_authority_usage(
 tenant_scope text NOT NULL CHECK(octet_length(tenant_scope) BETWEEN 1 AND 64),
 scope_kind text NOT NULL CHECK(scope_kind IN ('tenant','account','principal')),
 scope_id text NOT NULL CHECK(octet_length(scope_id) BETWEEN 1 AND 256),
 retained_bytes bigint NOT NULL CHECK(retained_bytes>=0),
 updated_at bigint NOT NULL CHECK(updated_at>0),
 PRIMARY KEY(tenant_scope,scope_kind,scope_id),
 CHECK((scope_kind='tenant' AND scope_id=tenant_scope) OR scope_kind IN ('account','principal'))
);
CREATE INDEX retained_authority_usage_principal ON __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes);

CREATE FUNCTION __SCHEMA__.row_retained_bytes(value anyelement) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT octet_length(to_jsonb(value)::text)::bigint
$$;

CREATE FUNCTION __SCHEMA__.retained_principal(value jsonb) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE principal text; binding text; account text; task text;
BEGIN
 principal := value->>'principal_scope';
 IF principal IS NOT NULL THEN RETURN principal; END IF;
 binding := value->>'binding_digest';
 IF binding IS NOT NULL THEN
   SELECT i.principal_scope INTO principal FROM __SCHEMA__.quota_intents i
    WHERE i.tenant_scope=value->>'tenant_scope' AND i.binding_digest=binding;
   IF principal IS NOT NULL THEN RETURN principal; END IF;
 END IF;
 account := COALESCE(value->>'owner_account_id',value->>'actor_account_id',value->>'account_id');
 IF account IS NOT NULL THEN RETURN 'account:'||account; END IF;
 task := value->>'task_id';
 IF task IS NOT NULL THEN
   SELECT 'account:'||t.owner_account_id INTO principal FROM __SCHEMA__.tasks t
    WHERE t.tenant_scope=value->>'tenant_scope' AND t.task_id=task;
 END IF;
 RETURN principal;
END $$;

CREATE FUNCTION __SCHEMA__.retained_account(value jsonb) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE account text; binding text; task text;
BEGIN
 account := COALESCE(value->>'owner_account_id',value->>'actor_account_id',value->>'account_id');
 IF account IS NOT NULL THEN RETURN account; END IF;
 binding := COALESCE(value->>'binding_digest',value->>'mutation_binding_digest');
 IF binding IS NOT NULL THEN
   SELECT i.account_id INTO account FROM __SCHEMA__.quota_intents i
    WHERE i.tenant_scope=value->>'tenant_scope' AND i.binding_digest=binding;
   IF account IS NOT NULL THEN RETURN account; END IF;
 END IF;
 task := value->>'task_id';
 IF task IS NOT NULL THEN
   SELECT t.owner_account_id INTO account FROM __SCHEMA__.tasks t
    WHERE t.tenant_scope=value->>'tenant_scope' AND t.task_id=task;
 END IF;
 RETURN account;
END $$;

CREATE FUNCTION __SCHEMA__.account_retained_authority_row() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE old_json jsonb; new_json jsonb; old_tenant text; new_tenant text;
        old_account text; new_account text; old_principal text; new_principal text;
        old_bytes bigint:=0; new_bytes bigint:=0; now_ms bigint;
        tenant_limit bigint; account_limit bigint; principal_limit bigint; current_bytes bigint;
BEGIN
 now_ms := __SCHEMA__.db_millis();
 IF TG_OP<>'INSERT' THEN old_json:=to_jsonb(OLD); old_tenant:=old_json->>'tenant_scope'; old_account:=__SCHEMA__.retained_account(old_json); old_principal:=__SCHEMA__.retained_principal(old_json); old_bytes:=__SCHEMA__.row_retained_bytes(OLD); END IF;
 IF TG_OP<>'DELETE' THEN new_json:=to_jsonb(NEW); new_tenant:=new_json->>'tenant_scope'; new_account:=__SCHEMA__.retained_account(new_json); new_principal:=__SCHEMA__.retained_principal(new_json); new_bytes:=__SCHEMA__.row_retained_bytes(NEW); END IF;

 IF old_tenant IS NOT NULL THEN
   UPDATE __SCHEMA__.retained_authority_usage SET retained_bytes=retained_bytes-old_bytes,updated_at=now_ms
    WHERE tenant_scope=old_tenant AND scope_kind='tenant' AND scope_id=old_tenant AND retained_bytes>=old_bytes;
   IF NOT FOUND THEN RAISE EXCEPTION 'retained authority tenant counter is missing or corrupt'; END IF;
   IF old_account IS NOT NULL THEN
     UPDATE __SCHEMA__.retained_authority_usage SET retained_bytes=retained_bytes-old_bytes,updated_at=now_ms
      WHERE tenant_scope=old_tenant AND scope_kind='account' AND scope_id=old_account AND retained_bytes>=old_bytes;
     IF NOT FOUND THEN RAISE EXCEPTION 'retained authority account counter is missing or corrupt'; END IF;
   END IF;
   IF old_principal IS NOT NULL THEN
     UPDATE __SCHEMA__.retained_authority_usage SET retained_bytes=retained_bytes-old_bytes,updated_at=now_ms
      WHERE tenant_scope=old_tenant AND scope_kind='principal' AND scope_id=old_principal AND retained_bytes>=old_bytes;
     IF NOT FOUND THEN RAISE EXCEPTION 'retained authority principal counter is missing or corrupt'; END IF;
   END IF;
 END IF;
 IF new_tenant IS NOT NULL THEN
   INSERT INTO __SCHEMA__.retained_authority_usage VALUES(new_tenant,'tenant',new_tenant,new_bytes,now_ms)
    ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at
    RETURNING retained_bytes INTO current_bytes;
   SELECT (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,tenant}')::bigint,
          (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,account}')::bigint,
          (canonical_json::jsonb#>>'{limits,retainedAuthorityBytes,principal}')::bigint
     INTO tenant_limit,account_limit,principal_limit FROM __SCHEMA__.quota_policy_versions
    WHERE tenant_scope=new_tenant AND lifecycle='active';
   tenant_limit:=COALESCE(tenant_limit,67108864);
   account_limit:=COALESCE(account_limit,67108864);
   principal_limit:=COALESCE(principal_limit,67108864);
   IF current_bytes>tenant_limit THEN RAISE EXCEPTION 'retained authority tenant quota exceeded' USING ERRCODE='53000'; END IF;
   IF new_account IS NOT NULL THEN
     INSERT INTO __SCHEMA__.retained_authority_usage VALUES(new_tenant,'account',new_account,new_bytes,now_ms)
      ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at
      RETURNING retained_bytes INTO current_bytes;
     IF current_bytes>account_limit THEN RAISE EXCEPTION 'retained authority account quota exceeded' USING ERRCODE='53000'; END IF;
   END IF;
   IF new_principal IS NOT NULL THEN
     INSERT INTO __SCHEMA__.retained_authority_usage VALUES(new_tenant,'principal',new_principal,new_bytes,now_ms)
      ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at
      RETURNING retained_bytes INTO current_bytes;
     IF current_bytes>principal_limit THEN RAISE EXCEPTION 'retained authority principal quota exceeded' USING ERRCODE='53000'; END IF;
   END IF;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;

-- Seed counters from the complete revision-3 canonical row oracle before any
-- accounting trigger can observe an UPDATE or DELETE of pre-existing data.
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
   EXECUTE format('INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) SELECT tenant_scope,''tenant'',tenant_scope,sum(__SCHEMA__.row_retained_bytes(r)),__SCHEMA__.db_millis() FROM __SCHEMA__.%I r GROUP BY tenant_scope ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at',t);
   EXECUTE format('INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) SELECT tenant_scope,''account'',__SCHEMA__.retained_account(to_jsonb(r)),sum(__SCHEMA__.row_retained_bytes(r)),__SCHEMA__.db_millis() FROM __SCHEMA__.%I r WHERE __SCHEMA__.retained_account(to_jsonb(r)) IS NOT NULL GROUP BY tenant_scope,__SCHEMA__.retained_account(to_jsonb(r)) ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at',t);
   EXECUTE format('INSERT INTO __SCHEMA__.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) SELECT tenant_scope,''principal'',__SCHEMA__.retained_principal(to_jsonb(r)),sum(__SCHEMA__.row_retained_bytes(r)),__SCHEMA__.db_millis() FROM __SCHEMA__.%I r WHERE __SCHEMA__.retained_principal(to_jsonb(r)) IS NOT NULL GROUP BY tenant_scope,__SCHEMA__.retained_principal(to_jsonb(r)) ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=__SCHEMA__.retained_authority_usage.retained_bytes+EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at',t);
 END LOOP;
END $$;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
   EXECUTE format('CREATE TRIGGER retained_authority_accounting AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.%I FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.account_retained_authority_row()',t);
 END LOOP;
END $$;

CREATE FUNCTION __SCHEMA__.retained_authority_oracle(wanted_tenant text,wanted_principal text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
   EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND ($2 IS NULL OR __SCHEMA__.retained_principal(to_jsonb(r))=$2)',t)
    INTO part USING wanted_tenant,wanted_principal;
   total:=total+part;
   IF total>9223372036854775807 THEN RAISE EXCEPTION 'retained authority oracle overflow'; END IF;
 END LOOP;
 RETURN total::bigint;
END $$;

CREATE FUNCTION __SCHEMA__.retained_authority_account_oracle(wanted_tenant text,wanted_account text) RETURNS bigint
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE t text; total numeric:=0; part numeric;
BEGIN
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
   EXECUTE format('SELECT COALESCE(sum(__SCHEMA__.row_retained_bytes(r)),0) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.retained_account(to_jsonb(r))=$2',t)
    INTO part USING wanted_tenant,wanted_account;
   total:=total+part;
   IF total>9223372036854775807 THEN RAISE EXCEPTION 'retained authority account oracle overflow'; END IF;
 END LOOP;
 RETURN total::bigint;
END $$;

CREATE OR REPLACE FUNCTION __SCHEMA__.authority_tenants_bounded() RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 RETURN QUERY SELECT tenant_scope FROM (
   SELECT tenant_scope FROM __SCHEMA__.tasks
   UNION SELECT tenant_scope FROM __SCHEMA__.task_events
   UNION SELECT tenant_scope FROM __SCHEMA__.idempotency_records
   UNION SELECT tenant_scope FROM __SCHEMA__.outbox
   UNION SELECT tenant_scope FROM __SCHEMA__.outbox_attempts
   UNION SELECT tenant_scope FROM __SCHEMA__.receiver_inbox
   UNION SELECT tenant_scope FROM __SCHEMA__.receiver_frames
   UNION SELECT tenant_scope FROM __SCHEMA__.loopback_effects
   UNION SELECT tenant_scope FROM __SCHEMA__.stream_transcripts
   UNION SELECT tenant_scope FROM __SCHEMA__.stream_frames
   UNION SELECT tenant_scope FROM __SCHEMA__.cancellation_intents
   UNION SELECT tenant_scope FROM __SCHEMA__.authorization_decisions
   UNION SELECT tenant_scope FROM __SCHEMA__.list_snapshots
   UNION SELECT tenant_scope FROM __SCHEMA__.list_snapshot_entries
   UNION SELECT tenant_scope FROM __SCHEMA__.list_page_tokens
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_reservations
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_policy_versions
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_policy_reconciliation_audits
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_intents
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_buckets
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_receipts
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_request_receipts
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_execution_reservations
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_allocations
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_leases
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_denial_audits
   UNION SELECT tenant_scope FROM __SCHEMA__.quota_override_audits
   UNION SELECT tenant_scope FROM __SCHEMA__.retained_authority_usage
   UNION SELECT tenant_scope FROM __SCHEMA__.outbox_tenant_scheduler
 ) scopes ORDER BY tenant_scope;
END $$;

CREATE FUNCTION __SCHEMA__.authority_retained_scopes_bounded(wanted_tenant text,wanted_kind text) RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t text; expression text;
BEGIN
 IF wanted_kind NOT IN ('account','principal') THEN RAISE EXCEPTION 'invalid retained scope kind'; END IF;
 PERFORM set_config('smesh.internal_global','diag-v1',true);
 expression:=CASE wanted_kind WHEN 'account' THEN 'retained_account' ELSE 'retained_principal' END;
 FOREACH t IN ARRAY ARRAY[
  'tasks','task_events','idempotency_records','outbox','outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames',
  'loopback_effects','stream_transcripts','stream_frames','cancellation_intents','authorization_decisions',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions','quota_policy_reconciliation_audits',
  'quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases',
  'quota_denial_audits','quota_override_audits'
 ] LOOP
   RETURN QUERY EXECUTE format('SELECT DISTINCT __SCHEMA__.%I(to_jsonb(r)) FROM __SCHEMA__.%I r WHERE tenant_scope=$1 AND __SCHEMA__.%I(to_jsonb(r)) IS NOT NULL',expression,t,expression)
    USING wanted_tenant;
 END LOOP;
END $$;

CREATE INDEX quota_denial_audits_expiry ON __SCHEMA__.quota_denial_audits(denied_at,tenant_scope,decision_key);
CREATE INDEX quota_override_audits_expiry ON __SCHEMA__.quota_override_audits(expires_at,tenant_scope,override_id);
CREATE INDEX quota_leases_gc ON __SCHEMA__.quota_leases(tenant_scope,state,lease_until,lease_id);

-- Quota evidence replay horizon: 86400000 ms (24 hours).  A task-bound
-- intent has no finite retention_until because tasks/idempotency/outbox/receiver/
-- transcript/cancellation rows currently have no deletion lifecycle.  Their complete
-- receipt/reservation chain is therefore retained.  Taskless read/list/egress
-- evidence is collectible only after the horizon and only when no durable
-- authorization decision or lease still names it.  Detail deletion is child-first.
CREATE FUNCTION __SCHEMA__.gc_quota_authority_bounded(now_ms bigint,max_rows integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE removed integer:=0; changed integer;
BEGIN
 IF max_rows<1 OR max_rows>1000 THEN RAISE EXCEPTION 'gc max_rows must be between 1 and 1000'; END IF;
 PERFORM set_config('smesh.internal_global','quota-gc-v1',true);
 WITH doomed AS (SELECT ctid FROM __SCHEMA__.quota_denial_audits WHERE denied_at<=now_ms-86400000 ORDER BY denied_at,tenant_scope,decision_key FOR UPDATE SKIP LOCKED LIMIT max_rows)
 DELETE FROM __SCHEMA__.quota_denial_audits q USING doomed d WHERE q.ctid=d.ctid;
 GET DIAGNOSTICS removed=ROW_COUNT;
 IF removed<max_rows THEN
   WITH doomed AS (SELECT ctid FROM __SCHEMA__.quota_override_audits WHERE expires_at<=now_ms ORDER BY expires_at,tenant_scope,override_id FOR UPDATE SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_override_audits q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (SELECT ctid FROM __SCHEMA__.quota_leases WHERE state IN ('released','expired') AND retention_until<=now_ms ORDER BY retention_until,tenant_scope,lease_id FOR UPDATE SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_leases q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (SELECT ctid FROM __SCHEMA__.quota_allocations WHERE state='released' AND retention_until<=now_ms ORDER BY retention_until,tenant_scope,binding_digest,scope_kind,scope_id,dimension FOR UPDATE SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_allocations q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (
     SELECT q.ctid FROM __SCHEMA__.quota_execution_reservations q
      WHERE q.state='settled' AND q.retention_until<=now_ms
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.outbox o WHERE o.tenant_scope=q.tenant_scope AND o.quota_reservation_id=q.reservation_id)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.receiver_inbox r WHERE r.tenant_scope=q.tenant_scope AND r.quota_reservation_id=q.reservation_id)
      ORDER BY q.retention_until,q.tenant_scope,q.reservation_id FOR UPDATE OF q SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_execution_reservations q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (SELECT ctid FROM __SCHEMA__.quota_request_receipts WHERE retention_until<=now_ms ORDER BY retention_until,tenant_scope,invocation_id FOR UPDATE SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_request_receipts q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (
     SELECT r.ctid FROM __SCHEMA__.quota_receipts r JOIN __SCHEMA__.quota_intents i USING(tenant_scope,binding_digest)
      WHERE i.task_id IS NULL AND r.retention_until<=now_ms
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_leases l WHERE l.tenant_scope=r.tenant_scope AND l.binding_digest=r.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_execution_reservations e WHERE e.tenant_scope=r.tenant_scope AND e.binding_digest=r.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_allocations a WHERE a.tenant_scope=r.tenant_scope AND a.binding_digest=r.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.authorization_decisions d WHERE d.tenant_scope=i.tenant_scope AND d.decision_id=i.semantic_id)
      ORDER BY r.retention_until,r.tenant_scope,r.binding_digest,r.scope_kind,r.scope_id,r.dimension FOR UPDATE OF r SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_receipts q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (
     SELECT i.ctid FROM __SCHEMA__.quota_intents i
      WHERE i.task_id IS NULL AND i.retention_until<=now_ms
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_receipts r WHERE r.tenant_scope=i.tenant_scope AND r.binding_digest=i.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_leases l WHERE l.tenant_scope=i.tenant_scope AND l.binding_digest=i.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_execution_reservations e WHERE e.tenant_scope=i.tenant_scope AND e.binding_digest=i.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_allocations a WHERE a.tenant_scope=i.tenant_scope AND a.binding_digest=i.binding_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.authorization_decisions d WHERE d.tenant_scope=i.tenant_scope AND d.decision_id=i.semantic_id)
      ORDER BY i.retention_until,i.tenant_scope,i.binding_digest FOR UPDATE OF i SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_intents q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (
     SELECT b.ctid FROM __SCHEMA__.quota_buckets b
      WHERE b.retention_until<=now_ms
        AND (b.algorithm<>'gauge' OR b.used_units=0)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_receipts r JOIN __SCHEMA__.quota_intents i USING(tenant_scope,binding_digest)
          WHERE r.tenant_scope=b.tenant_scope AND i.policy_digest=b.policy_digest AND r.scope_kind=b.scope_kind AND r.scope_id=b.scope_id
            AND i.operation=b.operation AND r.dimension=b.dimension AND r.window_start=b.window_start)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_request_receipts r
          WHERE r.tenant_scope=b.tenant_scope AND r.policy_digest=b.policy_digest AND r.scope_kind=b.scope_kind AND r.scope_id=b.scope_id
            AND r.operation=b.operation AND r.dimension=b.dimension AND r.window_start=b.window_start)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_allocations a JOIN __SCHEMA__.quota_intents i USING(tenant_scope,binding_digest)
          WHERE a.tenant_scope=b.tenant_scope AND a.state='active' AND i.policy_digest=b.policy_digest AND a.scope_kind=b.scope_kind
            AND a.scope_id=b.scope_id AND i.operation=b.operation AND a.dimension=b.dimension)
      ORDER BY b.retention_until,b.tenant_scope,b.policy_digest,b.scope_kind,b.scope_id,b.operation,b.dimension,b.window_start FOR UPDATE OF b SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_buckets q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 IF removed<max_rows THEN
   WITH doomed AS (
     SELECT p.ctid FROM __SCHEMA__.quota_policy_versions p
      WHERE p.lifecycle IN ('draining','retired') AND p.retired_at<=now_ms-86400000
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_intents i WHERE i.tenant_scope=p.tenant_scope AND i.policy_digest=p.policy_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_buckets b WHERE b.tenant_scope=p.tenant_scope AND b.policy_digest=p.policy_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_request_receipts r WHERE r.tenant_scope=p.tenant_scope AND r.policy_digest=p.policy_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_execution_reservations e WHERE e.tenant_scope=p.tenant_scope AND e.policy_digest=p.policy_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_override_audits o WHERE o.tenant_scope=p.tenant_scope AND o.policy_digest=p.policy_digest)
        AND NOT EXISTS (SELECT 1 FROM __SCHEMA__.quota_policy_reconciliation_audits a WHERE a.tenant_scope=p.tenant_scope AND (a.old_policy_digest=p.policy_digest OR a.new_policy_digest=p.policy_digest))
      ORDER BY p.retired_at,p.tenant_scope,p.policy_id,p.policy_revision FOR UPDATE OF p SKIP LOCKED LIMIT max_rows-removed)
   DELETE FROM __SCHEMA__.quota_policy_versions q USING doomed d WHERE q.ctid=d.ctid;
   GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 END IF;
 RETURN removed;
END $$;

DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['outbox_tenant_scheduler','quota_policy_versions','quota_policy_reconciliation_audits','quota_intents','quota_buckets','quota_receipts','quota_request_receipts','quota_execution_reservations','quota_allocations','quota_leases','quota_denial_audits','quota_override_audits','retained_authority_usage'] LOOP
   EXECUTE format('ALTER TABLE __SCHEMA__.%I ENABLE ROW LEVEL SECURITY',t);
   EXECUTE format('ALTER TABLE __SCHEMA__.%I FORCE ROW LEVEL SECURITY',t);
   EXECUTE format('CREATE POLICY tenant_isolation ON __SCHEMA__.%I FOR ALL TO __ROLE__ USING (tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),'''')) WITH CHECK (tenant_scope=NULLIF(current_setting(''smesh.tenant_scope'',true),''''))',t);
 END LOOP;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY[
  'outbox_attempts','outbox_tenant_scheduler','receiver_inbox','receiver_frames','stream_transcripts','stream_frames','cancellation_intents',
  'list_snapshots','list_snapshot_entries','list_page_tokens','quota_reservations','quota_policy_versions',
  'quota_policy_reconciliation_audits','quota_intents','quota_buckets','quota_receipts','quota_request_receipts',
  'quota_execution_reservations','quota_allocations','quota_leases','quota_denial_audits','quota_override_audits','retained_authority_usage'
 ] LOOP
   EXECUTE format('CREATE POLICY internal_quota_diagnostics ON __SCHEMA__.%I FOR SELECT USING (current_user=''__MIGRATOR__'' AND current_setting(''smesh.internal_global'',true)=''diag-v1'')',t);
 END LOOP;
END $$;
CREATE POLICY internal_claim_execution_reservations ON __SCHEMA__.quota_execution_reservations FOR SELECT
 USING (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
CREATE POLICY internal_claim_tenant_scheduler ON __SCHEMA__.outbox_tenant_scheduler FOR ALL
 USING (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1')
 WITH CHECK (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
-- Retained attribution follows immutable task ownership and quota intent bindings.
-- Global fair/outbox claims run without a tenant GUC, so these bounded lookups must
-- remain visible to the migrator-owned claim procedure while accounting its writes.
CREATE POLICY internal_claim_retained_task_attribution ON __SCHEMA__.tasks FOR SELECT
 USING (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
CREATE POLICY internal_claim_retained_intent_attribution ON __SCHEMA__.quota_intents FOR SELECT
 USING (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
CREATE POLICY internal_scheduler_accounting ON __SCHEMA__.retained_authority_usage FOR ALL
 USING (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1' AND tenant_scope='__scheduler__')
 WITH CHECK (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1' AND tenant_scope='__scheduler__');
CREATE POLICY internal_claim_retained_accounting ON __SCHEMA__.retained_authority_usage FOR ALL
 USING (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1')
 WITH CHECK (current_user='__MIGRATOR__' AND current_setting('smesh.internal_global',true)='claim-v1');
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['quota_policy_versions','quota_policy_reconciliation_audits','quota_buckets','retained_authority_usage'] LOOP
   EXECUTE format('CREATE POLICY internal_quota_reconcile ON __SCHEMA__.%I FOR ALL USING (current_user=''__MIGRATOR__'' AND current_setting(''smesh.internal_global'',true)=''reconcile-v1'') WITH CHECK (current_user=''__MIGRATOR__'' AND current_setting(''smesh.internal_global'',true)=''reconcile-v1'')',t);
 END LOOP;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['quota_denial_audits','quota_override_audits','quota_leases','quota_allocations','quota_execution_reservations','quota_receipts','quota_request_receipts','quota_intents','quota_buckets','quota_policy_versions','retained_authority_usage'] LOOP
   EXECUTE format('CREATE POLICY internal_quota_gc ON __SCHEMA__.%I FOR ALL USING (current_user=''__MIGRATOR__'' AND current_setting(''smesh.internal_global'',true)=''quota-gc-v1'') WITH CHECK (current_user=''__MIGRATOR__'' AND current_setting(''smesh.internal_global'',true)=''quota-gc-v1'')',t);
 END LOOP;
END $$;
GRANT SELECT ON __SCHEMA__.outbox_tenant_scheduler TO __ROLE__;
GRANT USAGE,SELECT ON SEQUENCE __SCHEMA__.outbox_served_sequence TO __ROLE__;
GRANT SELECT,INSERT,UPDATE ON __SCHEMA__.retained_authority_usage TO __ROLE__;
GRANT SELECT,INSERT ON __SCHEMA__.quota_policy_versions,__SCHEMA__.quota_policy_reconciliation_audits,__SCHEMA__.quota_intents,__SCHEMA__.quota_receipts,__SCHEMA__.quota_request_receipts,__SCHEMA__.quota_denial_audits,__SCHEMA__.quota_override_audits TO __ROLE__;
GRANT SELECT,INSERT,UPDATE ON __SCHEMA__.quota_execution_reservations TO __ROLE__;
GRANT SELECT,INSERT,UPDATE ON __SCHEMA__.quota_buckets,__SCHEMA__.quota_allocations,__SCHEMA__.quota_leases TO __ROLE__;
REVOKE ALL ON FUNCTION __SCHEMA__.ensure_outbox_tenant_scheduler() FROM PUBLIC;
REVOKE ALL ON FUNCTION __SCHEMA__.authority_retained_scopes_bounded(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION __SCHEMA__.authority_retained_scopes_bounded(text,text) TO __ROLE__;
