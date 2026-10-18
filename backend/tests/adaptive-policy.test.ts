import assert from 'assert';
import { adaptivePolicy, levelOf, REASON, RISK } from '../src/security/policy';
import type { AccessSignals, DeviceAssessment, RiskAssessment } from '../src/security/types';

const sig = (classification: AccessSignals['resource']['classification'], extra: Partial<AccessSignals> = {}): AccessSignals => ({
  userId: 'u1', email: 'a@b.c', role: 'user', action: 'download', via: 'direct',
  resource: { type: 'file', id: 'f1', classification }, ...extra,
});
const risk = (score: number, reasons: string[] = []): RiskAssessment => ({ score, level: levelOf(score), reasons });
const known: DeviceAssessment = { trusted: true, reasons: [] };
const unknown: DeviceAssessment = { trusted: false, reasons: ['user_agent_not_seen_before'] };
const decide = (s: AccessSignals, r: RiskAssessment, d: DeviceAssessment = known) => adaptivePolicy.decide(s, r, d).decision;

// ---- low risk: allow everything the access rules already allow ----
for (const c of ['public', 'internal', 'confidential', 'restricted'] as const) assert.equal(decide(sig(c), risk(0)), 'ALLOW', c);

// ---- a new device alone never changes the outcome for non-sensitive files and cannot deny anything ----
assert.equal(decide(sig('internal'), risk(0), unknown), 'ALLOW');
assert.equal(decide(sig('restricted'), risk(0), unknown), 'ALLOW', 'new device alone (20) stays below medium');
assert.notEqual(decide(sig('restricted'), risk(0), unknown), 'DENY');

// ---- medium risk (new device + repeated failed logins = 40) ----
const medium = risk(RISK.points.failedRepeated, [`${REASON.FAILED_LOGINS}:3`]);
assert.equal(decide(sig('public'), medium, unknown), 'ALLOW');
assert.equal(decide(sig('internal'), medium, unknown), 'ALLOW');
assert.equal(decide(sig('confidential'), medium, unknown), 'REQUIRE_APPROVAL');
assert.equal(decide(sig('restricted'), medium, unknown), 'REQUIRE_APPROVAL');
// ...unless the owner already approved this user through an access request, or the user is the owner
assert.equal(decide(sig('confidential', { hasApprovedGrant: true }), medium, unknown), 'ALLOW');
assert.equal(decide(sig('confidential', { isOwner: true }), medium, unknown), 'ALLOW');

// ---- high risk ----
const high = risk(RISK.points.failedMany + RISK.points.volumeHigh, [`${REASON.FAILED_LOGINS}:6`, `${REASON.DOWNLOAD_VOLUME}:20/h`]);
assert.equal(decide(sig('public'), high), 'REQUIRE_APPROVAL');
assert.equal(decide(sig('internal', { hasApprovedGrant: true }), high), 'ALLOW');
assert.equal(decide(sig('confidential'), high), 'DENY');
assert.equal(decide(sig('restricted', { hasApprovedGrant: true }), high), 'DENY', 'approval does not override high risk on sensitive files');
assert.equal(decide(sig('restricted', { isOwner: true }), high), 'DENY');

// ---- revoked / signed-out session is always denied ----
for (const c of ['public', 'internal', 'confidential', 'restricted'] as const) {
  assert.equal(decide(sig(c, { isOwner: true }), risk(RISK.points.noActiveSession, [REASON.NO_ACTIVE_SESSION])), 'DENY', c);
}

// ---- score is capped and reasons are reported ----
const v = adaptivePolicy.decide(sig('internal'), risk(100, [REASON.NO_ACTIVE_SESSION]), unknown);
assert.match(v.reason, /score=100 level=high/);
assert.match(v.reason, /new_device/);

console.log('adaptive policy decisions: OK');
