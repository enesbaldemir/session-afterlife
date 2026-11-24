// Planning for server-side timeout measurements. Pure state machine: the
// background worker calls `start`, waits `nextDelayUnits` time units, probes,
// and feeds the verdict to `advance`.
//
// Idle timeout: wait without touching the session, then probe once. Every
// successful probe resets the server's idle timer, so the waits can grow. The
// first failure after waiting W (previous success after V) means the idle
// timeout lies in (V, W].
//
// Absolute timeout: keep the session busy with a probe every `interval`, so
// idle expiry cannot happen, and record when it still dies.

// Waits in units (minutes by default). About 1.4x growth, 24h worst case.
export const IDLE_WAITS = [1, 2, 3, 5, 8, 12, 18, 25, 35, 50, 70, 100, 140, 200, 300, 480];

export function startIdle({ maxUnits = 480, waits = IDLE_WAITS } = {}) {
  const plan = waits.filter((w) => w <= maxUnits);
  if (plan.length === 0 || plan[plan.length - 1] < maxUnits) plan.push(maxUnits);
  return { mode: 'idle', plan, step: 0, lastOk: 0, history: [], done: false, result: null };
}

export function startAbsolute({ intervalUnits = 5, maxUnits = 1440 } = {}) {
  return { mode: 'absolute', intervalUnits, maxUnits, elapsed: 0, lastOk: 0, history: [], done: false, result: null };
}

export function nextDelayUnits(state) {
  if (state.done) return null;
  if (state.mode === 'idle') return state.plan[state.step];
  return Math.min(state.intervalUnits, state.maxUnits - state.elapsed);
}

// verdict: 'STILL_VALID' | 'INVALIDATED' | 'INCONCLUSIVE'
export function advance(state, verdict, waitedUnits = nextDelayUnits(state)) {
  const s = structuredClone(state);
  s.history.push({ waited: waitedUnits, verdict });

  if (verdict === 'INCONCLUSIVE') {
    s.done = true;
    s.result = { kind: 'inconclusive', text: 'A probe gave no clear answer, so the measurement stopped.' };
    return s;
  }

  if (s.mode === 'idle') {
    const w = s.plan[s.step];
    if (verdict === 'INVALIDATED') {
      s.done = true;
      s.result = { kind: 'expired', lowerUnits: s.lastOk, upperUnits: w };
      return s;
    }
    s.lastOk = w;
    s.step += 1;
    if (s.step >= s.plan.length) {
      s.done = true;
      s.result = { kind: 'survived', units: w };
    }
    return s;
  }

  // absolute
  s.elapsed += waitedUnits;
  if (verdict === 'INVALIDATED') {
    s.done = true;
    s.result = { kind: 'expired', lowerUnits: s.lastOk, upperUnits: s.elapsed };
    return s;
  }
  s.lastOk = s.elapsed;
  if (s.elapsed >= s.maxUnits) {
    s.done = true;
    s.result = { kind: 'survived', units: s.elapsed };
  }
  return s;
}

export function describeResult(state, unitName = 'min') {
  const r = state.result;
  if (!r) return 'Measurement in progress.';
  const u = (x) => `${x} ${unitName}`;
  if (r.kind === 'inconclusive') return r.text;
  if (state.mode === 'idle') {
    if (r.kind === 'expired') {
      return r.lowerUnits === 0
        ? `The session expired after less than ${u(r.upperUnits)} of inactivity.`
        : `Idle timeout is between ${u(r.lowerUnits)} and ${u(r.upperUnits)}.`;
    }
    return `The session was still valid after ${u(r.units)} of inactivity.`;
  }
  if (r.kind === 'expired') {
    return `Although it was kept active, the session ended between ${u(r.lowerUnits)} and ${u(r.upperUnits)} after the measurement started.`;
  }
  return `The session was kept active for ${u(r.units)} and never ended.`;
}
