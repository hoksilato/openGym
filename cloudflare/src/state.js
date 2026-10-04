/* Cloudflare state repository, AGPL-3.0-or-later. No filesystem or isolate-local truth. */
export const MAX_BODY = 5 * 1024 * 1024;
// UTF-16 slicing can split a surrogate pair. The encoder-independent loop below keeps
// code points intact; even worst-case UTF-8 chunks stay comfortably under D1's row cap.
export const CHUNK_CHARS = 256 * 1024;
export function chunkText(text) {
  const chunks = [];
  for (let start = 0; start < text.length;) {
    let end = Math.min(text.length, start + CHUNK_CHARS);
    const last = text.charCodeAt(end - 1);
    if (end < text.length && last >= 0xD800 && last <= 0xDBFF) end--;
    chunks.push(text.slice(start, end)); start = end;
  }
  return chunks;
}
export const records = value => Array.isArray(value) ? value.filter(x => x && typeof x === 'object' && !Array.isArray(x)) : [];
export async function readHead(env, uid) {
  return await env.DB.prepare('SELECT revision,write_id,updated_at,last_pull FROM state_heads WHERE user_id=?').bind(uid).first();
}
export async function readState(env, uid) {
  // One SQL statement reads a consistent committed manifest and its chunks. A separate
  // head/parts read could race cleanup after publication of a newer version.
  const { results } = await env.DB.prepare(`SELECT p.part_no,p.data FROM state_heads h
    JOIN state_parts p ON p.user_id=h.user_id AND p.write_id=h.write_id
    WHERE h.user_id=? ORDER BY p.part_no`).bind(uid).all();
  if (!results.length) return null;
  if (results.some((row, index) => row.part_no !== index)) throw new Error('incomplete state manifest');
  return JSON.parse(results.map(row => row.data).join(''));
}
export function prepareState(body, current) {
  if (!body.state || typeof body.state !== 'object') return { error: 'state required', status: 400 };
  if (!Array.isArray(body.state) && !Object.keys(body.state).some(k => k !== '_rev' && k !== '_ts')) return { error: 'state required', status: 400 };
  const list = v => v == null || Array.isArray(v);
  if (Array.isArray(body.state) || !list(body.state.workouts) || !list(body.state.routines)) return { error: 'invalid state', status: 400 };
  const rev = current?._rev || 0;
  if (body.baseRev != null && body.baseRev !== rev) return { error: 'conflict', status: 409, rev, state: current };
  const next = { ...body.state };
  for (const k of ['workouts', 'routines']) if (Array.isArray(next[k])) next[k] = records(next[k]);
  delete next.active;
  if ((Number(current?.resetAt) || 0) > (Number(next.resetAt) || 0)) {
    next.resetAt = current.resetAt;
    if (current.resetIds && typeof current.resetIds === 'object') next.resetIds = current.resetIds;
    else delete next.resetIds;
  }
  next._rev = rev + 1;
  return { state: next, rev: rev + 1, previousRev: rev };
}
export async function writeState(env, uid, body) {
  const current = await readState(env, uid);
  const result = prepareState(body, current);
  if (result.error) return result;
  const text = JSON.stringify(result.state);
  if (new TextEncoder().encode(text).byteLength > MAX_BODY) return { error: 'body too large', status: 413 };
  const writeId = crypto.randomUUID();
  const parts = chunkText(text);
  // Batch is one D1 transaction. Chunks may only be inserted when the expected head
  // still matches; the conditional UPDATE is the publication/CAS point. A competing
  // writer cannot expose half a document or delete another writer's selected version.
  const statements = [env.DB.prepare('INSERT OR IGNORE INTO state_heads(user_id) VALUES(?)').bind(uid)];
  for (let n = 0; n < parts.length; n++) statements.push(env.DB.prepare(`INSERT INTO state_parts(user_id,write_id,part_no,data)
    SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM state_heads WHERE user_id=? AND revision=?)`)
    .bind(uid, writeId, n, parts[n], uid, result.previousRev));
  const publishIndex = statements.length;
  const workouts = records(result.state.workouts);
  const lastDate = workouts.at(-1)?.d;
  statements.push(env.DB.prepare(`UPDATE state_heads SET revision=?,write_id=?,updated_at=?,workout_count=?,last_workout=?,state_ts=?
    WHERE user_id=? AND revision=?`).bind(result.rev, writeId, Date.now(), workouts.length,
    typeof lastDate === 'string' ? lastDate.slice(0, 32) : null,
    Number.isFinite(Number(result.state._ts)) ? Number(result.state._ts) : 0, uid, result.previousRev));
  statements.push(env.DB.prepare(`DELETE FROM state_parts WHERE user_id=? AND write_id !=
    (SELECT write_id FROM state_heads WHERE user_id=?)`).bind(uid, uid));
  const executed = await env.DB.batch(statements);
  if (!executed[publishIndex].meta.changes) {
    const fresh = await readState(env, uid);
    return { error: 'conflict', status: 409, rev: fresh?._rev || 0, state: fresh };
  }
  return result;
}
export async function notePull(env, uid) {
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO state_heads(user_id,last_pull) VALUES(?,?)
    ON CONFLICT(user_id) DO UPDATE SET last_pull=excluded.last_pull WHERE state_heads.last_pull<?`)
    .bind(uid, now, now - 600000).run();
}
