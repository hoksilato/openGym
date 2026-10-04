// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../lib/api.js', () => ({ api: vi.fn(), setRemoteAuth: vi.fn() }))
vi.mock('./useUI.js', () => ({ useUI: { getState: () => ({ toast: vi.fn() }) } }))

import { api } from '../lib/api.js'
import { DEF, useStore } from './useStore.js'

const clone = value => JSON.parse(JSON.stringify(value))
const A = { id: 'account-a', name: 'A' }, B = { id: 'account-b', name: 'B' }
const state = id => ({ ...clone(DEF), _ts: 100, workouts: [{ id, d: '2026-09-01', start: 1, entries: [] }] })
const ids = () => useStore.getState().S.workouts.map(w => w.id)
const puts = () => api.mock.calls.filter(([, opts]) => opts?.method === 'PUT').map(([, opts]) => JSON.parse(opts.body))
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const switchToB = () => {
  useStore.getState().setUser(B)
  useStore.setState({ S: state('b-workout') })
}

beforeEach(() => {
  vi.useFakeTimers()
  useStore.getState().setUser(null)
  localStorage.clear()
  api.mockReset()
  useStore.setState({ S: state('a-local'), ready: true, config: null, sync: { offline: false, pending: false, lastSynced: 0 } })
  useStore.getState().setUser(A)
})
afterEach(() => {
  useStore.getState().setUser(null)
  localStorage.clear()
  vi.useRealTimers()
})

describe('data sync belongs to the account that started it', () => {
  it('never pulls account state without a known signed-in identity', async () => {
    useStore.getState().setUser(null)
    await useStore.getState().pullState()
    expect(api).not.toHaveBeenCalled()
  })

  it('identifies every outgoing state with its owner for the server-side cookie-switch fence', async () => {
    api.mockResolvedValue({ uid: A.id, ok: true, rev: 1 })
    await useStore.getState().pushState()
    expect(puts()).toHaveLength(1)
    expect(puts()[0].uid).toBe(A.id)
  })

  it('does not start a push from a stale tab even before its owner storage event arrives', async () => {
    localStorage.setItem('gym_owner', B.id)
    await useStore.getState().pushState()
    expect(api).not.toHaveBeenCalled()
  })

  it('does not relabel A’s in-memory copy as B when another tab already changed the shared owner', () => {
    useStore.getState().update(s => { s.restSec = 30 })
    localStorage.setItem('gym_owner', B.id)
    useStore.getState().setUser(B)
    expect(ids()).toEqual([])
    const kept = Object.values(JSON.parse(localStorage.getItem('gym_stash')))
    expect(kept).toHaveLength(1)
    expect(kept[0].uid).toBe(A.id)
    expect(kept[0].state.workouts.map(w => w.id)).toEqual(['a-local'])
  })

  it('keeps a stale tab’s last edit out of B’s shared saved copy, then stashes it only for A', () => {
    const shared = JSON.stringify(state('b-saved'))
    localStorage.setItem('gym_state_v1', shared)
    localStorage.setItem('gym_owner', B.id)
    useStore.getState().update(s => { s.restSec = 30 })
    expect(localStorage.getItem('gym_state_v1')).toBe(shared)
    window.dispatchEvent(new StorageEvent('storage', { key: 'gym_owner', newValue: B.id }))
    expect(useStore.getState().user).toBeNull()
    expect(ids()).toEqual([])
    expect(localStorage.getItem('gym_state_v1')).toBe(shared)
    const kept = Object.values(JSON.parse(localStorage.getItem('gym_stash')))
    expect(kept[0].uid).toBe(A.id)
    expect(kept[0].state.restSec).toBe(30)
    expect(kept[0].state.workouts.map(w => w.id)).toEqual(['a-local'])
    expect(api).not.toHaveBeenCalled()
  })

  it('remembers the in-memory copy’s owner after expiration while another tab signs in as B', () => {
    useStore.getState().update(s => { s.restSec = 30 })
    useStore.getState().setUser(null)
    localStorage.setItem('gym_owner', B.id)
    useStore.getState().setUser(B)
    expect(ids()).toEqual([])
    const kept = Object.values(JSON.parse(localStorage.getItem('gym_stash')))
    expect(kept[0].uid).toBe(A.id)
  })

  it('discards account A’s delayed pull after account B signs in', async () => {
    const request = deferred()
    api.mockReturnValue(request.promise)
    const pull = useStore.getState().pullState()
    switchToB()
    request.resolve({ uid: A.id, state: state('a-server'), rev: 5 })
    await pull
    expect(ids()).toEqual(['b-workout'])
    expect(puts()).toEqual([])
    expect(localStorage.getItem('gym_sync')).toBeNull()
  })

  it('discards a new cookie’s account B response before its owner storage event arrives', async () => {
    api.mockResolvedValue({ uid: B.id, state: state('b-server'), rev: 5 })
    await useStore.getState().pullState()
    expect(ids()).toEqual(['a-local'])
    expect(puts()).toEqual([])
    expect(localStorage.getItem('gym_sync')).toBeNull()
  })

  it('never merges or retries A’s delayed conflict under B’s session', async () => {
    const request = deferred()
    api.mockReturnValue(request.promise)
    const push = useStore.getState().pushState()
    switchToB()
    request.reject(Object.assign(new Error('conflict'), { status: 409, data: { uid: A.id, state: state('a-server'), rev: 5 } }))
    await push
    expect(ids()).toEqual(['b-workout'])
    expect(puts()).toHaveLength(1)
    expect(puts()[0].uid).toBe(A.id)
    expect(localStorage.getItem('gym_sync')).toBeNull()
  })

  it('does not clear B’s pending marker when A’s old write succeeds', async () => {
    const request = deferred()
    api.mockReturnValue(request.promise)
    const push = useStore.getState().pushState()
    switchToB()
    localStorage.setItem('gym_dirty', '1')
    request.resolve({ uid: A.id, ok: true, rev: 5 })
    await push
    expect(localStorage.getItem('gym_dirty')).toBe('1')
    expect(localStorage.getItem('gym_sync')).toBeNull()
    expect(ids()).toEqual(['b-workout'])
  })

  it('discards an old response even if the same account signs back in after signing out', async () => {
    const request = deferred()
    api.mockReturnValue(request.promise)
    const pull = useStore.getState().pullState()
    useStore.getState().setUser(null)
    useStore.getState().setUser(A)
    useStore.setState({ S: state('a-new-session') })
    request.resolve({ uid: A.id, state: state('a-old-session'), rev: 5 })
    await pull
    expect(ids()).toEqual(['a-new-session'])
    expect(puts()).toEqual([])
  })

  it('a late adoption answer cannot import A’s entries into B', async () => {
    const question = deferred()
    const ask = vi.fn(() => question.promise)
    api.mockResolvedValue({ uid: A.id, state: state('a-server'), rev: 1 })
    const adoption = useStore.getState().adoptProfile(ask)
    await vi.waitFor(() => expect(ask).toHaveBeenCalled())
    switchToB()
    question.resolve(true)
    expect(await adoption).toEqual({ cancelled: true })
    expect(ids()).toEqual(['b-workout'])
    expect(puts()).toEqual([])
  })

  it('lets B adopt while A’s old adoption fetch is still pending', async () => {
    const request = deferred()
    api.mockReturnValueOnce(request.promise)
    const oldAdoption = useStore.getState().adoptProfile(async () => true)
    useStore.getState().setUser(B, { adopt: true })
    api.mockResolvedValue({ uid: B.id, state: state('b-server'), rev: 7 })
    await useStore.getState().adoptProfile(async () => false)
    request.resolve({ uid: A.id, state: state('a-server'), rev: 2 })
    expect(await oldAdoption).toEqual({ cancelled: true })
    expect(ids()).toEqual(['b-server'])
    expect(localStorage.getItem('gym_adopt')).toBeNull()
    expect(puts()).toEqual([])
  })

  it('a delayed revision check cannot mark the next account as synced', async () => {
    localStorage.setItem('gym_sync', JSON.stringify({ rev: 1, ts: 100 }))
    useStore.setState({ S: state('a-local') })
    const request = deferred()
    api.mockReturnValue(request.promise)
    window.dispatchEvent(new Event('online'))
    expect(api).toHaveBeenCalledWith('/api/data/rev')
    switchToB()
    request.resolve({ uid: A.id, rev: 1 })
    await Promise.resolve(); await Promise.resolve()
    expect(localStorage.getItem('gym_synced_at')).toBeNull()
    expect(puts()).toEqual([])
  })
})
