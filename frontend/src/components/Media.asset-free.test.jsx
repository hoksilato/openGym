// @vitest-environment happy-dom
import React, { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../store/useStore.js', () => ({ useStore: selector => selector({ S: { gifSize: 'full' }, update: vi.fn() }) }))
globalThis.IS_REACT_ACT_ENVIRONMENT = true
let root, host
beforeEach(() => {
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})
afterEach(() => {
  act(() => root.unmount())
  host.remove()
  vi.unstubAllEnvs()
  vi.resetModules()
})
const ex = { id: 'test', n: 'Exercise', img: 'test.jpg', gif: 'test.gif' }

describe('asset-free builds', () => {
  it('renders neutral thumbnails and no empty media element or third-party URL', async () => {
    vi.stubEnv('VITE_EXERCISE_MEDIA', 'false')
    const { default: Media, Thumb } = await import('./Media.jsx')
    act(() => root.render(<><Media ex={ex} /><Thumb ex={ex} /></>))
    expect(host.querySelector('img, video, iframe')).toBeNull()
    expect(host.querySelector('.exmedia')).toBeNull()
    expect(host.querySelector('.thumb-x')).toBeTruthy()
  })

  it('retains configurable image and animation bases when assets are enabled', async () => {
    vi.stubEnv('VITE_EXERCISE_MEDIA', 'true')
    vi.stubEnv('VITE_IMG_BASE', 'https://assets.example.com/images/')
    vi.stubEnv('VITE_GIF_BASE', 'https://assets.example.com/animations/')
    const { imgSrc, gifSrc } = await import('../lib/exercises.js')
    expect(imgSrc(ex)).toBe('https://assets.example.com/images/test.jpg')
    expect(gifSrc(ex)).toBe('https://assets.example.com/animations/test.gif')
    expect(imgSrc({})).toBeNull()
    expect(gifSrc({})).toBeNull()
  })

  it('does not prefetch any catalogue media for an installed asset-free app', async () => {
    vi.stubEnv('VITE_EXERCISE_MEDIA', 'false')
    const { planMediaUrls } = await import('../lib/media-prefetch.js')
    expect(planMediaUrls({ routines: [{ ex: [{ id: ex.id }] }] }, 'https://gym.example.com/', { [ex.id]: ex })).toEqual([])
  })

  it('falls back from an unavailable animation to its still and then a neutral tile', async () => {
    const { default: Media } = await import('./Media.jsx')
    act(() => root.render(<Media ex={ex} />))
    expect(host.querySelector('img').getAttribute('src')).toBe('gif/test.gif')
    act(() => host.querySelector('img').dispatchEvent(new Event('error')))
    expect(host.querySelector('img').getAttribute('src')).toBe('img/test.jpg')
    act(() => host.querySelector('img').dispatchEvent(new Event('error')))
    expect(host.querySelector('img')).toBeNull()
    expect(host.querySelector('.exmedia-x')).toBeTruthy()
  })
})
