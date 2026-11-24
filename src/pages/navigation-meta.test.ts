import { describe, expect, it } from 'vitest'

import { isNavigationItemAvailable, navigationItems } from './_navigation-meta'

describe('MITM navigation', () => {
  it('has a dedicated unique route', () => {
    expect(navigationItems.mitm.path).toBe('/mitm')
    const paths = Object.values(navigationItems).map(({ path }) => path)
    expect(new Set(paths).size).toBe(paths.length)
  })

  it('only exposes MITM on current desktop targets', () => {
    expect(isNavigationItemAvailable('/mitm', 'windows')).toBe(true)
    expect(isNavigationItemAvailable('/mitm', 'macos')).toBe(true)
    expect(isNavigationItemAvailable('/mitm', 'linux')).toBe(false)
    expect(isNavigationItemAvailable('/settings', 'linux')).toBe(true)
  })
})
