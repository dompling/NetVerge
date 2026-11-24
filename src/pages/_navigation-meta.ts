export const navigationItems = {
  home: { label: 'layout.components.navigation.tabs.home', path: '/' },
  proxies: {
    label: 'layout.components.navigation.tabs.proxies',
    path: '/proxies',
  },
  profiles: {
    label: 'layout.components.navigation.tabs.profiles',
    path: '/profile',
  },
  connections: {
    label: 'layout.components.navigation.tabs.connections',
    path: '/connections',
  },
  rules: { label: 'layout.components.navigation.tabs.rules', path: '/rules' },
  mitm: { label: 'settings.mitm.title', path: '/mitm' },
  logs: { label: 'layout.components.navigation.tabs.logs', path: '/logs' },
  unlock: {
    label: 'layout.components.navigation.tabs.unlock',
    path: '/unlock',
  },
  settings: {
    label: 'layout.components.navigation.tabs.settings',
    path: '/settings',
  },
} as const

// Keep the experimental desktop feature out of Linux navigation until supported.
export function isNavigationItemAvailable(path: string, platform: string) {
  return path !== navigationItems.mitm.path || platform === 'windows' || platform === 'macos'
}
