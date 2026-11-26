// Transforms the Chrome manifest into the Firefox one. Kept separate so it can
// be unit tested without running the full build.

export function toFirefox(base) {
  const m = structuredClone(base);
  delete m.minimum_chrome_version;
  // Firefox has no declarativeNetRequest session rules and no side panel.
  m.permissions = m.permissions
    .filter((p) => p !== 'declarativeNetRequestWithHostAccess' && p !== 'sidePanel')
    .concat('webRequestBlocking');
  delete m.side_panel;
  m.sidebar_action = {
    default_panel: 'panel.html',
    default_title: 'Session Afterlife',
    default_icon: base.action.default_icon,
  };
  // Firefox MV3 uses an event page, not a service worker.
  m.background = { scripts: ['background.js'], type: 'module' };
  m.browser_specific_settings = {
    gecko: {
      id: 'session-afterlife@enesbaldemir.github',
      strict_min_version: '140.0',
      // The extension collects nothing and sends nothing off-device.
      data_collection_permissions: { required: ['none'] },
    },
  };
  return m;
}
