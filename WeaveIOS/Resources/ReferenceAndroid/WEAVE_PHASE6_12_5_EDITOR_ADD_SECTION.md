# Weave Phase 6.12.5 — Editor Add Section

Advanced Editor UI polish based on Phase 6.12.4.

- Moved **Add** below the divider into the scrollable property-panel area.
- Property order is now: Add → Move / Size → Appearance → Content (when applicable) → File.
- Add now uses the same reusable rounded `Section` component as Move / Size and Appearance, so its header tint, border, expansion arrow, spacing, and animation match those controls.
- Add starts collapsed for a cleaner inspector.
- Foreground Add remains a vertical list for Text, Image, Audio, Widget, Link, and Button.
- Background Add continues to expose Stamp.
- Existing media import/loading behavior is unchanged.

Version: `versionCode 43`, `versionName 0.11.5-editor-add-section`.
