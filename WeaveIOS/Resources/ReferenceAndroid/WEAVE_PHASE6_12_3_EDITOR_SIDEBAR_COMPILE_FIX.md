# Weave Phase 6.12.3 — Editor Sidebar Compile Fix

Fixes the Kotlin/JVM signature collision introduced in 6.12.2.

- Renamed the persisted sidebar helper from `setPanelCollapsed(Boolean)` to `updatePanelCollapsed(Boolean)`.
- This avoids colliding with Kotlin's generated setter for the `panelCollapsed` property (`setPanelCollapsed(boolean)`).
- Updated both expand and collapse call sites.
- No intended editor behavior changes from 6.12.2.
- Version: `versionCode 41`, `versionName 0.11.3-editor-sidebar-compile-fix`.
