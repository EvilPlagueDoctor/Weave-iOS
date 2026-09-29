# Weave Phase 6.12.2 — Editor Sidebar + Layer Ordering

Advanced Editor polish following the 6.12 redesign.

## Sidebar
- First-ever state defaults to collapsed.
- Subsequent expanded/collapsed state is remembered in local UI preferences.
- Collapsed expansion tab is bright red with a white arrow.
- Expanded collapse strip is pale red and the arrow is centered.

## Pages & Layers
- The visible Depth property section has been removed.
- Long-press and vertically drag a page row to change page order.
- Page reordering preserves the currently open page by page ID and recalculates pageIndex immediately, so previous/next navigation follows the new order.
- Long-press and vertically drag a layer row to change its actual z-order.
- Layers are displayed front-most first; dragging upward moves a layer forward.
- Reordering is recorded as one undo transaction per drag gesture.

## Add section
- "Add to foreground/background" text was replaced with a collapsible `Add` section.
- Foreground actions are now a vertical full-width list: Text, Image, Audio, Widget, Link, Button.
- Background exposes Stamp through the same Add section.

## Version
- versionCode 40
- versionName 0.11.2-editor-sidebar-layers
