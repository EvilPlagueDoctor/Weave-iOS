# Weave Phase 6.12.4 — Editor Lift Reorder

Advanced Editor interaction polish.

## Pages & Layers reorder
- Long-pressing a page or layer now visually lifts the selected row above the list.
- The lifted row follows the pointer with a small scale increase and elevation/shadow.
- Neighboring rows animate out of the way while dragging, creating a visible insertion gap.
- The actual document order is committed only on release.
- Page moves preserve the currently open page by page ID and recalculate its index immediately, so Previous/Next navigation follows the new page order.
- Layer moves continue to change the real z-order.
- A completed drag is one undoable reorder operation; cancelling a drag makes no document change.

## Undo button
- Restored an explicit capsule/oval border around Undo.
- The border remains visible at reduced intensity when Undo is disabled.

## Version
- versionCode 42
- versionName 0.11.4-editor-lift-reorder
