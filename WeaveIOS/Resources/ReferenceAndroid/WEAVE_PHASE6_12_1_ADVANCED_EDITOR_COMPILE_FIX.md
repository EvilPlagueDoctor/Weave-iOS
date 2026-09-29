# Weave Phase 6.12.1 — Advanced Editor Compile Fix

Fixes two compile errors introduced by the Phase 6.12 Advanced Editor redesign:

- Reworded `create_next_page_body` to avoid the unescaped apostrophe that AAPT2 rejected while flattening Android string resources.
- Added the explicit `EditorTool.Move -> return` branch to the enum `when` expression in `EditorState.add()` so the expression is exhaustive.

No Advanced Editor behavior was otherwise changed from Phase 6.12.

Version: `0.11.1-advanced-editor-compile-fix` (`versionCode 39`).
