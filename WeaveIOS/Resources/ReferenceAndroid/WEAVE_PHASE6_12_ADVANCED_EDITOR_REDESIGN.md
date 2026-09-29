# Weave Phase 6.12 — Advanced Editor Redesign

This pass simplifies Advanced profile editing around two workspaces: **Background** and **Foreground**. It does not change the VSPF/profile wire format.

## Header and inspector cleanup

- Removed the profile/user name above the current page label in the Advanced editor header.
- Removed the current workspace/mode badge beside **Done**.
- Removed the Inspector title and selected `Page: ...` subtitle from the side panel header; that strip now contains only the collapse control.
- Moved **Pages & layers** below Delete / Copy / Undo.
- Delete, Copy, and Undo now use matching oval/pill outlines.

## Undo

Undo was already functional before this redesign. `EditorState` snapshots the profile document before edits, retains up to 60 snapshots, and restores the previous snapshot when Undo is pressed. This pass keeps that behavior and makes the Undo button visually consistent with Delete and Copy.

## Bottom navigation

The old mode/tool strip is replaced by:

`Previous page | Background | Foreground | Next page`

- Previous page is disabled on the first page.
- Next page opens the next existing page when one exists.
- On the last page, Next opens a dialog asking whether to create a new page and what to call it.
- Next is disabled when the document has reached the profile-format page limit.

## Freeform foreground editing

New Advanced-editor foreground elements no longer require a box/container. Text, links, buttons, images, audio, and widgets are placed directly under the page root and can then be moved/resized/styled with the normal property controls.

The side panel exposes the foreground add controls. Image and audio additions now use Android's media picker and the same sanitized `LocalMediaStore` import path used by the Basic editor, rather than creating empty media placeholders.

Background mode continues to edit page appearance and background stamps.

## Existing boxed profiles

`ElementType.Block` remains supported by the document model, codec, renderer, hierarchy, hit testing, and property editor. Existing profiles containing boxes are not flattened or rewritten merely by opening them.

The separate **Boxes** workflow is no longer exposed for new editing. New profiles and newly inserted foreground content use the flat/freeform page layout.

## Starter profile

The default Advanced profile now contains root-level foreground text/widget elements rather than Header/Welcome box containers. Root-level stamps remain background decorations.

## Version

- `versionCode 38`
- `versionName 0.11.0-advanced-editor-redesign`
