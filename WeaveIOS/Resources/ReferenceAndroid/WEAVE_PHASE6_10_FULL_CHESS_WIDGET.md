# Weave Phase 6.10 — Full Chess Widget

Date: 2026-09-17

Phase 6.10 turns the bundled Chess example from a networking/language scaffold into a full interactive turn-based Chess widget implemented in Weave widget source.

## Important architecture rule

Chess rules are **not** hard-coded into Android/Kotlin. The bundled Chess widget is ordinary source-only widget code and goes through the same local parser, compiler, verifier and sandbox runtime as third-party widgets.

Kotlin remains responsible for the security boundary:

- click-to-load package activation,
- local compilation and bytecode verification,
- strict public-widget network parsing,
- exact-hash acknowledgements,
- grouped-action/session metadata,
- fair shared-random negotiation,
- runtime budgets,
- bounded dynamic UI mutation,
- and the host-owned close/X control.

The Chess widget source is responsible for Chess rules and presentation.

## Chess UI

The built-in Chess template now contains:

- a real 8×8 / 64-square interactive board,
- piece rendering inside the widget,
- selection and previous-move highlighting,
- status/player labels,
- start/invite/accept controls,
- promotion controls for Queen, Rook, Bishop and Knight,
- and an `I give up` / resignation action.

The board is represented by a bounded 64-element numeric array. Positive piece codes are White, negative piece codes are Black, and zero is empty.

## Rules implemented in widget source

The current source implements and validates:

- pawn movement and captures,
- double pawn moves,
- en passant,
- knight movement,
- bishop movement and blocked paths,
- rook movement and blocked paths,
- queen movement and blocked paths,
- king movement,
- own-piece collision rejection,
- king-safety validation,
- castling rights,
- castling path clearance,
- prohibition on castling while/in/through check,
- promotion to Queen/Rook/Bishop/Knight,
- check detection,
- checkmate,
- stalemate,
- resignation,
- 50-move draw handling,
- bounded repetition history / threefold repetition handling,
- and basic insufficient-material handling.

Both sides independently validate a proposed move using their own locally compiled copy of the widget source before accepting the exact grouped action.

## Network move representation

Chess uses the deliberately tiny declared widget input surface:

- `kind = number(1, 3)`
- `value = number(0, 63)`
- `resign = button`

A normal move is one grouped action containing two steps:

1. `kind=1, value=<FROM square>`
2. `kind=2, value=<TO square>`

A promotion adds a third step:

3. `kind=3, value=<piece choice>`

The receiving widget gets the already structurally validated grouped action, checks that the expected player is moving, independently checks Chess legality, and then calls `network.accept` or `network.reject`.

A committed action is validated again before local board state is changed.

## Fair White/Black selection

After the paired widget session is ready, Weave's commit/reveal shared-random host capability establishes a common random seed. Neither participant's RNG alone determines the result.

The first two-sided roll assigns White/Black. Participant/session ordering used internally by the host is not exposed as raw DHT identity to widget source.

## Language/runtime additions used by Chess

Phase 6.10 exercises the Phase 6.9 foundations heavily and adds/refines support needed by the full board:

- VWB5 local bytecode/runtime revision,
- bounded numeric arrays,
- non-recursive helper functions,
- expression indexing/arithmetic/boolean logic,
- dynamic host-validated UI text assignment,
- bounded dynamic square-background assignment,
- player-slot and event-player metadata,
- grouped multi-step network actions,
- action/action-committed receive handlers,
- shared-random/dice events,
- cached parsed expressions for the substantially larger Chess workload,
- and larger but still hard-bounded widget source/node/event/action/instruction budgets.

Published widget packages remain **source-only**. VWB5 is a local compiled representation and is not trusted or distributed as executable content.

## Runtime/security limits

The larger Chess template does not remove sandbox limits. It remains constrained by the receiver's local compiler/verifier/runtime, including:

- maximum source size,
- maximum node/event/state/function/array counts,
- maximum helper call depth,
- maximum expression size/tokens,
- maximum actions per handler,
- maximum instructions per event,
- strict network input types/ranges,
- at most two declared input values in one network event,
- at most five steps in one grouped action,
- inert bounded network text,
- no raw sockets/HTTP/arbitrary DHT/filesystem/native/Android API access,
- and host-controlled clipping/close behavior.

Dynamic UI assignment never hands widget code an Android View, Compose object or TextView. The VM identifies a declared widget node/property; Kotlin validates the target/value and applies the mutation through the host renderer.

## Validation performed in this build environment

The pure Kotlin widget compiler/verifier/template core was compiled again from the Phase 6.10 sources rather than relying only on older jars.

All seven bundled templates compile and independently verify. The Chess template is approximately 122 KiB / 3,400 lines and remains within the source limit.

A headless harness executes the actual compiled Chess helper/action logic and currently passes checks covering:

- normal legal and illegal moves,
- blocked paths,
- kingside castling,
- en passant,
- promotion validation/application,
- rejection of a pinned-piece move that exposes its king,
- Fool's Mate / checkmate,
- and a known stalemate position.

The heaviest tested checkmate path remained below the widget event instruction ceiling.

A full Android Gradle build is not available in this container because Android SDK 36 / the requested Gradle distribution are not installed here. The Windows JDK 17+ / Android SDK 36 build remains the authoritative complete Android compile test.

## Current practical limitation

This is the first full Chess implementation and should still be treated as a test/reference widget until it has been exercised across two real devices over the public widget-networking path. The headless rule tests cover important rule classes but are not an exhaustive formal proof over every legal Chess position.
