# Weave Phase 6.12.6 — Startup Tips

## Loading-screen change

The embedded VeilKnit connection gate keeps the live technical startup status for diagnostics, but replaces the old explanatory paragraph beginning with “VeilKnit is starting inside Weave…” with rotating Weave tips.

- 41 tips total: all previously selected practical/profile/group/widget/network tips plus the three selected joke tips.
- A random tip is shown immediately.
- The tip changes every 4 seconds while embedded VeilKnit is still loading.
- Consecutive repeats are prevented.
- The existing non-embedded VeilKnit connection help text is unchanged.
- Tips are translated for EN / FR / ES / RU / ZH-CN through the existing `tr()` translation system.

## Future TODO

Keep the current selection uniformly random for now. Later, add contextual weighting, e.g. favor the publish reminder when the profile is unpublished, backup reminders when no backup has been made, or Advanced-editor hints for users who have not opened Advanced yet.

## Version

- versionCode: 44
- versionName: `0.11.6-startup-tips`
