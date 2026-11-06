# UI standards

Read this before any console or client-page work. The goal is that spacing,
widths, radii and colours are fixed once here, so the same structure comes out
the first time and two views do not drift apart.

Two rules, both from how teams keep agents consistent:

1. Never invent a token value. Use the ones below.
2. Copy a real example, do not describe one in prose. The canonical structures
   are `tools/page_template.py` (client page) and the `SEV_MAP` plus the card
   and section markup in `tools/panel.py` (console). When in doubt, match them.

## Severity palette (authoritative)

The source of truth is `SEV_MAP` in `tools/panel.py`. Do not redefine these
anywhere else, import or mirror them.

| Severity | Label | Background | Text |
|---|---|---|---|
| SEV1 | Critical | `#8E0B21` | `#ffffff` |
| SEV2 | High | `#E53935` | `#ffffff` |
| SEV3 | Medium | `#ED7D31` | `#111820` |
| SEV4 | Low | `#F5C518` | `#111820` |
| SEV5 | Informational | `#607085` | `#ffffff` |

## Core colours

| Token | Value | Use |
|---|---|---|
| accent | `#3BBBF8` | links, focus rings, active dots (already `var(--accent)`) |
| alert | `#ff8095` | the pink alert accent used across the console |
| surface-0 | `#06121b` | page background |
| surface-1 | `#1b232e` | raised panel or card |
| surface-2 | `#2a3542` | borders and dividers |
| text-on-dark | `#ffffff` | body text on dark surfaces |

New colours need a reason. If you reach for one that is not here, stop and ask
before adding it, then add it to this table in the same change.

## Spacing, radius and layout

These are the dominant values already in the console. Use them as the scale.

| Token | Value | Use |
|---|---|---|
| radius | `8px` | default corner radius for cards, inputs and buttons |
| radius-pill | `999px` | pills and tags |
| radius-dot | `50%` | status dots and avatars |
| gap-sm | `6px` | tight inline groups |
| gap-md | `8px` | default gap between controls |
| gap-lg | `12px` | gap between cards and sections |
| pad-card | `12px 14px` | default card padding |
| width-full | `100%` | fill the container, do not set fixed pixel widths |

Known drift to converge: the console currently also uses radii of 6, 7, 9, 10
and 12 px in places. When you touch that markup, move it to `8px` (or the pill
or dot radius) rather than adding another value. Do not do a sweeping refactor
just for this, fix it in the markup you are already editing.

## Structure

- A view is built from cards. A card is a titled block with `pad-card` padding
  and `radius` corners, separated from its neighbours by `gap-lg`.
- A client page follows `tools/page_template.py` exactly. Do not hand-roll a
  second page structure.
- Prefer flow and `width-full` over fixed widths, so a view reflows instead of
  breaking at a set size.

## When you adopt a token in code

Define it once as a CSS custom property on `:root` (the console already does
this for `--accent`) and reference it with `var(--token)`. Do not paste the
literal value in many places, that is how drift starts. Editing `tools/panel.py`
needs an explicit go from the operator, so propose the change first.
