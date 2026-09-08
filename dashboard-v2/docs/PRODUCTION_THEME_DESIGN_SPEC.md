# PTI-Honeypot Production Theme Design Specification

Status: design contract for implementation  
Branch: `design/production-theme-system`  
Scope: `dashboard-v2` visual system only

This document defines the approved visual direction before existing pages and components are restyled. It does not authorize changes to API behavior, authentication, data semantics, routes, or operational logic.

## Design Scope

The visual implementation may edit existing pages and components. It may move, reorder, regroup, resize, or restyle existing information when that improves hierarchy, spacing, responsive behavior, and reading flow.

Permitted presentation changes include:

- changing grid structure, column proportions, card order, alignment, and responsive breakpoints;
- grouping existing values by task or meaning and separating overview from detail;
- changing visual hierarchy, typography, whitespace, borders, radius, icon placement, and control placement;
- adapting tables, charts, maps, forms, and navigation to the shared theme;
- adding the presentation copy and accessible markup required for loading, refreshing, empty, error, disabled, hover, focus, selected, and stale states.

The implementation must not add, remove, fabricate, reinterpret, or recalculate domain information. Existing fields, metrics, units, labels, status meanings, filters, actions, links, and data sources remain authoritative. Do not add a new KPI merely because space is available. Do not use mock values to make a layout look complete.

## Direction: Semi-formal Cyber-Honeycomb

The product should look like a dependable security operations application, but with a stylized "Honeypot" aesthetic. The interface balances scanability and stable hierarchy with dynamic, tech-forward visuals (hexagons, soft glows) primarily designed for dark environments.

Core principles:

1. Amber/Yellow is the primary brand and interaction color.
2. Hexagon (Honeycomb) shapes are used for layout components and backgrounds.
3. Tasteful gradients, soft glows (neon), and glassmorphism (translucency) are encouraged to enhance the tech aesthetic.
4. Elegant animations (e.g., Framer Motion) are used for staggered entrances and interactive hover states.
5. Typography and spacing create hierarchy before decoration.
6. Dark mode is the primary focus, though light mode should remain functional.
7. Machine data remains visually distinct without making the whole product monospace.

## Existing UI Audit

The current implementation has several constraints the migration must address deliberately:

- `globals.css` only defines background and foreground values, while most components contain hard-coded dark Tailwind utilities and hex values. The media query therefore cannot produce a complete light theme.
- The authenticated layout applies `font-mono` to the entire application, while the root body falls back to Arial. This weakens reading rhythm and makes hierarchy feel less formal.
- Purple is used for brand, navigation, focus, charts, and decoration. Red, amber, orange, cyan, blue, and emerald are also used inconsistently between meaning and decoration.
- Landing, login, cards, gauges, and charts use gradients, glows, translucent surfaces, and blur effects that compete with operational data.
- Recharts and map components contain fixed dark-mode hex colors, so CSS-only surface changes would leave charts unreadable in light mode.
- Dense screens frequently use 9–10 px labels. Several controls remove the native outline without providing a consistent `focus-visible` replacement.
- Reusable cards and badges exist, but many pages recreate their own surface, input, table, and modal styles.

These are migration observations. Component markup and layout may change for presentation, but component data and behavior must remain stable.

## Theme Model

Support three stored preferences: `system`, `light`, and `dark`. Resolve the preference to exactly `light` or `dark` on the root `<html data-theme>` attribute.

- Storage key: `pti-theme`
- Default preference: `system`
- Root attribute: `data-theme="light"` or `data-theme="dark"`
- Root CSS property: `color-scheme: light` or `color-scheme: dark`
- Toggle location: authenticated top bar and public navigation
- Toggle control: labeled menu or segmented choice; an icon alone is insufficient

The implementation must set the resolved theme before first paint to prevent a light flash on a dark preference. It must then listen for OS preference changes only while the stored preference is `system`.

## Color System

All components must consume semantic tokens. Palette names such as `purple-500` and raw hex values must not be the long-term component API.

### Foundation tokens

| Role | Light | Dark | Intended use |
| --- | --- | --- | --- |
| `canvas` | `#F4F7FB` | `#0B1220` | Application background |
| `surface` | `#FFFFFF` | `#111827` | Cards, sidebar, panels |
| `surface-subtle` | `#F8FAFC` | `#182235` | Table headers, inset areas |
| `surface-raised` | `#FFFFFF` | `#1B2638` | Menus, tooltips, modals |
| `surface-hover` | `#EEF3F8` | `#202C40` | Hovered neutral rows |
| `text` | `#0F172A` | `#F8FAFC` | Primary text |
| `text-muted` | `#475569` | `#CBD5E1` | Secondary text |
| `text-subtle` | `#64748B` | `#94A3B8` | Metadata and placeholders |
| `border` | `#CBD5E1` | `#334155` | Default boundaries |
| `border-strong` | `#94A3B8` | `#475569` | Active or emphasized boundaries |
| `primary` | `#1D4ED8` | `#60A5FA` | Links, active indicators, chart focus |
| `primary-action` | `#1D4ED8` | `#2563EB` | Primary button background |
| `primary-action-hover` | `#1E40AF` | `#1D4ED8` | Primary button hover |
| `on-primary` | `#FFFFFF` | `#FFFFFF` | Text/icons on primary actions |
| `focus-ring` | `#2563EB` | `#93C5FD` | Keyboard focus ring |

### Semantic state tokens

| State | Light foreground | Dark foreground | Meaning |
| --- | --- | --- | --- |
| Success / online | `#15803D` | `#4ADE80` | Healthy, completed, online |
| Warning / degraded | `#B45309` | `#FBBF24` | Attention, medium risk, degraded |
| Danger / critical | `#B91C1C` | `#F87171` | Failed, offline, critical risk |
| Info / running | `#0369A1` | `#38BDF8` | Running, informational activity |
| Neutral / unknown | `#475569` | `#94A3B8` | Unknown, unavailable, inactive |

Each state also needs a low-emphasis background and border derived from the same hue. Do not rely on color alone: retain a text label, icon, pattern, or shape.

### Usage rules

- Brand Amber/Yellow may identify navigation, links, focus, selected filters, and glowing hover states.
- Red, green, and cyan are reserved for semantic states (Danger, Success, Info).
- A page should normally have one solid primary action.
- Tasteful gradients and translucency (glassmorphism) are permitted to match the tech aesthetic.
- Soft neon glows (colored box shadows) are permitted for hover states or critical emphasis, provided they do not overwhelm the UI.

## Typography

Primary UI stack:

```text
Inter Variable, Noto Sans Thai Variable, ui-sans-serif, system-ui, sans-serif
```

Machine-data stack:

```text
JetBrains Mono Variable, ui-monospace, SFMono-Regular, Consolas, monospace
```

Font files should be self-hosted WOFF2 assets with their licenses recorded. Do not depend on a runtime font CDN. Until approved font assets are available, use the system fallbacks without blocking the rest of the theme migration.

Use the sans stack for navigation, headings, descriptions, controls, tables, and normal values. Use monospace only for IP addresses, ports, hashes, event IDs, TTP IDs, commands, timestamps when column alignment matters, and raw telemetry.

| Style | Size / line height | Weight | Use |
| --- | --- | --- | --- |
| Display | `32 / 40 px` | 700 | Public landing title only |
| Page title | `24 / 32 px` | 600 | One per screen |
| Section title | `16 / 24 px` | 600 | Card and region titles |
| Body | `14 / 20 px` | 400 | Default application text |
| Body strong | `14 / 20 px` | 600 | Important values and labels |
| Compact | `12 / 16 px` | 400–500 | Metadata and dense table support |
| Data value | `20–28 / 28–36 px` | 600 | KPI values |

Avoid text smaller than 12 px for meaningful information. Uppercase and wide letter spacing are limited to short status or category labels. Do not use weight 900 as the default brand voice.

## Shape, Spacing, and Elevation

- Base spacing unit: 4 px.
- Common gaps: 12, 16, 24, and 32 px. Use 8 px only inside compact controls or tightly related inline content.
- Control height: 36 px compact, 40 px default.
- Table row height: at least 44 px.
- Card padding: 20 px compact, 24 px default.
- Control radius: 8 px.
- Card radius: 12 px.
- Modal and large-panel radius: 16 px.
- Pills are reserved for statuses, filters, and compact toggles.
- Default light card shadow: `0 1px 3px rgb(15 23 42 / 0.08)`.
- Raised light surfaces may add `0 8px 24px rgb(15 23 42 / 0.05)`.
- Dark mode relies on a clear border plus `0 1px 2px rgb(0 0 0 / 0.20)` rather than large shadows.
- Hover shadows remain neutral and soft. Hover must not lift or resize dense dashboard content.

Animations should normally complete in 120–180 ms and be limited to color, opacity, or small transforms. Honor `prefers-reduced-motion`. Continuous pulsing is reserved for a truly live or urgent state and must not be used to make static content feel active.

## Component Contracts

### Application shell

- Sidebar width: 240 px desktop; collapsible drawer below the desktop breakpoint.
- Top bar height: 64 px.
- Page canvas uses `canvas`; navigation and cards use `surface`.
- Active navigation uses a primary-colored 3 px leading indicator plus a subtle primary background. Inactive links remain neutral.
- Search, time, profile, theme, and logout controls must have clear names and keyboard focus states.
- Page content keeps a maximum width of 1600 px with 24–32 px desktop gutters and 16 px mobile gutters.
- Existing page sections may be repositioned to follow the reading order: context and summary first, investigation content second, supporting detail last.
- Preserve the user's location while data refreshes; layout must not jump as states change.

### Cards and KPIs

- One border, one background, a 12 px radius, and at most one soft neutral shadow.
- Remove decorative gradient blobs and glow-on-hover behavior.
- KPI title comes before the value in reading order. Trend color represents metric meaning; an increase is not automatically good or bad.
- Icon tiles use primary or neutral styling unless the icon communicates a real state.
- Cards may be reordered and regrouped, but their displayed metrics, units, values, and calculations must not change.

### Tables

- Use a subtle surface header, stable column alignment, and tabular numerals.
- Use horizontal dividers rather than a separate elevated card for every row.
- Hover must remain visible in both themes without changing semantic text color.
- Critical information appears in text; truncation requires an accessible way to inspect the full value.
- Loading, empty, error, and stale states require distinct copy and must not be represented only by color.
- Repositioning columns is allowed for readability, but no existing field may silently disappear. Move lower-priority fields into an existing detail view only when the same information remains directly reachable.

### Forms and actions

- Inputs use `surface`, `border`, `text`, and `text-subtle` tokens.
- Every interactive control receives a visible 2 px `focus-visible` ring with a 2 px offset.
- Do not leave `outline-none` unless the replacement focus style is present in the same rule.
- Destructive actions use danger styling and confirmation. Primary blue is not used for destructive confirmation.
- Disabled controls retain readable text and expose the disabled state programmatically.

### Badges and severity

- Use consistent labels: `Critical`, `High`, `Medium`, `Low`; and `Online`, `Degraded`, `Offline`.
- Status badges combine foreground, subtle background, border, and text.
- Reserve red for critical/failure, amber for warning/degraded, green for healthy/success, and blue for informational/running.

### Charts

- Consume CSS variables for axes, grid, tooltip, and series colors; do not branch component logic on theme when CSS can resolve the value.
- Default grid and axis colors use neutral tokens. Tooltip uses `surface-raised`, `border`, and `text`.
- Main series is blue. Additional categorical series use teal, amber, violet, rose, and sky in that order.
- Use solid lines and low-opacity flat area fills. Do not use SVG `linearGradient` fills.
- Never encode multiple series by color alone; use labels, dash patterns, or markers where necessary.
- Keep chart labels at least 12 px when space permits and provide a non-chart summary for important conclusions.

Recommended categorical palette:

| Series | Light | Dark |
| --- | --- | --- |
| 1 | `#2563EB` | `#60A5FA` |
| 2 | `#0F766E` | `#2DD4BF` |
| 3 | `#B45309` | `#FBBF24` |
| 4 | `#7C3AED` | `#A78BFA` |
| 5 | `#BE123C` | `#FB7185` |
| 6 | `#0369A1` | `#38BDF8` |

### Map

- Land, borders, hover, tooltip, and controls use theme tokens rather than fixed dark hex values.
- Attack markers use severity tokens and retain a legend.
- Animation is disabled under reduced-motion preferences.

## Required Interface States

Every data-bearing region must define its own state instead of forcing the whole page into one generic state. State containers keep the same approximate dimensions as the loaded content to prevent layout shift.

### Loading and refreshing

- Initial loading uses a quiet skeleton shaped like the final content, with `aria-busy="true"` on the affected region.
- Skeletons use neutral surface tokens and no shimmer gradient. A restrained opacity pulse is allowed and must stop under reduced-motion preferences.
- Never display invented values, random chart points, or realistic-looking placeholder incidents.
- During background refresh, keep the last valid result visible when safe and show a compact refreshing indicator. Do not replace an entire usable dashboard with a spinner.

### Error

- Show an inline error surface next to the failed region so unrelated panels remain usable.
- Use a concise title, a plain-language description, and a retry action only when retry behavior already exists or can call the same read operation without changing domain behavior.
- Do not expose stack traces, database details, tokens, raw upstream responses, or implementation jargon.
- Danger styling identifies the failure, while normal text provides the full meaning.

### Empty and unavailable

- Empty means the request succeeded but returned no applicable records. It is visually and verbally distinct from error and loading.
- Use a simple neutral icon, short title, and one supporting sentence. Do not add decorative illustrations or fabricated examples.
- Do not present missing data as a real zero. Preserve the existing unavailable/unknown semantics.
- Add an action only when an equivalent existing action is already valid for that state.

### Hover, focus, selected, and pressed

- Hover uses a subtle surface change and optionally a stronger border. It must not move, scale, glow, or reflow the item.
- Keyboard focus uses the shared focus ring and remains at least as visible as hover.
- Selected state combines primary tint, border or leading indicator, and an accessible state such as `aria-current`, `aria-selected`, or checked semantics.
- Pressed state uses a small color/opacity change rather than a large transform.
- State transitions last 120–180 ms and must remain understandable with animation disabled.

### Disabled and stale

- Disabled controls retain legible labels, use reduced emphasis rather than very low opacity, and expose the native disabled state.
- Stale data remains readable and carries an explicit freshness label already supported by the data contract. Do not recolor stale data as critical unless its existing semantics say so.

## Accessibility Acceptance Criteria

- Normal text meets WCAG 2.2 AA contrast of at least 4.5:1; large text and essential non-text UI meet at least 3:1.
- Every interactive element is reachable and visibly focused by keyboard.
- Theme controls have an accessible name and expose the active preference.
- Both themes retain usable native form controls through the `color-scheme` property.
- Meaning is not conveyed by color alone.
- At 200% zoom, core navigation, authentication, dashboard metrics, tables, and dialogs remain operable.
- Reduced-motion users do not receive continuous pulse, ping, glow, or decorative motion.

## Proposed Implementation Shape

The implementation agent may add foundations before migrating existing views:

```text
src/components/theme/ThemeProvider.tsx
src/components/theme/ThemeToggle.tsx
src/lib/theme.ts
src/app/fonts/
```

`globals.css` should expose semantic Tailwind v4 color and font utilities through CSS variables. Exact file names may change if the installed Next.js documentation requires a different convention.

Suggested migration order:

1. Capture current route screenshots and interaction notes without editing behavior.
2. Add theme resolution, semantic tokens, font foundations, and focus/motion rules.
3. Add theme toggle controls to public and authenticated shells.
4. Migrate shared cards, badges, fields, buttons, and table patterns.
5. Recompose authenticated shell and high-traffic dashboard screens around existing information, using clearer hierarchy and more whitespace.
6. Migrate charts and map using theme-aware CSS variables.
7. Migrate public, login, profile, archive, malware, and management screens.
8. Remove obsolete raw palette classes only after route-by-route parity checks.

Do not perform a blind global replacement of color classes. For example, current purple may mean brand, selection, a chart category, or an analytical state; each occurrence needs semantic classification.

## Verification Matrix

Review at minimum these routes in light and dark themes:

- `/`
- `/login`
- `/dashboard`
- `/threat-intel`
- `/threat-intel/[id]`
- `/archives`
- `/malware-vault`
- `/system-health`
- `/profile`
- `/user-management`
- `/change-password`

For each route, verify desktop and narrow viewport layouts, keyboard focus order, empty/loading/error states, and theme persistence across reloads. Also run:

```bash
npm run lint
npm run build
python -m pytest -q \
  honeypot-analysis/tests/test_dashboard_v2_api_integration_contract.py \
  honeypot-analysis/tests/test_dashboard_v2_staging_contract.py
```

## Definition of Done

- Light and dark modes are complete, persistent, and free of first-paint flashing.
- The UI has one recognizable blue primary color and consistent semantic statuses.
- Normal UI surfaces contain no gradients, glow effects, or decorative blur.
- Existing information may have a better position and grouping, but no domain data, metric, calculation, or action has been added, removed, or changed.
- Sans-serif is the default; monospace is limited to machine data.
- No meaningful text is smaller than 12 px.
- Loading, refreshing, error, empty, hover, focus, selected, disabled, and stale states follow the required state contracts without layout shift.
- Charts, maps, forms, tables, modals, public pages, and authenticated pages remain readable in both themes.
- API calls, routes, authentication behavior, data semantics, and component functionality remain unchanged unless separately authorized.
- Lint, production build, contract tests, and the visual verification matrix pass.
