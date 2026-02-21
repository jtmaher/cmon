# cmon

A real-time terminal dashboard for monitoring [Claude Code](https://docs.anthropic.com/en/docs/claude-code) token usage and costs.

```
┌─ TODAY ──────────────────────────────────────────────────────────┐
│ ● Live                                                          │
│ claude-opus-4-6        42 msgs   1.2M in  890K out    $14.23    │
│ claude-haiku-4-5        8 msgs   320K in  180K out     $0.98    │
├─ COST (last 60 min) ────────────────────────────────────────────┤
│ peak $2.40    ▄ █▆▄▂▃▅▇█▆▄▂                                    │
│ -60m          ▆▇██████████▇▅▃▂▁                            now  │
├─ DAILY HISTORY ─────────────────────────────────────────────────┤
│ 2026-02-21   50 msgs   1.5M in  1.1M out    $15.21             │
│ 2026-02-20   83 msgs   2.1M in  1.4M out    $22.47             │
│ 2026-02-19   61 msgs   1.8M in  1.2M out    $18.90             │
├─ ALL TIME ──────────────────────────────────────────────────────┤
│ 24 sessions  412 messages                          Total $187   │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Live token tracking** — watches today's session files via inotify for instant updates
- **Per-model breakdown** — input, output, cache read/write tokens and costs for each model
- **Rolling cost histogram** — 60-minute bar chart showing spend over time
- **Daily history** — scrollable day-by-day usage with keyboard navigation
- **All-time stats** — aggregated totals across sessions
- **Dynamic pricing** — fetches current model prices from LiteLLM, with 24h cache and hardcoded fallback
- **Configurable lookback** — `-d` flag to set how many days of history to show

## Install

Requires `gcc`, `ncurses` headers, and a Linux system with inotify support.

```sh
# install ncurses dev headers (if not bundled)
sudo apt install libncursesw5-dev

# build
make
```

## Usage

```sh
./cmon            # launch with 30-day lookback (default)
./cmon -d 7       # show only the last 7 days
```

### Keybindings

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit |
| `j` / `↓` | Scroll daily history down |
| `k` / `↑` | Scroll daily history up |
| `r` | Force rescan all data |

## How it works

cmon reads from Claude Code's local data files:

- **`~/.claude/stats-cache.json`** — daily activity, per-model token totals, session/message counts
- **`~/.claude/projects/*/*.jsonl`** — raw session logs with per-request token usage

It uses `inotify` to watch for file changes and updates the display instantly. Streaming response chunks sharing the same `requestId` are deduplicated so tokens are counted accurately. Falls back to 2-second polling if inotify is unavailable.

## License

MIT
