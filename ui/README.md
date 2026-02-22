# Antidote UI

Vite + React + TypeScript SPA for the Antidote AI Activity Monitor.

## Dev mode (with proxy)

```bash
cd ui
npm install
npm run dev
```

Then open **http://localhost:5173/ui/** — Vite proxies `/ui/state`, `/ui/sessions`, and `/debug` to the daemon at `127.0.0.1:17845`.

**Prerequisite:** Daemon must be running (`cargo run -p antidote-daemon`).

## Build and serve from daemon

```bash
cd ui
npm ci
npm run build
```

Then run the daemon from the repo root (so `ui/dist` is found):

```bash
cargo run -p antidote-daemon
```

Open **http://127.0.0.1:17845/ui/**
