# AGENTS.md — Master Instructions for Coding Agent

## 1. Source of Truth
- Read `Blueprint_Backend.html` before writing any code. Every directory path, SQLite column, security rule (`SEC-01` to `SEC-04`), and module contract (`M1` to `M6`) in that file is mandatory.
- `UI_UX_Frontend.html` is the frontend UI. Do NOT overwrite or break its visual layout. In Phase 5, we will connect its simulated actions to the live FastAPI endpoints (`127.0.0.1:8420`).

## 2. Hardware & Thermal Rules (Strict)
- Target OS: WSL2 Ubuntu on Intel Core i9-13900H with 32 GB RAM (no NVIDIA CUDA).
- Always set `torch.set_num_threads(4)` so the laptop stays silent and cool.
- RAM usage must stay <= 1.5 GB and idle CPU usage must be 0.0% (no background polling loops).
- Never use `torch.load()` on `.pt` or `.bin` files; use `safetensors` exclusively with SHA-256 verification (`weights/manifest.sha256`).

## 3. Execution Discipline (One Task at a Time)
- NEVER implement multiple phases at once.
- Only implement the specific Task ID (`T01` through `T15`) requested by the user.
- For every task, write an automated test that proves the "Verification Criterion" listed in Section 06 of `Blueprint_Backend.html` passes before stopping.