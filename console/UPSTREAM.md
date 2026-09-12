# Console Upstream Provenance

This Console adapts the design direction and component-stack choice of [Soybean Admin](https://github.com/soybeanjs/soybean-admin), pinned for review at commit `3d3613f20cd4add3cd20fd6cc884abead165c6d2` (2026-08-12).

- Upstream license: MIT, Copyright (c) 2021 Soybean.
- Reused approach: Vue 3 + Naive UI, compact Chinese admin layout, collapsible graphite sider, dense operational data surfaces.
- Not copied: upstream source files, monorepo infrastructure, generated routing, state management, authentication, or business modules.
- This project owns the local ControlPlane contract, authentication, redaction rules, state reducers and UI implementation under `pentest-agent/console/`.
