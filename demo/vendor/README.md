# Vendored runtime dependency

`three.module.min.js` is Three.js r169 (`three@0.169.0`), vendored from the npm package so both the operational WebGL observatory and legacy cinematic renderer execute no remote JavaScript. Its reviewed SHA-256 is pinned by `server.test.mjs` as `f7cee3c7533449a1505cc12cb5128b89e3d4fd3d7ea62b05f9f5464a217472ee`; any refresh must update that contract deliberately.

License: MIT. See `THREE-LICENSE.txt`.

To refresh it deliberately:

```bash
npm pack three@0.169.0
# extract build/three.module.min.js and LICENSE, review the diff, then rerun demo tests
```
