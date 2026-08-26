# Vendored runtime dependency

`three.module.min.js` is Three.js r169 (`three@0.169.0`), vendored from the npm package so the local renderer and GitHub Pages build execute no remote JavaScript.

License: MIT. See `THREE-LICENSE.txt`.

To refresh it deliberately:

```bash
npm pack three@0.169.0
# extract build/three.module.min.js and LICENSE, review the diff, then rerun demo tests
```
