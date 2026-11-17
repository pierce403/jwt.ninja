# jwt.ninja
JWT security testing tool

## Cloudflare publishing

Native Cloudflare Git builds publish `main`. Validate with `npm ci` and
`npm run check:deploy`; build uses `npm run build`, deployment `npm run deploy`.
Only the reviewed public file list is copied to `dist`; original public content
and GitHub Pages recovery remain. Credentials stay in Cloudflare and previews
are disabled. The revision is at `/.well-known/cloudflare-build.json`.

## Licensing scope

Original project code and documentation are licensed under the [Apache License, Version 2.0](LICENSE). Third-party dependencies, vendored code, quoted material, data, fonts, media, and other third-party assets retain their respective licenses and rights; this grant does not relicense them. Existing license notices and attribution must be preserved.
