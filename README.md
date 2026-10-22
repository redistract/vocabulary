# Redistract vocabulary

Public, read-only vocabulary packs for the Redistract Android app, served from
https://redistract.github.io/vocabulary/.

This repository is generated. Do not edit `site/` by hand: content is built and
reviewed in the app project, then staged here with `tools/stage_vocabulary_publish.py`.

- `site/` is what GitHub Pages serves. Pack files under `site/v1/packs/<id>/<revision>.json`
  are immutable once published; changes need a new revision.
- `.github/workflows/deploy.yml` verifies `site/`, deploys it, then verifies the live site.
- `.github/workflows/monitor.yml` re-verifies the live site daily and opens an issue on failure.

Licenses for dictionary-derived content are in `site/licenses/`.
