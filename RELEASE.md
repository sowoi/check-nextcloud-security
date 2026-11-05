## check-nextcloud-security 1.6.1

### Changed

- **Dependencies updated** to the latest releases: `types-requests`
  2.33.0.20261030, plus the locked transitive packages `filelock`,
  `mypy-extensions`, `platformdirs`, `python-discovery` and `virtualenv`.
- **Docker image uses uv 0.13.7.**
- The GitHub Actions were already on their latest releases (`actions/checkout`
  v7, `actions/dependency-review-action` v5, `astral-sh/setup-uv` v10.3.3,
  `peter-evans/create-pull-request` v8, `shundor/python-bandit-scan` at the
  head of its default branch); no change was needed.
