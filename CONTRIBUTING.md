<!-- TOC -->
* [CONTRIBUTING](#contributing)
  * [Guidelines](#guidelines)
  * [🛠️ Local Setup](#-local-setup)
    * [1. Install `uv`](#1-install-uv)
  * [Install Dependencies](#install-dependencies)
  * [Running Tests](#running-tests)
  * [Linting](#linting)
<!-- TOC -->

# CONTRIBUTING
We welcome and appreciate all contributions to this project! Before submitting a Pull Request (PR), please take a moment to review this guide.

---

## Guidelines

* Ensure your code adheres to the existing coding style.
* Write clear and concise commit messages.
* **Always** run the tests and linting before submitting a PR.
* Keep PRs focused on a single feature or fix.

---

## 🛠️ Local Setup

We recommend using **`uv`** for managing dependencies and running development tasks.

### 1. Install `uv`

If you haven't already, install the `uv` package manager (or your preferred installation method):

```
pipx install uv
```

## Install Dependencies

Install the project's runtime dependencies along with the necessary development dependencies specified in the test group:

```
uv sync
```

## Running Tests
Tests are managed using pytest, and the required packages are defined in the test dependency group.

To run the complete test suite:
```
uv run --group test pytest
```

## Linting
We use Ruff for linting and code formatting checks.

To run the linting check:
```
uvx ruff check
```
