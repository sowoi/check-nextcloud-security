import nox

nox.options.default_venv_backend = "uv"

@nox.session(python=["3.11", "3.12", "3.13", "3.14", "3.15"])
def versions_check(session):
    # "test" is a dependency group, not an extra, so install it explicitly
    # into the session venv; otherwise pytest resolves from the outer env.
    session.install(".", "pytest>=9.1.1", "pytest-mock>=3.17.0")
    session.run("python", "--version")
    session.run("python", "-m", "pytest")
