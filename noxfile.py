import nox

nox.options.default_venv_backend = "uv"

@nox.session(python=["3.10", "3.11", "3.12", "3.13", "3.14"])
def versions_check(session):
    session.run("uv", "pip", "install", ".[test]")
    session.run("pytest")