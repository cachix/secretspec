"""``Resolved.close()`` must attempt every ``as_path`` file.

The method exists so secret-bearing temp files do not outlive the result.
Stopping at the first file the OS refuses to remove leaves every later secret
on disk — the exact outcome it is meant to prevent — and the caller has no way
to know which ones survived.

The Go SDK (``firstErr``) and the .NET SDK (``firstError``) already clean up
everything and report the first failure afterwards; .NET catches ``IOException``
specifically, which is the ordinary Windows sharing violation raised when
another process still holds the file open. These tests hold the Python SDK to
the same contract.
"""

import os
from unittest import mock

import pytest

from secretspec import Resolved, ResolvedSecret


def _resolved(tmp_path, count=3):
    """A Resolved over `count` real as_path files."""
    paths = []
    for i in range(count):
        path = tmp_path / f"secret{i}"
        path.write_text("super-secret-value")
        paths.append(str(path))
    secrets = {
        f"S{i}": ResolvedSecret(
            value=None, path=path, as_path=True,
            source="provider", source_provider="dotenv",
        )
        for i, path in enumerate(paths)
    }
    return Resolved(provider="dotenv", profile="default", secrets=secrets), paths


def test_close_removes_every_as_path_file(tmp_path):
    resolved, paths = _resolved(tmp_path)
    resolved.close()
    assert [os.path.exists(p) for p in paths] == [False, False, False]


def test_close_is_idempotent(tmp_path):
    resolved, _ = _resolved(tmp_path)
    resolved.close()
    resolved.close()  # a file already gone is not an error


def test_close_removes_the_rest_when_one_file_cannot_be_removed(tmp_path):
    """The regression: one refusal must not strand the other secrets."""
    resolved, paths = _resolved(tmp_path)
    blocked = paths[1]

    real_remove = os.remove

    def refuse_one(path, *args, **kwargs):
        if path == blocked:
            raise PermissionError(13, "Permission denied", path)
        return real_remove(path, *args, **kwargs)

    with mock.patch("os.remove", side_effect=refuse_one):
        with pytest.raises(PermissionError):
            resolved.close()

    assert not os.path.exists(paths[0]), "file before the failure was not removed"
    assert not os.path.exists(paths[2]), "file after the failure was stranded on disk"
    assert os.path.exists(blocked), "the blocked file should still be there"


def test_close_reports_the_first_failure(tmp_path):
    """Two refusals: the first is raised, matching Go's firstErr / .NET's firstError."""
    resolved, paths = _resolved(tmp_path, count=2)

    def refuse_all(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied", path)

    with mock.patch("os.remove", side_effect=refuse_all):
        with pytest.raises(PermissionError) as excinfo:
            resolved.close()

    assert excinfo.value.filename == paths[0]


def test_context_manager_exit_closes(tmp_path):
    resolved, paths = _resolved(tmp_path)
    with resolved:
        assert all(os.path.exists(p) for p in paths)
    assert not any(os.path.exists(p) for p in paths)
