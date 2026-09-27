import argparse

import pytest

from grAPI.cli import parse_window_size


def test_parse_window_size_valid():
    assert parse_window_size("1440x900") == (1440, 900)
    assert parse_window_size("1024X768") == (1024, 768)
    assert parse_window_size("800,600") == (800, 600)
    assert parse_window_size(" 1280 x 720 ") == (1280, 720)


def test_parse_window_size_rejects_garbage():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_window_size("fullscreen")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_window_size("100x100")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_window_size("x900")
