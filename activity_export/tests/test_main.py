import os
import sys
from datetime import datetime

sys.path.insert(0, f"{os.path.dirname(__file__)}/../")

from main import _get_first_day_of_month, _get_last_day_of_month, _get_last_month


def test_get_first_day_of_month():
    month = datetime(2022, 3, 15)
    expected = datetime(2022, 3, 1, 0, 0, 0)
    assert _get_first_day_of_month(month) == expected


def test_get_last_day_of_month_1():
    month = datetime(2024, 3, 15, )
    expected = datetime(2024, 3, 31, 0, 0, 0)
    assert _get_last_day_of_month(month) == expected


def test_get_last_day_of_month_2():
    month = datetime(2024, 1, 15)
    expected = datetime(2024, 1, 31, 0, 0, 0)
    assert _get_last_day_of_month(month) == expected


def test_get_last_day_of_month_3():
    month = datetime(2023, 12, 15)
    expected = datetime(2023, 12, 31, 0, 0, 0)
    assert _get_last_day_of_month(month) == expected


def test_get_last_month():
    assert _get_last_month() == '2024-03'
