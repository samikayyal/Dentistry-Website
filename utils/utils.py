from datetime import datetime


def number_to_month(num: int):
    """
    Converts a number (1-12) to its corresponding month name.

    Args:
        num (int): Month number (1-12).

    Returns:
        str: Month name (e.g., 'January', 'February', etc.),
        or empty string if the number is out of range.
    """
    months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    return months[num - 1] if 1 <= num <= 12 else ""


def format_datetime(date_str: str, method:str) -> str:
    """
    Formats an ISO-like date string into 'Month Day, Year' format.

    Args:
        dt_str (str): Datetime value.
        method (str): Either 'month day, year' or 'month year'.

    Returns:
        str: A string with the date formatted as 'Month Day, Year' (e.g., 'April 14, 2025'),
        or empty string if the input string format is invalid.
    """

    # 2025-04-14 12:44:12.841265+00
    # date_str = str(date_str)
    # print(f"date_str: {date_str}")
    # print(type(date_str))
    year = date_str[0:4]
    month = number_to_month(int(date_str[5:7]))
    day = date_str[8:10]

    if method == "month year":
        return f"{month} {year}" if month else ""
    elif method == "month day, year":
        return f"{month} {day}, {year}" if month else ""
