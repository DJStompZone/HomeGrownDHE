from homegrowndhe import DEV_TEST
from pprint import pprint
from typing import List

from os import get_terminal_size as gts

def _twidth():
    try:
        return gts().columns
    except OSError:
        return 40

def twidth():
    try:
        return _twidth()
    except PermissionError:
        return 40

def cprint(*args, padding=3, **kwargs):
    txt = " ".join(list(map(str, *args)))
    print(txt.center(twidth()-(padding*2), "=").center(twidth()))

def blockprint(txt):
    cprint("", padding=0)
    cprint(f" {txt} ", padding=0)
    cprint("", padding=0)

def p_print(*args, **kwargs):
    if not DEV_TEST:
        return
    try:
        if kwargs.keys():
            raise TypeError()
        pprint(*args)
    except (TypeError, AttributeError):
        print(*args, **kwargs)

def get_digits(s: str) -> str:
    return "".join(filter(str.isdigit, s))

def is_long_num(_s: str, min_d: int = 100) -> bool:
    return len(get_digits(_s)) > min_d

def get_long_numerics(s: str, min_d: int = 100) -> List[str]:
    lines = s.splitlines()
    qualifying = [line for line in lines if is_long_num(line, min_d)]
    return [get_digits(line) for line in qualifying]
