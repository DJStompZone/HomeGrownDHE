from homegrowndhe import DEV_TEST
from pprint import pprint
from typing import List

from os import get_terminal_size as gts

def _twidth():
    return gts().columns

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
    elems = filter(str.isdigit, s)
    return "".join(elems)

def is_long_num(_s: str, min_d: int = 100) -> bool:
    return len(get_digits(_s)) > min_d

def get_long_numerics(s: str, min_d: int = 100) -> List[str]:
    def _long_num(_s: str) -> bool:
        return is_long_num(_s, min_d)
    qualifying = filter(_long_num, s.splitlines())
    if not qualifying:
        return []
    return list(map(get_digits, qualifying))