from dataclasses import dataclass


type Pair[T] = tuple[T, T]


class Box[T]:
    def __init__(self, item: T) -> None:
        self.item = item

    def get(self) -> T:
        return self.item


def first[T](xs: list[T]) -> T:
    return xs[0]


@dataclass
class Point:
    x: int
    y: int


def describe(cmd):
    match cmd:
        case Point(x=0, y=0):
            return "origin"
        case [a, b, *rest]:
            return helper(a)
        case {"k": v}:
            return helper(v)
        case _:
            return "other"


def helper(v):
    if (n := len(str(v))) > 2:
        return n
    try:
        pass
    except* ValueError:
        pass
    return Box(1).get()
