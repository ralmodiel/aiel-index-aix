from .repo import Repo
from util import slugify


class Service(Base):
    def __init__(self):
        self.repo = Repo()

    def run(self, name: str):
        key = slugify(name)
        self.repo.save(key)
        return self._build(key)

    def _build(self, key):
        helper = Helper()
        return helper.make(key)


def main():
    Service().run("x")
