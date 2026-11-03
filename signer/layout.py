import json
from dataclasses import dataclass
from pathlib import Path


def number(value):
    return int(value, 0) if isinstance(value, str) else value


@dataclass(frozen=True)
class Part:
    name: str
    start: int
    end: int | None
    stage: str | None = None
    key: str | None = None
    header: bool = False
    avb_keys: bool = False

    @property
    def size(self) -> int | None:
        return None if self.end is None else self.end - self.start


@dataclass(frozen=True)
class Image:
    name: str
    stage: str | None = "st2"
    key: str | None = "ree"
    avb: str | None = None
    parts: tuple[Part, ...] = ()
    bundle: bool = True
    version: bool = True


def load_part(item):
    return Part(
        item["name"], number(item["start"]), number(item["end"]),
        item.get("stage"), item.get("key"), item.get("header", False),
        item.get("avb_keys", False),
    )


def load_image(item):
    return Image(
        item["name"], item.get("stage", "st2"), item.get("key", "ree"),
        item.get("avb"), tuple(load_part(part) for part in item.get("parts", ())),
        item.get("bundle", True), item.get("version", True),
    )


CONFIG = json.loads(
    (Path(__file__).resolve().parents[1] / "s5e8825.json").read_text()
)

IMAGES = tuple(load_image(item) for item in CONFIG["images"])
BY_NAME = {image.name: image for image in IMAGES}
SIGNING_TYPE = int(CONFIG["signing_type"])
KEY_IMAGE = CONFIG["key_image"]
VBMETA_IMAGE = CONFIG["vbmeta_image"]
LK_IMAGE = CONFIG["lk"]["image"]
LK_PART = CONFIG["lk"]["part"]
