import json
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOCS = ("s5e8825", "s5e9925")
PROFILE_KEYS = {
    "soc", "signing", "key_image", "vbmeta_image", "lk", "loader", "images",
}
SIGNING_KEYS = {
    "codesigner_type", "st2_tee_key", "st2_ree_key",
    "avb_private_key", "avb_public_key",
}


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
    preserve: bool = False


@dataclass(frozen=True)
class Layout:
    soc: str
    signing_type: int
    key_image: str
    vbmeta_image: str
    lk_image: str
    lk_part: str
    code_area: str
    alias_base: int | None
    images: tuple[Image, ...]

    @property
    def by_name(self) -> dict[str, Image]:
        return {image.name: image for image in self.images}

    @property
    def names(self) -> set[str]:
        return {image.name for image in self.images}

    def lk(self, images: dict[str, bytes]) -> bytes:
        image = self.by_name[self.lk_image]
        parts = [part for part in image.parts if part.name == self.lk_part]
        if len(parts) != 1:
            raise ValueError(f"{self.soc}: cannot resolve one LK part")
        part = parts[0]
        return images[image.name][part.start:part.end]

def load_part(item) -> Part:
    return Part(
        item["name"], number(item["start"]), number(item["end"]),
        item.get("stage"), item.get("key"), item.get("header", False),
        item.get("avb_keys", False),
    )


def load_image(item) -> Image:
    return Image(
        item["name"], item.get("stage", "st2"), item.get("key", "ree"),
        item.get("avb"), tuple(load_part(part) for part in item.get("parts", ())),
        item.get("bundle", True), item.get("version", True),
        item.get("preserve", False),
    )


def load(path: Path) -> Layout:
    path = path.resolve()
    raw = json.loads(path.read_text())
    if set(raw) != PROFILE_KEYS or set(raw["signing"]) != SIGNING_KEYS:
        raise ValueError(f"{path}: invalid profile fields")
    images = tuple(load_image(item) for item in raw["images"])
    names = [image.name for image in images]
    if len(names) != len(set(names)):
        raise ValueError(f"{path}: duplicate image name")
    for image in images:
        for item in (image, *image.parts):
            if item.stage not in (None, "st1", "st2"):
                raise ValueError(f"{path}: invalid stage for {item.name}")
            if item.stage == "st2" and item.key not in ("tee", "ree"):
                raise ValueError(f"{path}: invalid ST2 key for {item.name}")
    soc = raw["soc"]
    if not re.fullmatch(r"s5e[0-9]+", soc):
        raise ValueError(f"{path}: invalid SoC name")
    layout = Layout(
        soc, int(raw["signing"]["codesigner_type"]), raw["key_image"],
        raw["vbmeta_image"], raw["lk"]["image"], raw["lk"]["part"],
        raw["loader"]["code_area"], number(raw["loader"]["alias_base"]), images,
    )
    if layout.code_area not in ("download", "alias"):
        raise ValueError(f"{path}: invalid loader code area")
    if (layout.code_area == "alias") != (layout.alias_base is not None):
        raise ValueError(f"{path}: invalid loader alias")
    if not {layout.key_image, layout.vbmeta_image, layout.lk_image} <= layout.names:
        raise ValueError(f"{path}: missing primary image")
    lk_parts = [part for part in layout.by_name[layout.lk_image].parts
                if part.name == layout.lk_part]
    if len(lk_parts) != 1:
        raise ValueError(f"{path}: cannot resolve one LK part")
    return layout


def get(soc: str, root: Path = ROOT) -> Layout:
    if soc not in SOCS:
        raise ValueError(f"invalid SoC: {soc}")
    path = root / f"{soc}.json"
    if not path.is_file():
        raise ValueError(f"missing SoC profile: {path}")
    layout = load(path)
    if layout.soc != soc:
        raise ValueError(f"profile does not match --soc {soc}")
    return layout
