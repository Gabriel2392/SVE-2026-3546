from dataclasses import dataclass


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


# This is ONLYY FOR s5e8825
IMAGES = (
    Image(
        "fld.bin",
        avb="fld",
        parts=(
            Part("bl1.bin", 0, 0x3000, "st1"),
            Part("tail.bin", 0x3000, None),
        ),
    ),
    Image(
        "harx.bin",
        avb="harx",
        parts=(
            Part("harx.bin", 0, 0x200000, "st2", "ree"),
            Part("tail.bin", 0x200000, None),
        ),
    ),
    Image(
        "keystorage.bin",
        avb="keystorage",
        parts=(
            Part("keystorage.bin", 0, 0x4000, "st2", "tee", avb_keys=True),
            Part("tail.bin", 0x4000, None),
        ),
    ),
    Image(
        "ldfw.img",
        avb="ldfw",
        parts=(
            Part("ldfw.bin", 0, 0x3FC000, "st2", "tee"),
            Part("tail.bin", 0x3FC000, None),
        ),
    ),
    Image(
        "sboot.bin",
        avb="bootloader",
        parts=(
            Part("epbl.bin", 0, 0x13000, "st2", "tee", header=True),
            Part("bl2.bin", 0x13000, 0x8B000, "st2", "ree"),
            Part("pad.bin", 0x8B000, 0xE9000),
            Part("dpm.img", 0xE9000, 0xEB000, "st2", "tee"),
            Part("pad2.bin", 0xEB000, 0xED000),
            Part("lk.bin", 0xED000, 0x4ED000, "st2", "ree"),
            Part("el3_mon.bin", 0x4ED000, 0x54D000, "st2", "tee"),
            Part("tail.bin", 0x54D000, None),
        ),
    ),
    Image("tzar.img"),
    Image(
        "tzsw.img",
        avb="tzsw",
        parts=(
            Part("tzsw.bin", 0, 0x100000, "st2", "tee"),
            Part("tail.bin", 0x100000, None),
        ),
    ),
    Image("uh.bin"),
    Image(
        "up_param.bin",
        stage=None, key=None,
    ),
    Image(
        "vbmeta.img",
        stage=None, key=None,
    ),
)

BY_NAME = {img.name: img for img in IMAGES}
