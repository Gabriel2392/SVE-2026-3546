# android-resigner

## Build

```sh
cargo build --release --manifest-path android-resigner/Cargo.toml
```

## Full firmware

```sh
android-resigner AP.tar.md5 CP.tar.md5 CSC.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  -o AP_RESIGNED.tar.md5
```

```sh
android-resigner AP.tar.md5 CP.tar.md5 CSC.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  --image boot=boot.img \
  --image vendor_boot=vendor_boot.img \
  --image recovery=recovery.img \
  --logical system=system.img \
  --logical vendor=vendor.img \
  -o AP_RESIGNED.tar.md5
```

```sh
android-resigner AP.tar.md5 CP.tar.md5 CSC.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  --super super.img \
  -o AP_RESIGNED.tar.md5
```

Result:

```text
AP_RESIGNED.tar.md5
BL_RESIGNED.tar.md5 (vbmeta.img updated)
```

```sh
android-resigner AP.tar.md5 CP.tar.md5 CSC.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  --aosp-zip lineage.zip \
  -o AP_RESIGNED.tar.md5
```

Result:

```text
AP_RESIGNED.tar.md5
BL_RESIGNED.tar.md5 (vbmeta.img updated)
```

## Update AP

```sh
android-resigner update-ap \
  --base AP_RESIGNED.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  --image boot=boot.img \
  --logical vendor=vendor.img
```

Result:

```text
AP_RESIGNED.tar.md5
BL_RESIGNED.tar.md5 (vbmeta.img updated)
```

```sh
android-resigner update-ap \
  --base AP_RESIGNED.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  --image boot=boot.img \
  --incremental
```

Result:

```text
INCREMENTAL.tar.md5
BL_RESIGNED.tar.md5 (vbmeta.img updated)
```

```sh
android-resigner update-ap \
  --base AP_RESIGNED.tar.md5 \
  --bl BL_RESIGNED.tar.md5 \
  --aosp-zip lineage.zip \
  --incremental
```

Result:

```text
INCREMENTAL.tar.md5
BL_RESIGNED.tar.md5 (vbmeta.img updated)
```

## Sign one image

```sh
android-resigner sign-image \
  --from AP_RESIGNED.tar.md5 \
  --name boot.img \
  boot.img boot-signed.img
```

```sh
android-resigner sign-image \
  --from AP_RESIGNED.tar.md5 \
  --name vendor.img \
  vendor.img vendor-signed.img
```
