# DOCUMENT.DAT Format

| Name                                        |
|---------------------------------------------|
| PGD Header                                  |
| DOC Header                                  |
| DOC Info Block                              |
| DOC Pages Blocks                            |

## PGD Header

| offset | Size | Name      | Remarks                       |
|--------|------|-----------|-------------------------------|
|   0x00 | 0x04 | magic     | Magic: 00 50 47 44 (b"\0PGD") |
|   0x04 | 0x04 | key_index | Key Index, Always 1           |
|   0x08 | 0x04 | drm_type  | DRM Type. Always 1            |
|   0x0c | 0x04 | reserved  | Reserved: 00 00 00 00         |

## DOC Header
