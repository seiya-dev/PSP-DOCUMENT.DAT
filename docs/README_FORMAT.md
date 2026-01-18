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
| 0x0000 | 0x04 | magic     | Magic: 00 50 47 44 (b"\0PGD") |
| 0x0004 | 0x04 | key_index | Key Index, Always 1           |
| 0x0008 | 0x04 | drm_type  | DRM Type. Always 1            |
| 0x000c | 0x04 | reserved  | Reserved: 00 00 00 00         |

## DOC Header (Encrypted)

| offset PS1 | offset PSP | Size | Name       | Remarks PS1 on PSP/ePSP/PS3                                                   | Remarks PSP                                                               |
|------------|------------|------|------------|-------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| 0x00000010 | 0x00000010 | 0x60 | doc_header | Encrypted Header Data                                                         | Encrypted Header Data                                                     |
| 0x00000070 | 0x00000070 | 0x10 | mac_hash   | BB MAC of Encrypted Header Data using Secure Install ID as key via sceIoIoctl | Zeroes                                                                    |
| 0x00000080 | 0x00000080 | 0x10 | digest     | First 16 bytes of SHA-1 from Encrypted Header Data                            | First 16 bytes of HMAC-SHA-1 with PSP HMAC Key from Encrypted Header Data |
|            | 0x00000090 | 0x10 | digest_ps3 |                                                                               | First 16 bytes of HMAC-SHA-1 with PS3 HMAC Key from Encrypted Header Data |

* Note 1: For PS1 DOCUMENT.DAT - "mac_hash" used in PSP, "digest" used in ePSP/PS3

* Note 2: For PSP DOCUMENT.DAT - "digest" used in PSP, "digest_ps3" used in ePSP/PS3 (Need be checked)

### Header Data (Decrypted)

| offset | Size | Name      | Remarks                                                                                                                       |
|--------|------|-----------|-------------------------------------------------------------------------------------------------------------------------------|
| 0x0000 | 0x04 | magic     | Magic: 44 4F 43 20 ("DOC ")                                                                                                   |
| 0x0004 | 0x08 | unknown   | Unknown value. Always 0x00000100 0x00000100 (Unused?)                                                                         |
| 0x000C | 0x10 | title_id  | Format: XXXXYYYYY. ASCII string followed by null-terminator (Unused?)                                                         |
| 0x001C | 0x04 | size_flag | 1 = greater size, 0 = smaller, else fail. The info block size switch determines the size of the info block: 0x31E8 or 0x1F3E8 |
| 0x0020 | 0x40 | padding   | Zeroed                                                                                                                        |

## DOC Info Block (Encrypted)

| offset PS1       | offset PSP       | Size             | Name       | Remarks PS1 on PSP/ePSP/PS3                                                  | Remarks PSP                                                              |
|------------------|------------------|------------------|------------|------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| 0x0090           | 0x00A0           | 0x31E8 / 0x1F3E8 | info_block | Encrypted Info Block                                                         | Encrypted Info Block                                                     |
| 0x3278 / 0x1F478 | 0x3288 / 0x1F488 | 0x10             | mac_hash   | BB MAC of Encrypted Info Block using Secure Install ID as key via sceIoIoctl | Zeroed                                                                   |
| 0x3288 / 0x1F488 | 0x3298 / 0x1F498 | 0x10             | digest     | First 16 bytes of SHA-1 from Encrypted Info Block                            | First 16 bytes of HMAC-SHA-1 with PSP HMAC Key from Encrypted Info Block |
|                  | 0x32A8 / 0x1F4A8 | 0x10             | digest_ps3 |                                                                              | First 16 bytes of HMAC-SHA-1 with PS3 HMAC Key from Encrypted Info Block |

### Info Block (Decrypted)

| offset           | Size                   | Name             | Remarks                                            |
|------------------|------------------------|------------------|----------------------------------------------------|
| 0x0000           | 0x04                   | unknown          | Unknown. Always 0xFFFFFFFF (-1) in all known files |
| 0x0004           | 0x04                   | total_pages      | Total page count (Used in PSP)                     |
| 0x0008           | 99 x 0x80 / 999 x 0x80 | file_info        | File Info section                                  |
| 0x3188 / 0x1F388 | 0x04                   | total_pages_ps3  | Total page count (Used in PS3)                     |
| 0x318C / 0x1F38C | 0x5C                   | padding          | Zeroed                                             |

### File Info Entry

| offset  | Size | Name             | Remarks                                                                 |
|---------|------|------------------|-------------------------------------------------------------------------|
| 0x0000  | 0x04 | offset           | File pointer for PSP image (points to offset in encrypted DOCUMENT.DAT) |
| 0x0004  | 0x08 | unknown          | Zeroed                                                                  |
| 0x000C  | 0x04 | size             | PSP File entry size (including hashes)                                  |
| 0x0010  | 0x04 | offset_ps3       | File pointer for PS3 image (points to offset in encrypted DOCUMENT.DAT) |
| 0x0014  | 0x08 | unknown          | Zeroed                                                                  |
| 0x001C  | 0x04 | size_ps3         | PS3 File entry size (including hashes)                                  |
| 0x0020  | 0x60 | unknown          | Zeroed                                                                  |

## Page / File Entry

| offset PS1                 | offset PSP                 | Size             | Name           | Remarks PS1 on PSP/ePSP/PS3                                                                   | Remarks PSP                                                                               |
|----------------------------|----------------------------|------------------|----------------|-----------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| 0x0000                     | 0x0000                     | 0x20             | file_header    | File header, encrypted                                                                        | File header, encrypted                                                                    |
| 0x0020                     | 0x0020                     | k * 0x08         | enc_chunk_info | List of encrypted chunk descriptors, encrypted. Each descriptor is 8 bytes                    | List of encrypted chunk descriptors, encrypted. Each descriptor is 8 bytes                |
| 0x0020 + k*0x08            | 0x0020 + k*0x08            | n                | png_file       | PNG file                                                                                      | PNG file                                                                                  |
| 0x0020 + k*0x08 + n        | 0x0020 + k*0x08 + n        | 0x10             | mac_hash       | BB MAC of (File Header + Chunk Info + PNG File) using Secure Install ID as key via sceIoIoctl | Zeroed                                                                                    |
| 0x0020 + k*0x08 + n + 0x10 | 0x0020 + k*0x08 + n + 0x10 | 0x10             | digest         | First 16 bytes of SHA-1 from (File Header + Chunk Info + PNG File)                            | First 16 bytes of HMAC-SHA-1 with PSP HMAC Key from (File Header + Chunk Info + PNG File) |
|                            | 0x0020 + k*0x08 + n + 0x20 | 0x10             | digest_ps3     |                                                                                               | First 16 bytes of HMAC-SHA-1 with PS3 HMAC Key from (File Header + Chunk Info + PNG File) |

### File Header (Decrypted)

| offset  | Size | Name             | Remarks                                                                                        |
|---------|------|------------------|------------------------------------------------------------------------------------------------|
| 0x0000  | 0x04 | file_size        | Total size of the file including this header, encrypted chunk descriptors, PNG file and hashes |
| 0x0004  | 0x04 | unknown          | Zeroed                                                                                         |
| 0x0008  | 0x04 | enc_chunks_count | Number of encrypted file chunks. Can be 0.                                                     |
| 0x000C  | 0x14 | unknown          | Zeroed                                                                                         |

### Encrypted Chunk Info entry

| offset  | Size | Name   | Remarks                                                     |
|---------|------|------- |-------------------------------------------------------------|
| 0x0000  | 0x04 | offset | Offset into PNG file (Not file entry) of an encrypted chunk |
| 0x0004  | 0x04 | size   | Size of encrypted chunk in PNG file                         |
