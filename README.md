# PSP DOCUMENT.DAT Decrypter/Unpacker

Scripts for decrypting and unpacking png from `PS1 on PSP/ePSP/PS3`, `PSP` and `Minis` manuals.

Both scripts support manuals with more than 100 pages.

To use the scripts, `Python 3.12+` is required, and the `pycryptodome` package must be installed.

## app_ps1.py
* For `PS1 on PSP/ePSP/PS3`manuals.

Copy DOCUMENT.DAT files into the `dat_ps1docs` folder using any filename with the `.DAT` extension.

The script will create an `out_png_ps1` folder containing all pages.

Additionally, the decrypted `DOCUMENT_DEC.DAT` (only for PSP CFW) file will be saved in the `out_dat_ps1` folder.

## app_psp.py
* For `PSP Game` and `Minis` manuals.

Copy `DOCUMENT.DAT` and `DOCINFO.EDAT` (if present) into the `dat_pspdocs` folder, adding a prefix to the filenames
(for example: `GAME_ULUS12345_DOCUMENT.DAT` and `GAME_ULUS12345_DOCINFO.EDAT`, respectively).

The script will create an `out_png_psp` folder containing all pages.

Additionally, a re-encrypted `DOCUMENT.DAT` using the default key (to get rid of the `DOCINFO.EDAT` file requirement) will be saved in the `out_dat_psp` folder.

## DOCUMENT.DAT format

For format summary of the PS1 / PSP DOCUMENT.DAT read [README_FORMAT.md](README_FORMAT.md).

## Creating DOCUMENT.DAT

For creating PS1 DOCUMENT.DAT file you can use [pop-fe](https://github.com/sahlberg/pop-fe) tool.
