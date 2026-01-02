# PSP DOCUMENT.DAT Decrypter/Unpacker

Both scripts support manuals with more than 100 pages.
To use the scripts, Python 3.12+ is required, and the pycryptodome package must be installed.

## app_ps1.py
Copy DOCUMENT.DAT files into the `dat_ps1docs` folder using any filename with the `.DAT` extension.
The script will create an `out_png_ps1` folder containing all pages.
Additionally, the decrypted `DOCUMENT.DAT` file will be saved in the `out_dat_ps1` folder.

## app_psp.py
Copy `DOCUMENT.DAT` and `DOCINFO.EDAT` (if present) into the `dat_pspdocs` folder, adding a prefix to the filenames
(for example: `GAME_ULUS12345_DOCUMENT.DAT` and `GAME_ULUS12345_DOCINFO.EDAT`, respectively).
The script will create an `out_png_psp` folder containing all pages.
Additionally, a re-encrypted `DOCUMENT.DAT` using the default key (to get rid of the `DOCINFO.EDAT` file requirement) will be saved in the `out_dat_psp` folder.
