# Corrupted file: Repairing a Broken JPEG Header

**Source:** picoMini (CMU-Africa) | **Category:** Forensics | **Difficulty:** Easy

---

## Executive Summary

The challenge provides one file that the system cannot identify (`file` reports only `data`) and no viewer will open. The hints point to the file header and to JPEG. The first two bytes of the file were replaced with the text characters `\x` (hex `5C 78`), which breaks the JPEG start-of-image marker. Restoring those two bytes to `FF D8` turns the file back into a valid 500 x 500 JPEG, and the flag is visible in the image.

**Impact:** Two wrong bytes at the start of a file are enough to make it unreadable, even though all the image data after them is intact.

---

## Vulnerability Analysis

### Target Behavior

The downloaded file (saved here as `file (2)`) has no extension and is not recognized:

```bash
$ file 'file (2)'
file (2): data

$ xxd 'file (2)' | head -n 3
00000000: 5c78 ffe0 0010 4a46 4946 0001 0100 0001  \x....JFIF......
00000010: 0001 0000 ffdb 0043 0008 0606 0706 0508  .......C........
00000020: 0707 0709 0908 0a0c 140d 0c0b 0b0c 1912  ................
```

The text `JFIF` is visible in the dump, so the rest of the header looks like a normal JPEG.

### Root Cause: Damaged Magic Bytes

File formats start with a fixed signature (magic bytes) that tools use to identify the type. A JPEG starts with the start-of-image marker `FF D8`, followed by `FF E0` for the JFIF header.

| | First 4 bytes | As text |
|---|---|---|
| Valid JPEG | `FF D8 FF E0` | `....` |
| This file | `5C 78 FF E0` | `\x..` |

Bytes 0 and 1 are the ASCII characters `\` and `x`, which look like the start of an escape sequence written as plain text instead of the real bytes. Because the signature does not match, `file` and image viewers reject the file.

---

## Exploit Development

### Steps

1. Run `file` and look at the first bytes with `xxd`, as above.
2. Compare them with the known JPEG signature (`FF D8 FF E0`).
3. Overwrite only the first two bytes with `FF D8`, leaving everything else unchanged.
4. Run `file` again, then open the image.

Patch on a copy, so the original stays untouched:

```bash
cp 'file (2)' recovered.jpg
printf '\377\330' | dd of=recovered.jpg bs=1 count=2 conv=notrunc
```

`conv=notrunc` makes `dd` overwrite the two bytes without cutting off the rest of the file. The octal escapes `\377\330` are the bytes `FF D8`; they work in any shell. The form `printf '\xff\xd8'` works in bash but not in `sh`/`dash`, where it writes the literal text `\xff\xd8` and would damage the file again.

An interactive alternative is `hexedit`: open the file, type `FF` and `D8` over the first two bytes, then press `Ctrl+X` and `Y` to save.

### Checking the Result

```bash
$ file recovered.jpg
recovered.jpg: JPEG image data, JFIF standard 1.01, ..., baseline, precision 8, 500x500, components 3
```

`file` now identifies a 500 x 500 JPEG and the image opens in a viewer. The same patch was also tested on a generated JPEG with the same damage, and the repaired copy opened normally.

### Result

The flag is shown in the repaired image (flag omitted from this writeup).

---

## Mitigation

| Weakness | Fix |
|---|---|
| File type decided by name or extension | Identify uploaded files by content (magic bytes), not by extension |
| Silent corruption of file headers | Store checksums or digital signatures for important files, so damage is detected early |
| No way to recover damaged files | Keep backups or versioned copies of important data |
| Header treated as proof a file is safe | A correct header does not mean a file is harmless, so validate the full file as well, not only the first bytes |

---

## Key Takeaways

- Tools such as `file` identify a file by its magic bytes, so a damaged header makes a file look like "data".
- Knowing common signatures helps: `FF D8 FF` for JPEG, `89 50 4E 47` for PNG, `25 50 44 46` for PDF.
- Shell commands can behave differently between `bash` and `sh`. Checking the result after patching is part of the job.
