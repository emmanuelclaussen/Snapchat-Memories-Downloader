# Snapchat Memories Downloader

A reliable Python script to download Snapchat Memories exports with correct
filenames, timestamps, deduplication, and a clean chronological folder structure.

---

## Why this exists

Snapchat’s official Memories export has several well-known issues:

- Files are downloaded without proper extensions (`.jpg`, `.mp4`)
- Timestamps are lost
- Large exports frequently fail or stop midway
- Duplicates appear with no clear way to detect them
- Manual cleanup is extremely time-consuming

This script solves those problems in a safe, resumable, and structured way.

---

## Features

- Downloads Memories **oldest → newest**
- Prevents duplicates using a **stable key** (`mid` / `sid`)
- Extra safety: byte-identical files are moved to a separate *Dupes* folder
- Resume-safe downloads using `.part` files
- Correct file extensions (`.jpg` / `.mp4`)
- Date-based filenames: `YYYY-MM-DD_HH-MM-SS`
- Clean folder structure:
