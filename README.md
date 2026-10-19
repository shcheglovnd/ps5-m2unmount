# m2unmount

PS5 payload that unmounts the console's own volume on the M.2 SSD and keeps it unmounted,
for consoles that boot Linux from that drive with
[ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader).

## Why

Linux can live on the M.2 inside the console's own bfs volume (`/dev/ssd1.user`, mounted at
`/mnt/ext1`). PS5-OS mounts that volume at every boot and marks it dirty. A session that ends
in a kexec into Linux never unmounts it, so the next PS5 boot shows "Repairing" for the M.2.

Unmounting the volume right after the jailbreak writes the clean state and keeps PS5-OS off the
drive for the rest of the session. Tested on a CFI-1115A, firmware 4.50: after a Linux session
the next boot no longer repairs the M.2, and the console only warns that it wasn't turned off
properly.

## Use

Send `m2unmount.elf` to an ELF loader on port 9021, for example the elfldr that the umtx2
jailbreak starts, or etaHEN's:

    make send PS5_HOST=<ps5-ip>

- It unmounts every volume on the M.2 (`ssd1`…`ssd9`; the internal drive is `ssd0`) and shows
  a notification.
- It stays resident and unmounts again if the console mounts one later. It does no periodic
  work while games run: it sleeps until the kernel reports a mount (`EVFILT_FS`), waits 2 s for
  the burst to settle (a game launch mounts dozens of sandboxes), then checks once, at most once
  per 10 s. A safety check runs every 10 min. One check reads the mount table, about 0.2 ms with
  ~940 mounts.
- It never forces an unmount: a busy volume is retried every 10 s, with one notification.
- Loading it again replaces the running copy.
- Status: `nc <ps5-ip> 9211` prints a short report.
- Log: `/data/m2unmount.log` (events only, rotated at 256 KiB).

## Build

Needs the [ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk) and a system clang 19
with lld:

    make PS5_PAYLOAD_SDK=/path/to/sdk        # default /opt/ps5-payload-sdk

The notification call and the `kinfo_proc` offsets used to find a running copy follow
[ps5-payload-dev/shsrv](https://github.com/ps5-payload-dev/shsrv).

## License

GPL-3.0, see [LICENSE](LICENSE).
