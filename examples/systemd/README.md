# Example systemd units

`muster-collect.service` runs `/usr/bin/muster collect` once; `muster-collect.timer`
starts it weekly (`OnCalendar=weekly`, `Persistent=true`, with up to an hour of
random delay). Each run writes a snapshot under `/var/lib/muster`, the default
`--out`.

The muster package does not install these units on the unit search path and
never enables them: they ship as documentation under
`/usr/share/doc/muster/examples/systemd/` (and under `examples/systemd/` in the
release archive). To use them, as root:

```sh
install -m 0644 /usr/share/doc/muster/examples/systemd/muster-collect.service /usr/share/doc/muster/examples/systemd/muster-collect.timer /etc/systemd/system/
systemctl enable --now muster-collect.timer
```

The unit runs `collect` without `--deep`. To walk the filesystem too, edit
`ExecStart=` in your copy; every snapshot it takes is then deep.
