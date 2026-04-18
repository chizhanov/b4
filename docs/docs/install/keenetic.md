---
sidebar_position: 4
title: Keenetic
---

## Requirements

- Keenetic router with OPKG support
- Entware installed (required)

## Install Entware

### Newer models (with built-in storage)

1. Open the router web interface
2. Go to **System settings**
3. Enable the **OPKG package manager** component

### Older models (USB drive required)

1. Plug a USB drive into the router
2. Install Entware through the package manager

More details: https://help.keenetic.com/hc/en-us/articles/360021214160

## Install b4

Connect over SSH and run:

```bash
curl -fsSL https://raw.githubusercontent.com/DanielLavrushin/b4/main/install.sh | sh
```

## Service control

```bash
/opt/etc/init.d/S99b4 start
/opt/etc/init.d/S99b4 stop
/opt/etc/init.d/S99b4 restart
```

## Paths

| What | Where |
| --- | --- |
| Binary | `/opt/sbin/b4` |
| Configuration | `/opt/etc/b4/b4.json` |
| Service | `/opt/etc/init.d/S99b4` |

## Architecture

- Older models (MT7621) - `mipsle_softfloat`
- Newer models (aarch64) - `arm64`

The installer detects the architecture automatically.

:::warning Without Entware
Without Entware, b4 is placed in `/tmp`, which is cleared on every reboot. For persistent operation, Entware is required.
:::
