# elrond Configuration

## Environment Variables

Elrond behavior can be configured through environment variables:

### Non-Interactive Mode (Default: Enabled)

```bash
# Automatically enabled in Docker containers
ELROND_NONINTERACTIVE=1
```

**Purpose**: Ensures clean output for web applications and automation
- No interactive prompts (uses safe defaults)
- No ANSI color codes or ASCII art
- No separator lines or visual formatting
- Perfect for job logs and monitoring

**Default**: `1` (enabled)
**To disable** (interactive CLI mode only): `ELROND_NONINTERACTIVE=0`

### Elrond Paths

```bash
ELROND_HOME=/opt/elrond          # Installation directory
ELROND_OUTPUT=/output            # Analysis output directory
ELROND_EVIDENCE=/evidence        # Evidence/source files directory
ELROND_CASES=/cases              # Case files directory
ELROND_LOG_DIR=/var/log/elrond   # Log directory
```

### TERM Variable

The `TERM` environment variable is automatically set to `xterm` to prevent subprocess warnings.

---

## Installation

[Prepare Virtual Machine](https://github.com/cmdaltr/elrond/blob/main/elrond/VIRTUALMACHINE.md)<br>

---
<br>

⚠️ _The following script will partition and format /dev/sdb. If you have not configured the second HDD as recommended above, it may delete data if you have another drive mounted. You can change this location, by editing the [init.sh](https://github.com/cmdaltr/elrond/blob/main/elrond/tools/scripts/init.sh) script_<br><br>
<!-- sudo passwd elrond && sudo apt install git -y && sudo hostname elrond -->
`sudo git clone https://github.com/cmdaltr/elrond.git /opt/elrond && sudo /opt/elrond/./make.sh`<br>
  - &darr; &darr; `ENTER c g` *(apfs-fuse on x64 architecture only)*<br>

---
<br>

[Revert Virtual Machine](https://github.com/cmdaltr/elrond/blob/main/elrond/VIRTUALMACHINE.md)