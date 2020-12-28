# kdbx-cli

**kdbx-cli** is an interactive command-line interface for the KeePass password database (.kdbx).

## Features

- Thin wrapper over the [pykeepass](https://github.com/libkeepass/pykeepass) library as the only dependency except the standard Python modules
- Runs as a single process to avoid the complexity of protecting inter-process communication (unlike [passhole](https://github.com/Evidlo/passhole) which keeps a [background process](https://github.com/libkeepass/pykeepass_cache))
- Interoperable with [KDBX 4.0](https://keepass.info/help/kb/kdbx_4.html), [KeePassXC](https://keepassxc.org) and [Keepass2Android Offline](https://github.com/PhilippC/keepass2android)
- Clipboard integration (using `xclip` by default)
- Auto-erase clipboard (after `10` seconds by default)
- Auto-completion using the `tab` key
- No destructive operations 
  - Every change is saved to entry history
  - Deleted entries are moved to `Recycle Bin`
- Prevent overwriting the database file when its modified time changes (not atomic)
  - For file synchronization use e.g. [Syncthing](https://syncthing.net) with [Staggered File Versioning](https://docs.syncthing.net/users/versioning.html)
- Copying entries to another database file
- SSH integration (using the included scripts [sshgen](sshgen), [sshknown](sshknown))
- Custom Attributes
- Notes are line-separated and prepended with a label

## Limitations

- Database files can be protected only by a password
- New entries can be created only in the root group
- Entry titles with spaces are not supported in commands with multiple parameters (but can be changed using `rename`)
- Auto-closing not available
- No GPG integration (e.g. by [forwarding gpg-agent](https://wiki.gnupg.org/AgentForwarding))
- Only tested manually
- Not published to [PyPI](https://pypi.org/) yet

## Install

Copy/clone the `kdbx-cli` script and make it executable.

Install [pykeepass](https://github.com/libkeepass/pykeepass):
```sh
pip3 install pykeepass==3.2.1
```

**MacOS** requires additional configuration for [GNU readline interface](https://docs.python.org/3/library/readline.html) to make tab-completion work:
```sh
tee ~/.editrc << EOM
python:bind ^I rl_complete
EOM
brew reinstall readline
```
**MacOS** uses `pbcopy` instead of `xclip`:
```sh
alias kp='kp --clip "pbcopy" --paste "pbpaste"'
```

On **Windows** or **WSL**, `win32yank` can be used (e.g. installed with [neovim](https://github.com/neovim/neovim/wiki/FAQ#how-to-use-the-windows-clipboard-from-wsl) by default):
```sh
alias kp='kp --clip "win32yank.exe -i --crlf" --paste "win32yank.exe -o --lf"'
```

## Commands

Start the interactive CLI with:
```sh
kp FILENAME
```

Use the `tab` key for auto-completion.

General
- `help` list all commands
- `q`  quit
- press `Ctrl`+`D` to quit and `Ctrl`+`C` to interrupt
- `ls`  list entries
- `s [TITLE]`  select entry by title
- `add TITLE`  new entry with title
- `rename TITLE`  change title
- `rm ENTRY...`  move entries to recycle bin
- `restore ENTRY...`  restore entries from recycle bin
- `cp FILE ENTRY...`  copy entries to db file
- `mv FILE ENTRY...`  copy entries to db file, then move to recycle bin
- `dedup`  number duplicate titles
- `passwd`  change db password
- `c`  clear clipboard

Read Entry
- `dump`  display fields
- `history`  display changes
- `h [TIME]`  select history item
- `p`  clip password
- `pd`  display password
- `u`  clip username
- `ud`  display username
- `l`  clip location (URL)
- `ld`  display location (URL)
- `n LABEL`  clip note by label
- `nd LABEL`  display note by label
- `ndump`  display notes
- `a LABEL`  clip attribute by label
- `ad LABEL`  display attribute by label
- `ssh [TIME]`  ssh-add private key (from password)
- `sshknown`  add to known_hosts (from URL)

Modify Entry
- `pput`  change password
- `ppaste`  paste new password
- `uput`  change username
- `upaste`  paste new username
- `lput`  change location (URL)
- `lpaste`  paste new location
- `nput LABEL`  change note by label
- `nrm LABEL`  remove note by label
- `aput LABEL`  change attribute by label
- `apaste LABEL`  paste new attribute by label
- `arm LABEL`  remove attribute by label

Generate Entry Passwords
- `agen LABEL SIZE`  generate new printable attribute
- `agena LABEL SIZE`  generate new alphanumeric attribute
- `agend LABEL SIZE`  generate new digit attribute
- `pgen SIZE`  generate new printable password
- `pgena SIZE`  generate new alphanumeric password
- `pgend SIZE`  generate new digit password
- `ngena LABEL SIZE`  generate new alphanumeric note
- `ngend LABEL SIZE`  generate new digit note
- `sshgen`  generate ssh keys

## Alternatives

* [keepassxc-cli](https://keepassxc.org/project/)
* [passhole](https://github.com/Evidlo/passhole)

