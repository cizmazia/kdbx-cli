#!/usr/bin/env python3
import pykeepass
import pyotp
from getpass import getpass
from argparse import ArgumentParser
from cmd import Cmd
from collections import Counter
from os import path, listdir, urandom, stat
from datetime import datetime
import subprocess
from threading import Timer
from copy import deepcopy
import re
import uuid
from importlib.metadata import version


class KeeCmd(Cmd):
    def __init__(self, kp):
        self.kp = kp
        self.mtime = stat(kp.filename).st_mtime
        self.entry = None
        self.prompt = prompt()
        Cmd.__init__(self)

    def do_EOF(self, arg):
        'press Ctrl+D to quit and Ctrl+C to interrupt'
        return True

    def do_q(self, arg):
        'q # quit'
        return True

    def do_ls(self, arg):
        'ls # list entries'
        print('\n'.join(titles(self.kp)))

    def do_s(self, arg):
        's [TITLE] # select entry by title'
        entry = self.kp.find_entries(title=arg, first=True)
        self.entry = entry
        self.prompt = prompt(entry)

    def complete_s(self, text, line, begin, end):
        return titles(self.kp, text)

    def do_find(self, arg):
        'find STRING # find entries'
        for e in self.kp.entries:
            if contains(e, arg) and not in_recycle_bin(self.kp, e):
                print(e.title)

    def do_dig(self, arg):
        'dig STRING # find entries in recycle bin'
        for e in self.kp.entries:
            if contains(e, arg) and in_recycle_bin(self.kp, e):
                print(e.title)

    def do_c(self, arg):
        'c # clear clipboard'
        clip('')

    def do_dump(self, arg):
        'dump # display fields'
        print('\n'.join('\033[36m' + k + '\033[0m: ' + v for k, v in fields(self.entry) if v))

    def do_history(self, arg):
        'history # display changes'
        print('\n'.join('\033[36m' + k + '\033[0m: ' + v for k, v in history(self.entry)))

    def do_p(self, arg):
        'p # clip password'
        temp_clip(field(self.entry, 'password'))

    def do_pd(self, arg):
        'pd # display password'
        print(field(self.entry, 'password'))

    def do_pc(self, arg):
        'pc # pipe password'
        pipe(field(self.entry, 'password'))

    def do_pv(self, arg):
        'pv # verify password'
        print(getpass() == field(self.entry, 'password'))

    def do_otp(self, arg):
        'otp # clip TOTP'
        temp_clip(pyotp.parse_uri(field(self.entry, 'otp')).now())

    def do_otpd(self, arg):
        'otpd # display TOTP'
        print(pyotp.parse_uri(field(self.entry, 'otp')).now())

    def do_otpuri(self, arg):
        'otpuri # display OTP uri'
        print(field(self.entry, 'otp'))

    def do_ssh(self, arg):
        'ssh [TIME] # ssh-add private key (from password)'
        p = {'time': arg or '10m'}
        stdin(ssh_add_fmt.format(**p), field(self.entry, 'password'))

    def complete_ssh(self, text, line, begin, end):
        return [x for x in ['10s', '10m', '10h', '10d'] if x.startswith(text)]

    def do_sshknown(self, arg):
        'sshknown # add to known_hosts (from URL)'
        stdin(ssh_known_cmd, field(self.entry, 'url'))

    def do_u(self, arg):
        'u # clip username'
        temp_clip(field(self.entry, 'username'))

    def do_ud(self, arg):
        'ud # display username'
        print(field(self.entry, 'username'))

    def do_uc(self, arg):
        'uc # pipe username'
        pipe(field(self.entry, 'username'))

    def do_l(self, arg):
        'l # clip location (URL)'
        temp_clip(field(self.entry, 'url'))

    def do_ld(self, arg):
        'ld # display location (URL)'
        print(field(self.entry, 'url'))

    def do_lc(self, arg):
        'lc # pipe location (URL)'
        pipe(field(self.entry, 'url'))

    def do_n(self, arg):
        'n LABEL # clip note by label'
        temp_clip(note(self.entry, arg))

    def complete_n(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_nd(self, arg):
        'nd LABEL # display note by label'
        print(note(self.entry, arg))

    def complete_nd(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_nc(self, arg):
        'nc LABEL # pipe note by label'
        pipe(note(self.entry, arg))

    def complete_nc(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_ndump(self, arg):
        'ndump # display notes'
        print(field(self.entry, 'notes'))

    def do_a(self, arg):
        'a LABEL # clip attribute by label'
        temp_clip(attr(self.entry, arg))

    def complete_a(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_ad(self, arg):
        'ad LABEL # display attribute by label'
        print(attr(self.entry, arg))

    def complete_ad(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_ac(self, arg):
        'ac LABEL # pipe attribute by label'
        pipe(attr(self.entry, arg))

    def complete_ac(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_h(self, arg):
        'h [TIME] # select history item'
        e = parent_entry(self.entry)
        for h in getattr(e, 'history', []):
            if arg == to_time_str(h.mtime):
                e = h
        self.entry = e
        self.prompt = prompt(e)

    def complete_h(self, text, line, begin, end):
        e = parent_entry(self.entry)
        return [
            d for d in [to_time_str(h.mtime) for h in getattr(e, 'history', [])]
            if d.startswith(text)
        ]

    def do_add(self, arg):
        'add TITLE # new entry with title'
        e = None
        if not self.kp.find_entries(title=arg, first=True):
            e = pykeepass.entry.Entry(arg, '', '', kp=self.kp)
            self.kp.root_group.append(e)
            self.save()
        self.entry = e
        self.prompt = prompt(e)

    def do_rename(self, arg):
        'rename TITLE # change title'
        if not self.kp.find_entries(title=arg, first=True):
            self.update(lambda e: setattr(e, 'title', arg))
            self.prompt = prompt(self.entry)

    def do_pput(self, arg):
        'pput # change password'
        self.update(lambda e: setattr(e, 'password', getpass()))

    def do_ppaste(self, arg):
        'ppaste # paste new password'
        s = paste()
        if s:
            self.update(lambda e: setattr(e, 'password', s))

    def do_otpput(self, arg):
        'otpput # change TOTP secret'
        self.update(lambda e: setattr(e, 'otp', pyotp.TOTP(getpass(prompt='TOTP secret: ')).provisioning_uri()))

    def do_otppaste(self, arg):
        'otppaste # paste new TOTP secret'
        s = paste()
        if s:
            self.update(lambda e: setattr(e, 'otp', pyotp.TOTP(s).provisioning_uri()))

    def do_uput(self, arg):
        'uput # change username'
        self.update(lambda e: setattr(e, 'username', getpass(prompt='Username: ')))

    def do_upaste(self, arg):
        'upaste # paste new username'
        s = paste()
        if s:
            self.update(lambda e: setattr(e, 'username', s))

    def do_lput(self, arg):
        'lput # change location (URL)'
        self.update(lambda e: setattr(e, 'url', getpass(prompt='URL: ')))

    def do_lpaste(self, arg):
        'lpaste # paste new location'
        s = paste()
        if s:
            self.update(lambda e: setattr(e, 'url', s))

    def do_nput(self, arg):
        'nput LABEL # change note by label'
        n = notes(self.entry)
        n[arg.strip()] = getpass(prompt='Note: ')
        self.update(lambda e: setattr(e, 'notes', notes_str(n)))

    def complete_nput(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_nrm(self, arg):
        'nrm LABEL # remove note by label'
        n = notes(self.entry)
        n.pop(arg.strip(), None)
        self.update(lambda e: setattr(e, 'notes', notes_str(n)))

    def complete_nrm(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_aput(self, arg):
        'aput LABEL # change attribute by label'
        label = arg.strip()
        self.update(lambda e: e.set_custom_property(label, getpass(prompt='Attribute: ')))

    def complete_aput(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_apaste(self, arg):
        'apaste LABEL # paste new attribute by label'
        label = arg.strip()
        s = paste()
        if label and s:
            self.update(lambda e: e.set_custom_property(label, s))

    def complete_apaste(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_arm(self, arg):
        'arm LABEL # remove attribute by label'
        label = arg.strip()
        self.update(lambda e: e.delete_custom_property(label))

    def complete_arm(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_agen(self, arg):
        'agen LABEL SIZE # generate new printable attribute'
        a = arg.split()
        p = filter_urandom(to_int(a[1]), owasp) if len(a) == 2 else None
        if not p or not a[0]:
            print(None)
            return
        self.update(lambda e: e.set_custom_property(a[0], p.decode()))

    def complete_agen(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_agena(self, arg):
        'agena LABEL SIZE # generate new alphanumeric attribute'
        a = arg.split()
        p = filter_urandom(to_int(a[1]), alnum) if len(a) == 2 else None
        if not p or not a[0]:
            print(None)
            return
        self.update(lambda e: e.set_custom_property(a[0], p.decode()))

    def complete_agena(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_agend(self, arg):
        'agend LABEL SIZE # generate new digit attribute'
        a = arg.split()
        p = filter_urandom(to_int(a[1]), decimal) if len(a) == 2 else None
        if not p or not a[0]:
            print(None)
            return
        self.update(lambda e: e.set_custom_property(a[0], p.decode()))

    def complete_agend(self, text, line, begin, end):
        return attr_labels(self.entry, text)

    def do_pgen(self, arg):
        'pgen SIZE # generate new printable password'
        p = filter_urandom(to_int(arg), owasp)
        if p is None:
            print(None)
            return
        self.update(lambda e: setattr(e, 'password', p.decode()))

    def do_pgena(self, arg):
        'pgena SIZE # generate new alphanumeric password'
        p = filter_urandom(to_int(arg), alnum)
        if p is None:
            print(None)
            return
        self.update(lambda e: setattr(e, 'password', p.decode()))

    def do_pgend(self, arg):
        'pgend SIZE # generate new digit password'
        p = filter_urandom(to_int(arg), decimal)
        if p is None:
            print(None)
            return
        self.update(lambda e: setattr(e, 'password', p.decode()))

    def do_sshgen(self, arg):
        'sshgen # generate ssh keys'
        key, pub = ssh_gen()
        self.update(lambda e: setattr(e, 'username', pub), save=False)
        self.update(lambda e: setattr(e, 'password', key))

    def do_ngena(self, arg):
        'ngena LABEL SIZE # generate new alphanumeric note'
        a = arg.split()
        p = filter_urandom(to_int(a[1]), alnum) if len(a) == 2 else None
        if not p:
            print(None)
            return
        n = notes(self.entry)
        n[a[0]] = p.decode()
        self.update(lambda e: setattr(e, 'notes', notes_str(n)))

    def complete_ngena(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_ngend(self, arg):
        'ngend LABEL SIZE # generate new digit note'
        a = arg.split()
        p = filter_urandom(to_int(a[1]), decimal) if len(a) == 2 else None
        if not p:
            print(None)
            return
        n = notes(self.entry)
        n[a[0]] = p.decode()
        self.update(lambda e: setattr(e, 'notes', notes_str(n)))

    def complete_ngend(self, text, line, begin, end):
        return note_labels(self.entry, text)

    def do_rm(self, arg):
        'rm ENTRY... # move entries to recycle bin'
        for e in entries(self.kp, arg.split(), required=False):
            self.kp.trash_entry(e)
        self.save()

    def complete_rm(self, text, line, begin, end):
        return titles(self.kp, text)

    def do_restore(self, arg):
        'restore [ENTRY]... # restore entries from recycle bin'
        e = entries(self.kp, arg.split(), required=False)
        if e:
            self.kp.move_entry(e, self.kp.root_group)
            self.save()
        else:
            print('\n'.join(titles(self.kp, recycled=True)))

    def complete_restore(self, text, line, begin, end):
        return titles(self.kp, text, recycled=True)

    def do_cp(self, arg):
        'cp FILE ENTRY... # copy entries to db file'
        a = arg.split() or ['']
        e = entries(self.kp, a[1:])
        export(a[0], e)

    def complete_cp(self, text, line, begin, end):
        args = line.split()
        if len(args) <= 1:
            return [f for f in listdir('.')]
        elif len(args) == 2 and not line[-1:].isspace():
            p, n = path.split(path.expanduser(args[1]))
            return [f for f in listdir(p or '.') if f.startswith(n)]
        else:
            return titles(self.kp, text)

    def do_mv(self, arg):
        'mv FILE ENTRY... # copy entries to db file, then move to recycle bin'
        args = arg.split() or ['']
        e = entries(self.kp, args[1:])
        if export(args[0], e):
            for entry in e:
                self.kp.trash_entry(entry)
            self.save()

    def complete_mv(self, text, line, begin, end):
        return self.complete_cp(text, line, begin, end)

    def do_dedup(self, arg):
        'dedup # number duplicate titles'
        c = Counter(x.title for x in self.kp.entries)
        d = [t for t, x in c.items() if x > 1]
        for t in d:
            dedup(self.kp, t)
        self.save()

    def do_passwd(self, arg):
        'passwd # change db password'
        p = getpass()
        if p != getpass():
            print(None)
            return
        self.kp.password = p
        self.save()

    def update(self, f, save=True):
        update(self.entry, f)
        if save:
            self.save()

    def save(self):
        if self.mtime < stat(self.kp.filename).st_mtime:
            raise FileExistsError()
        self.kp.save()
        self.mtime = stat(self.kp.filename).st_mtime


def prompt(entry=None):
    p = '\n> '
    if not entry:
        return p
    t = entry.title
    if entry.is_a_history_entry:
        t = parent_entry(entry).title + ' ' + to_time_str(entry.mtime)
    p = '\n\033[34m' + t + '\033[0m' + p
    return p


def contains(e, arg):
    s = arg.lower()
    return (
        s in e.title.lower()
        or s in (e.url or '').lower()
        or s in (e.username or '').lower()
        or s in ' '.join(note_labels(e)).lower()
        or s in ' '.join(attr_labels(e)).lower()
    )


def fields(entry):
    return [
        ('Group', '/'.join(p or '' for p in entry.group.path)),
        ('Title', entry.title),
        ('URL', entry.url),
        ('Username', entry.username),
        ('Password', str(len(entry.password)) if entry.password else ''),
        ('OTP', str(len(pyotp.parse_uri(entry.otp).secret)) if entry.otp else ''),
        ('Notes', ', '.join(note_labels(entry))),
        ('Attributes', ', '.join(attr_labels(entry))),
        ('Modified', to_time_str(entry.mtime)),
        ('History', str(len(entry.history)) if entry.history else ''),
    ] if entry else []


def history(entry):
    e = parent_entry(entry)
    if not e:
        return []
    cl = []
    hl = getattr(e, 'history', [])
    while hl:
        h = hl.pop()
        cl.append((to_time_str(h.mtime), ', '.join(changes(e, h))))
        e = h
    return cl


def changes(new, old):
    res = []
    if not new or not old:
        return res
    if new.title != old.title:
        res.append('Title')
    if new.url != old.url:
        res.append('URL')
    if new.username != old.username:
        res.append('Username')
    if new.password != old.password:
        res.append('Password')
    if new.otp != old.otp:
        res.append('OTP')
    if notes(new) != notes(old):
        res.append('Notes')
    if new.custom_properties != old.custom_properties:
        res.append('Attributes')
    return res


def field(entry, field):
    return getattr(entry, field, None)


def notes(entry):
    return dict(
        tuple(s.strip() for s in x.split(':', maxsplit=1))
        for x in entry.notes.splitlines() if ':' in x
    ) if entry and entry.notes else {}


def notes_str(d):
    return '\n'.join(': '.join(x) for x in d.items())


def note_labels(entry, prefix=''):
    return [x for x, _ in notes(entry).items() if x.startswith(prefix)]


def note(entry, label):
    n = notes(entry)
    return n[label] if label in n else None


def attr_labels(entry, prefix=''):
    return [
        x for x in entry.custom_properties.keys() if x.startswith(prefix)
    ] if entry else []


def attr(entry, label):
    return entry.custom_properties[label] if entry and label in entry.custom_properties else None


def entries(kp, titles, required=True):
    res = [e for e in kp.entries if e.title in titles]
    return res if not required or len(titles) == len(res) else None


def titles(kp, prefix='', recycled=False):
    return [
        x.title for x in kp.entries
        if x.title.startswith(prefix) and recycled == in_recycle_bin(kp, x)
    ]


def update(entry, f):
    if not entry or entry.is_a_history_entry:
        print(None)
        return
    entry.save_history()
    f(entry)
    entry.mtime = datetime.now()


def dedup(kp, title):
    d = sorted(kp.find_entries(title=title), reverse=True, key=lambda x: x.mtime)
    if len(d) < 2:
        return
    d.pop(0)
    for entry in d:
        t = number(kp, entry.title)
        update(entry, lambda e: setattr(e, 'title', t))


def number(kp, title):
    for i in range(len(kp.entries)):
        t = title + str(i)
        if not kp.find_entries(title=t, first=True):
            return t
    return None


def parent_entry(entry):
    if not entry:
        return None
    if not entry.is_a_history_entry:
        return entry
    return pykeepass.entry.Entry(element=entry._element.getparent().getparent(), kp=entry._kp)


def clone(kp, entry, history=True):
    e = deepcopy(entry._element)
    h = e.find('History') if not history else None
    if h is not None:
        e.remove(h)
    entry = pykeepass.entry.Entry(element=e, kp=kp)
    entry.uuid = uuid.uuid1()
    return entry


def export(filename, entries):
    if not entries:
        print(None)
        return False
    kp = open(filename)
    if not kp:
        return False
    kp.root_group.append([clone(kp, e, history=False) for e in entries])
    for e in entries:
        dedup(kp, e.title)
    kp.save()
    return True


def in_recycle_bin(kp, entry):
    b = kp.recyclebin_group
    if not b:
        return False
    uid = b.uuid
    g = entry.group
    while g and not g.is_root_group:
        if g.uuid == uid:
            return True
        g = g.parentgroup
    return False


def to_int(s):
    try:
        return int(s)
    except ValueError:
        return None


def to_time_str(d):
    return d.astimezone().strftime('%Y.%m.%d_%H.%M.%S')


# https://owasp.org/www-community/password-special-characters
def owasp(b):
    return alnum(b) or chr(b) in ('!"#$%&()*+,-./:<=>?@[]^_{|}' + "'" + "\\")


def alnum(b):
    c = chr(b)
    return ('0' <= c and c <= '9') or ('A' <= c and c <= 'Z') or ('a' <= c and c <= 'z')


def decimal(b):
    c = chr(b)
    return ('0' <= c and c <= '9')


def filter_urandom(size, cond, block_size=512):
    if not size or size <= 0:
        return None
    res = []
    while len(res) < size:
        for b in urandom(block_size):
            if cond(b):
                res.append(b)
    return bytes(res[:size])


def open(filename):
    db = path.expanduser(filename)
    if not path.exists(db):
        return pykeepass.create_database(db, password=getpass())
    try:
        return pykeepass.PyKeePass(db, password=getpass())
    except pykeepass.exceptions.CredentialsError:
        print('wrong password')
        return None


clip_cmd = 'xsel -ib'
paste_cmd = 'xsel -ob'
pipe_cmd = 'tee'
ssh_add_fmt = 'ssh-add -t {time} -'
ssh_gen_cmd = 'sshgen'
ssh_known_cmd = 'sshknown'
ssh_re = re.compile(r'(-*BEGIN[^\n]*.*\n-*END[^\n]*\n)([^\n]*)', re.DOTALL)
clip_seconds = 10


def stdin(cmd, s):
    if not isinstance(s, str):
        print(None)
        return
    subprocess.run(cmd.split(), input=s.encode())


def stdout(cmd):
    r = subprocess.run(cmd.split(), stdout=subprocess.PIPE)
    return r.stdout.decode() if r.returncode == 0 and r.stdout else None


def clip(s):
    stdin(clip_cmd, s)


def paste():
    s = stdout(paste_cmd)
    return s.rstrip('\r\n') if s else None


def temp_clip(s):
    clip(s)
    Timer(clip_seconds, lambda: paste() != s or clip('')).start()


def pipe(s):
    stdin(pipe_cmd, s)


def ssh_gen():
    r = stdout(ssh_gen_cmd)
    return ssh_re.match(r).group(1, 2) if r else (None, None)


def main(db):
    kp = open(db)
    if not kp:
        return
    while True:
        try:
            KeeCmd(kp).cmdloop()
            break
        except (KeyboardInterrupt, FileExistsError) as e:
            print(type(e).__name__)
            kp.read(password=kp.password, keyfile=kp.keyfile, transformed_key=kp.transformed_key)


if __name__ == '__main__':
    print('pykeepass ' + version('pykeepass'))
    print('pyotp ' + version('pyotp'))
    args = ArgumentParser()
    args.add_argument('--clip')
    args.add_argument('--clip-seconds',  type=int)
    args.add_argument('--paste')
    args.add_argument('--pipe')
    args.add_argument('--ssh-add')
    args.add_argument('--ssh-gen')
    args.add_argument('--ssh-known')
    args.add_argument('db')
    o = args.parse_args()
    clip_cmd = o.clip or clip_cmd
    clip_seconds = o.clip_seconds or clip_seconds
    paste_cmd = o.paste or paste_cmd
    pipe_cmd = o.pipe or pipe_cmd
    ssh_add_fmt = o.ssh_add or ssh_add_fmt
    ssh_gen_cmd = o.ssh_gen or ssh_gen_cmd
    ssh_known_cmd = o.ssh_known or ssh_known_cmd
    main(o.db)
