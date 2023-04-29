import unittest
from unittest.mock import patch, call
import kdbx_cli
from kdbx_cli import KpCmd
import pykeepass
from pykeepass.exceptions import CredentialsError
import tempfile
import os
import re
from time import sleep

__import__('sys').modules['unittest.util']._MAX_LENGTH = 999999999
mock_pw = 'mock pw'
mock_clip = ['mock', 'clip']
mock_paste = ['mock', 'paste']
kdbx_cli.clip_cmd = ' '.join(mock_clip)
kdbx_cli.paste_cmd = ' '.join(mock_paste)
kdbx_cli.clip_seconds = 1


class test_kdbx_cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, 'test.kdbx')
        cls.kp = pykeepass.create_database(cls.db, password=mock_pw)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.db)

    def setUp(self):
        self.maxDiff = None

    def test_do_add(self):
        cmd = KpCmd(self.kp)
        title = 'test_do_add'
        cmd.do_add(title)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.title, title)
    
    def test_do_rename(self):
        cmd = KpCmd(self.kp)
        title = 'test_do_rename'
        cmd.do_add(f'{title}-previous')
        cmd.do_rename(title)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.title, title)

    def test_do_restore(self):
        cmd = KpCmd(self.kp)
        title = 'test_do_restore'
        e = cmd.ui.add_entry(title)
        cmd.ui.trash_entry(e)
        self.assertTrue(cmd.ui.in_recycle_bin(e))
        cmd.do_restore(title)
        self.assertFalse(cmd.ui.in_recycle_bin(e))

    def test_do_dedup(self):
        cmd = KpCmd(self.kp)
        title = 'test_dup'
        cmd.ui.add_entry(title)
        cmd.ui.add_entry(title)
        cmd.ui.save()
        before = self.open_kp().find_entries(title=title)
        self.assertEqual([e.title for e in before], [title, title])
        cmd.do_dedup()
        after = [e for e in self.open_kp().entries if e.title.startswith(title)]
        self.assertEqual([e.title for e in after], [title, f'{title}0'])

    @patch('builtins.print')
    def test_do_find(self, mock_print):
        cmd = KpCmd(self.kp)
        title = 'test_find'
        keyword = f'{title}_keyword'
        cmd.ui.add_entry(keyword)
        e = cmd.ui.add_entry(f'{title}_url')
        e.url = keyword
        e = cmd.ui.add_entry(f'{title}_username')
        e.username = keyword
        e = cmd.ui.add_entry(f'{title}_notes')
        e.notes = f'{keyword}: test note'
        e = cmd.ui.add_entry(f'{title}_attr')
        e.set_custom_property(keyword, 'test attr')
        cmd.do_find(keyword)
        self.assertEqual(mock_print.mock_calls, [
            call(keyword),
            call(f'{title}_url'),
            call(f'{title}_username'),
            call(f'{title}_notes'),
            call(f'{title}_attr'),
        ])

    @patch('builtins.print')
    def test_do_dig(self, mock_print):
        cmd = KpCmd(self.kp)
        title = 'test_dig'
        keyword = f'{title}_keyword'
        e = cmd.ui.add_entry(keyword)
        cmd.ui.trash_entry(e)
        e = cmd.ui.add_entry(f'{title}_url')
        e.url = keyword
        cmd.ui.trash_entry(e)
        e = cmd.ui.add_entry(f'{title}_username')
        e.username = keyword
        cmd.ui.trash_entry(e)
        e = cmd.ui.add_entry(f'{title}_notes')
        e.notes = f'{keyword}: test note'
        cmd.ui.trash_entry(e)
        e = cmd.ui.add_entry(f'{title}_attr')
        e.set_custom_property(keyword, 'test attr')
        cmd.ui.trash_entry(e)
        cmd.do_dig(keyword)
        self.assertEqual(mock_print.mock_calls, [
            call(keyword),
            call(f'{title}_url'),
            call(f'{title}_username'),
            call(f'{title}_notes'),
            call(f'{title}_attr'),
        ])

    @patch('kdbx_cli.subprocess.run')
    def test_do_p(self, mock_run):
        pw = 'test_do_p pw'
        cmd = KpCmd(self.kp)
        title = 'test_do_p'
        cmd.do_add(title)
        cmd.ui.entry().password = pw
        cmd.do_p()
        self.assertEqual(mock_run.mock_calls, [call(mock_clip, input=pw.encode())])
        mock_run.mock_calls = []
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = pw.encode()
        sleep(2)
        self.assertEqual(mock_run.mock_calls, [
            call(mock_paste, stdout=-1),
            call(['mock', 'clip'], input=''.encode())
        ])

    @patch('builtins.print')
    def test_do_pd(self, mock_print):
        pw = 'test_do_pd pw'
        cmd = KpCmd(self.kp)
        title = 'test_do_pd'
        cmd.do_add(title)
        cmd.ui.entry().password = pw
        cmd.do_pd()
        self.assertEqual(mock_print.mock_calls, [call(pw)])

    def test_do_pgen(self):
        cmd = KpCmd(self.kp)
        title = 'test_do_pgen'
        cmd.do_add(title)
        cmd.do_pgen(10)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(len(e.password), 10)

    @patch('kdbx_cli.subprocess.run')
    def test_do_ppaste(self, mock_run):
        pw = 'test_do_ppaste pw'
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = pw.encode()
        cmd = KpCmd(self.kp)
        title = 'test_do_ppaste'
        cmd.do_add(title)
        mock_run.mock_calls = []
        cmd.do_ppaste()
        self.assertEqual(mock_run.mock_calls, [call(mock_paste, stdout=-1)])
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.password, pw)

    @patch('kdbx_cli.getpass')
    def test_do_pput(self, mock_getpass):
        pw = 'test_do_pput pw'
        mock_getpass.return_value = pw
        cmd = KpCmd(self.kp)
        title = 'test_do_pput'
        cmd.do_add(title)
        cmd.do_pput()
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.password, pw)

    @patch('builtins.print')
    def test_do_ud(self, mock_print):
        pw = 'test_do_ud pw'
        cmd = KpCmd(self.kp)
        title = 'test_do_ud'
        cmd.do_add(title)
        cmd.ui.entry().username = pw
        cmd.do_ud()
        self.assertEqual(mock_print.mock_calls, [call(pw)])

    @patch('kdbx_cli.getpass')
    def test_do_uput(self, mock_getpass):
        pw = 'test_do_uput pw'
        mock_getpass.return_value = pw
        cmd = KpCmd(self.kp)
        title = 'test_do_uput'
        cmd.do_add(title)
        cmd.do_uput()
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.username, pw)

    @patch('builtins.print')
    def test_do_ld(self, mock_print):
        pw = 'test_do_ld pw'
        cmd = KpCmd(self.kp)
        title = 'test_do_ld'
        cmd.do_add(title)
        cmd.ui.entry().url = pw
        cmd.do_ld()
        self.assertEqual(mock_print.mock_calls, [call(pw)])

    @patch('kdbx_cli.getpass')
    def test_do_lput(self, mock_getpass):
        pw = 'test_do_lput pw'
        mock_getpass.return_value = pw
        cmd = KpCmd(self.kp)
        title = 'test_do_lput'
        cmd.do_add(title)
        cmd.do_lput()
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.url, pw)

    @patch('builtins.print')
    def test_do_ad(self, mock_print):
        title = 'test_do_ad'
        pw = f'{title}_pw'
        label = f'{title}_label'
        cmd = KpCmd(self.kp)
        cmd.do_add(title)
        cmd.ui.entry().set_custom_property(label, pw)
        cmd.do_ad(label)
        self.assertEqual(mock_print.mock_calls, [call(pw)])

    @patch('kdbx_cli.getpass')
    def test_do_aput(self, mock_getpass):
        title = 'test_do_aput'
        pw = f'{title}_pw'
        label = f'{title}_label'
        mock_getpass.return_value = pw
        cmd = KpCmd(self.kp)
        cmd.do_add(title)
        cmd.do_aput(label)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.custom_properties[label], pw)

    @patch('builtins.print')
    def test_do_nd(self, mock_print):
        title = 'test_do_nd'
        pw = f'{title}_pw'
        label = f'{title}_label'
        cmd = KpCmd(self.kp)
        cmd.do_add(title)
        cmd.ui.entry().notes = f'{label}: {pw}'
        cmd.do_nd(label)
        self.assertEqual(mock_print.mock_calls, [call(pw)])

    @patch('kdbx_cli.getpass')
    def test_do_nput(self, mock_getpass):
        title = 'test_do_nput'
        pw = f'{title}_pw'
        label = f'{title}_label'
        mock_getpass.return_value = pw
        cmd = KpCmd(self.kp)
        cmd.do_add(title)
        cmd.do_nput(label)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.notes, f'{label}: {pw}')

    @patch('kdbx_cli.getpass')
    def test_do_cp(self, mock_getpass):
        title = 'test_do_cp'
        pw = f'{title}_pw'
        mock_getpass.return_value = pw
        db = self.create_kp(title, pw)
        cmd = KpCmd(self.kp)
        entry = cmd.ui.add_entry(title)
        cmd.do_cp(f'{db} {title}')
        res = self.open_kp(db, pw).entries
        self.assertEqual([e.title for e in res], [title])
        self.assertFalse(cmd.ui.in_recycle_bin(entry))

    @patch('kdbx_cli.getpass')
    def test_do_mv(self, mock_getpass):
        title = 'test_do_mv'
        pw = f'{title}_pw'
        mock_getpass.return_value = pw
        db = self.create_kp(title, pw)
        cmd = KpCmd(self.kp)
        entry = cmd.ui.add_entry(title)
        cmd.do_mv(f'{db} {title}')
        res = self.open_kp(db, pw).entries
        self.assertEqual([e.title for e in res], [title])
        self.assertTrue(cmd.ui.in_recycle_bin(entry))

    @patch('kdbx_cli.getpass')
    def test_do_passwd(self, mock_getpass):
        title = 'test_do_passwd'
        pw = f'{title}_pw'
        mock_getpass.return_value = pw
        db = self.create_kp(title, mock_pw)
        kp = self.open_kp(db, mock_pw)
        cmd = KpCmd(kp)
        entry = cmd.ui.add_entry(title)
        cmd.do_passwd()
        self.assertRaises(CredentialsError, lambda: self.open_kp(db, mock_pw))
        res = self.open_kp(db, pw).entries
        self.assertEqual([e.title for e in res], [title])

    @patch('builtins.print')
    def test_do_history(self, mock_print):
        cmd = KpCmd(self.kp)
        title = 'test_do_history'
        cmd.do_add(title)
        cmd.do_pgend('10')
        cmd.do_agenc('attr 10')
        cmd.do_history()
        res = mock_print.call_args.args[0]
        p = re.compile(r'^.*: (.*)\n.*: (.*)$')
        self.assertEqual(p.match(res).group(1,2), ('Attributes', 'Password'))

    def open_kp(self, db=None, pw=mock_pw):
        return pykeepass.PyKeePass(db if db else self.db, password=pw)

    def create_kp(self, name, pw):
        path = os.path.join(self.tmp, f'{name}.kdbx')
        pykeepass.create_database(path, password=pw)
        return path
