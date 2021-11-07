import unittest
from unittest.mock import patch, call
import kdbx_cli
from kdbx_cli import KeeCmd
import pykeepass
import tempfile
import os
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
        cls.db = os.path.join(tempfile.mkdtemp(), 'test.kdbx')
        cls.kp = pykeepass.create_database(cls.db, password=mock_pw)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.db)

    def setUp(self):
        self.maxDiff = None

    def test_do_add(self):
        cmd = KeeCmd(self.kp)
        title = 'test_do_add'
        cmd.do_add(title)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.title, title)

    @patch('kdbx_cli.subprocess.run')
    def test_do_p(self, mock_run):
        pw = 'test_do_p pw'
        cmd = KeeCmd(self.kp)
        title = 'test_do_p'
        cmd.do_add(title)
        cmd.entry.password = pw
        cmd.do_p(None)
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
        cmd = KeeCmd(self.kp)
        title = 'test_do_pd'
        cmd.do_add(title)
        cmd.entry.password = pw
        cmd.do_pd(None)
        self.assertEqual(mock_print.mock_calls, [call(pw)])

    @patch('kdbx_cli.subprocess.run')
    def test_do_ppaste(self, mock_run):
        pw = 'test_do_ppaste pw'
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = pw.encode()
        cmd = KeeCmd(self.kp)
        title = 'test_do_ppaste'
        cmd.do_add(title)
        mock_run.mock_calls = []
        cmd.do_ppaste(None)
        self.assertEqual(mock_run.mock_calls, [call(mock_paste, stdout=-1)])
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.password, pw)

    @patch('kdbx_cli.getpass')
    def test_do_pput(self, mock_getpass):
        pw = 'test_do_pput pw'
        mock_getpass.return_value = pw
        cmd = KeeCmd(self.kp)
        title = 'test_do_pput'
        cmd.do_add(title)
        cmd.do_pput(None)
        e = self.open_kp().find_entries(title=title, first=True)
        self.assertEqual(e.password, pw)

    def open_kp(self):
        return pykeepass.PyKeePass(self.db, password=mock_pw)
