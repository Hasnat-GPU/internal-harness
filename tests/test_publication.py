"""Public source-tree checks: python -m unittest discover -s tests -p test_publication.py."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PublicationTest(unittest.TestCase):
    def test_private_artifacts_are_ignored(self):
        paths = ['.env', '.env.production', 'module.pyc', '__pycache__/x.pyc',
                 '.venv/bin/python', 'venv/bin/python', 'node_modules/test/index.js',
                 'weights/backbone/tokenizer.json', 'weights/fast_state.safetensors',
                 'data/episodic_buffer.db', 'data/episodic_buffer.db-journal',
                 'tmp/recording.webm', 'seg1.mp3', 'artifacts/demo_video/seg1.mp3',
                 'harness2_demo_60s.mp4']
        result = subprocess.run(['git', 'check-ignore', '--no-index', '-z', '--stdin'],
                                input=('\0'.join(paths)+'\0').encode(), capture_output=True,
                                cwd=ROOT, check=True)
        self.assertEqual(set(result.stdout.decode().rstrip('\0').split('\0')), set(paths))

    def test_showcase_links_and_scope(self):
        readme = (ROOT/'README.md').read_text(encoding='utf-8')
        self.assertNotIn('<YOUR_GOOGLE_DRIVE_VIDEO_LINK>', readme)
        self.assertEqual(readme.count('https://drive.google.com/file/d/1u8OW0lUMhhxG1twcPHh2dPLS1x-La8N1/view?usp=sharing'), 2)
        self.assertIn('releases/download/v2.0.0/harness2_demo_60s.mp4', readme)
        self.assertIn('simulated behavior', readme)
        for name in ['Blueprint_Backend.html', 'UI_UX_Frontend.html', 'AGENTS.md', 'START_HERE_PROMPTS.txt']:
            self.assertTrue((ROOT/name).is_file())
            self.assertIn(name, readme)


if __name__ == '__main__':
    unittest.main()
