"""Artifact acceptance test; run after scripts/make_demo_video.py."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('demo_video', ROOT/'scripts/make_demo_video.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class DemoVideoTest(unittest.TestCase):
    def test_delivered_video_and_ui_actions(self):
        demo.verify_video()
        report = json.loads((demo.WORK/'verification.json').read_text(encoding='utf-8'))
        self.assertTrue(all(report['checks'].values()), report['checks'])
        self.assertEqual(report['source_sha256'], hashlib.sha256(demo.SOURCE.read_bytes()).hexdigest())
        self.assertEqual([s['start'] for s in report['segments']], [0,12,24,38,50])
        for n, slot in enumerate(demo.SLOTS, 1):
            self.assertAlmostEqual(demo.duration(demo.WORK/f'seg{n}.mp3'), slot, delta=.1)


if __name__ == '__main__':
    unittest.main()
