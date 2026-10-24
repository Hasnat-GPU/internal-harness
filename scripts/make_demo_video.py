"""Record the unchanged HTML demo. Run: python scripts/make_demo_video.py.

Dependencies: pip install playwright edge-tts; playwright install chromium;
ffmpeg and ffprobe on PATH (or a Windows WinGet Gyan.FFmpeg installation).
This records the frontend's simulations; it does not exercise backend weights.
The supplied UI uses Version 81's Restore This button, not a snap_v81 select.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import edge_tts
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "UI_UX_Frontend.html"
WORK = ROOT / "artifacts" / "demo_video"
OUTPUT = ROOT / "harness2_demo_60s.mp4"
SLOTS = [12, 12, 14, 12, 10]
TEXTS = [
    "Today’s AI agents either forget everything or bloat their context windows. This is the Harness Squared Companion—a visual control center for a private, self-improving local AI brain that learns in real weights while using zero percent CPU when idle.",
    "Designed for complete clarity, anyone can navigate the architecture with zero technical jargon. Using the Guided Story Player, you can watch a new rule pass through the security gates and update local fast-weight memory in under 110 milliseconds.",
    "In the live sandbox, you can teach the brain directly. Before any memory is saved, a four-layer security border checkpoint automatically scrubs leaked API keys and blocks prompt injections—so secrets are never baked into your model weights.",
    "And with a single click, the interface transforms from a plain-English guide into a full engineering flight deck—exposing the exact safetensors files, SQLite schemas, and cross-entropy surprise thresholds under the hood.",
    "With built-in cryptographic weight rollbacks in the Time Machine and a tiny 1.2-gigabyte edge footprint, you own your agent’s institutional memory locally. This is Harness Squared.",
]


def binary(name):
    local = WORK / 'tools' / f'{name}.exe'
    if local.exists():
        return str(local)
    found = shutil.which(name)
    if found:
        return found
    base = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/WinGet/Packages"
    matches = list(base.glob(f"Gyan.FFmpeg*/**/{name}.exe"))
    if matches:
        return str(matches[0])
    raise RuntimeError(f"Install {name} and add it to PATH")


def run(args):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, text=True)


def probe(path):
    return json.loads(run([binary("ffprobe"), "-v", "error", "-show_format", "-show_streams", "-of", "json", path]).stdout)


def duration(path):
    return float(probe(path)["format"]["duration"])


async def narration():
    captions, segments = [], []
    start = 0
    for n, (text, slot) in enumerate(zip(TEXTS, SLOTS), 1):
        raw = WORK / f"seg{n}_original.mp3"
        meta = WORK / f"seg{n}_words.json"
        if not raw.exists() or not meta.exists():
            words = []
            for attempt in range(3):
                try:
                    words = []
                    with raw.open("wb") as f:
                        async for chunk in edge_tts.Communicate(text, "en-US-AndrewNeural", rate="+5%", boundary="WordBoundary").stream():
                            if chunk["type"] == "audio":
                                f.write(chunk["data"])
                            elif chunk["type"] == "WordBoundary":
                                words.append({k: chunk[k] for k in ("offset", "duration", "text")})
                    meta.write_text(json.dumps(words), encoding="utf-8")
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(2)
        words = json.loads(meta.read_text(encoding="utf-8"))
        original = duration(raw)
        speed = max(1.0, original / (slot - .18))
        out = WORK / f"seg{n}.mp3"
        run([binary("ffmpeg"), "-y", "-v", "error", "-threads", "4", "-i", raw,
             "-af", f"atempo={speed:.8f},apad,atrim=duration={slot}", "-ar", "48000", "-c:a", "libmp3lame", "-b:a", "192k", out])
        for i in range(0, len(words), 9):
            group = words[i:i + 9]
            captions.append({"at": start + group[0]["offset"] / 1e7 / speed,
                             "text": " ".join(w["text"] for w in group), "chapter": n})
        segments.append({"number": n, "start": start, "slot": slot, "raw_duration": original, "tempo": speed})
        start += slot
        print(f"Narration {n}: {original:.2f}s -> {slot}s", flush=True)
    args = [binary("ffmpeg"), "-y", "-v", "error", "-filter_complex_threads", "4"]
    for n in range(1, 6):
        args += ["-i", WORK / f"seg{n}.mp3"]
    filters = []
    for n, start in enumerate([0, 12, 24, 38, 50]):
        filters.append(f"[{n}:a]atrim=duration={SLOTS[n]},asetpts=PTS-STARTPTS,adelay={start * 1000}:all=1[a{n}]")
    filters.append("[a0][a1][a2][a3][a4]amix=inputs=5:normalize=0,alimiter=limit=0.95,apad,atrim=duration=60[out]")
    run(args + ["-filter_complex", ";".join(filters), "-map", "[out]", WORK / "narration.wav"])
    return captions, segments


OVERLAY = r"""() => {
 const style=document.createElement('style');
 style.textContent=`
 * {cursor:none!important}
 #demo-pointer {position:fixed;left:0;top:0;width:22px;height:22px;margin:-11px;
 background:#fbbf24;border:3px solid white;border-radius:50%;z-index:2147483647;
 box-shadow:0 0 0 3px #2563eb,0 4px 20px #0008;pointer-events:none;
 transition:transform 0.45s cubic-bezier(0.22, 1, 0.36, 1)}
 .demo-ripple {position:fixed;width:24px;height:24px;margin:-12px;border:3px solid #2563eb;
 border-radius:50%;z-index:2147483646;pointer-events:none;animation:demo-ripple .7s ease-out forwards}
 @keyframes demo-ripple {to{transform:scale(3.5);opacity:0}}
 #demo-caption {position:fixed;bottom:28px;left:50%;transform:translateX(-50%);width:1120px;
 padding:17px 28px;background:rgba(10,18,34,.95);color:white;border:1px solid #64748b;
 border-radius:18px;box-shadow:0 10px 45px #0004;z-index:2147483645;pointer-events:none;
 font:500 26px/1.4 'Segoe UI',sans-serif;text-align:center;min-height:99px}
 #demo-chapter {font:600 12px/1.5 'Segoe UI',sans-serif;letter-spacing:2px;color:#93c5fd;margin-bottom:5px}
 .demo-focus {outline:3px solid #3b82f6!important;outline-offset:5px}
 `;
 document.head.appendChild(style);
 const pointer=document.createElement('div');pointer.id='demo-pointer';document.body.appendChild(pointer);
 const caption=document.createElement('div');caption.id='demo-caption';
 caption.innerHTML='<div id="demo-chapter">HARNESS² / LOCAL INTELLIGENCE</div><div id="demo-subtitle"></div>';
 document.body.appendChild(caption);
 window.demoMove=(x,y)=>pointer.style.transform=`translate(${x}px,${y}px)`;
 window.demoClick=(x,y)=>{let r=document.createElement('div');r.className='demo-ripple';
 r.style.left=x+'px';r.style.top=y+'px';document.body.appendChild(r);setTimeout(()=>r.remove(),750)};
 window.demoMove(960,300);
}"""


async def record(captions):
    checks = {}
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--renderer-process-limit=2"])
        context = await browser.new_context(viewport={"width": 1920, "height": 1080},
            device_scale_factor=1, record_video_dir=str(WORK / "recordings"),
            record_video_size={"width": 1920, "height": 1080}, color_scheme="light")
        page = await context.new_page()
        await page.goto(SOURCE.as_uri(), wait_until="networkidle")
        await page.wait_for_function("getComputedStyle(document.querySelector('header')).position === 'sticky'")
        await page.evaluate("document.fonts.ready")
        await page.evaluate(OVERLAY)
        checks["six_rooms"] = await page.locator('[id^="station-M"]').count() == 6
        checks["initial_light_simple"] = await page.evaluate("!document.documentElement.classList.contains('dark') && !isTechView")
        video = page.video

        async def focus(selector, click=False, scroll=True):
            loc = page.locator(selector).first
            if scroll:
                await loc.evaluate("e => {const r=e.getBoundingClientRect(); if(r.top<150 || r.bottom>880) window.scrollBy({top:r.top-280,behavior:'smooth'});}")
                await asyncio.sleep(.65)
            box = await loc.bounding_box()
            x, y = box["x"] + box["width"] / 2, box["y"] + min(box["height"] / 2, 80)
            await page.evaluate("([x,y])=>demoMove(x,y)", [x,y])
            await page.mouse.move(x,y)
            await asyncio.sleep(.48)
            await page.evaluate("() => document.querySelectorAll('.demo-focus').forEach(e=>e.classList.remove('demo-focus'))")
            await loc.evaluate("e=>e.classList.add('demo-focus')")
            if click:
                await page.evaluate("([x,y])=>demoClick(x,y)", [x,y])
                await loc.click(position={"x": box["width"] / 2, "y": min(box["height"] / 2,80)})

        start = time.monotonic()
        async def at(t):
            await asyncio.sleep(max(0, start + t - time.monotonic()))

        async def subtitles():
            names = ["01 / YOUR PRIVATE AI BRAIN", "02 / GUIDED STORY PLAYER", "03 / SECURITY IN ACTION", "04 / ENGINEERING FLIGHT DECK", "05 / YOUR MEMORY, LOCALLY"]
            for cap in captions:
                await at(cap["at"])
                await page.evaluate("c=>{document.getElementById('demo-subtitle').textContent=c.text;document.getElementById('demo-chapter').textContent=c.title}", {"text": cap["text"], "title": names[cap["chapter"]-1]})

        caption_task = asyncio.create_task(subtitles())
        await focus('#station-TIER-1')
        await at(3); await focus('#station-SEC-GATE')
        await at(6); await focus('div.border-2:has(#station-M1)')
        await at(9); await focus('#station-TIER-3')
        await at(12); await focus('#story-btn-story_learn', True)
        await at(15); await focus('#btn-next-step', True)
        await at(18); await focus('#btn-next-step', True)
        await at(21); await focus('#btn-next-step', True)
        checks['story_completed'] = await page.evaluate("currentStoryKey==='story_learn' && currentStepIndex===3")
        await at(24); await focus('#sandbox-rule-input')
        await at(26); await focus('button:has-text("Test Password Leak")', True)
        await at(28); await focus('button[onclick="submitCustomRule()"]', True)
        await at(30); await focus('#sandbox-feedback')
        checks['redacted_feedback'] = '<REDACTED_SECRET>' in await page.locator('#sandbox-feedback').inner_text()
        checks['scrubbed_memory'] = await page.evaluate("rulesDatabase[0].text.includes('<REDACTED_SECRET>') && !rulesDatabase[0].text.includes('sk-live-')")
        await page.screenshot(path=str(WORK / 'sandbox.png'))
        await at(34); await focus('#station-SEC-01')
        await at(38); await focus('#station-M3', True)
        await at(41); await focus('#tech-toggle-btn', True, False)
        await at(43); await focus('#insp-tech-drawer')
        checks['technical_drawer'] = await page.locator('#insp-tech-drawer').is_visible() and await page.evaluate('isTechView')
        await page.screenshot(path=str(WORK / 'technical.png'))
        await at(46); await focus('#station-M4', True)
        await at(48); await focus('#station-M2', True)
        await at(50); await focus('#snapshot-list')
        await at(52); await focus('#snapshot-list > div:has-text("Version 81") button', True)
        checks['version81_restored'] = await page.evaluate("brainSnapshots.find(s=>s.active).ver.startsWith('Version 81')")
        await at(54); await focus('#theme-toggle-btn', True, False)
        checks['final_dark'] = await page.evaluate("document.documentElement.classList.contains('dark')")
        await at(55.2)
        await page.evaluate("window.scrollTo({top:0,behavior:'smooth'})")
        await page.evaluate("demoMove(1640,320)")
        await at(57)
        await page.screenshot(path=str(WORK / 'hero.png'))
        await caption_task
        await at(60.4)
        end_hold = time.monotonic() - start - 60
        await context.close()
        path = await video.path()
        await browser.close()
    assert all(checks.values()), checks
    return path, end_hold, checks


def verify_video(path=OUTPUT):
    info = probe(path)
    v = next(s for s in info['streams'] if s['codec_type']=='video')
    a = next(s for s in info['streams'] if s['codec_type']=='audio')
    assert (v['width'], v['height'], v['codec_name']) == (1920,1080,'h264')
    assert a['codec_name'] == 'aac'
    assert abs(float(info['format']['duration']) - 60) < .15
    assert float(a['duration']) >= 59.9
    return info


async def main():
    WORK.mkdir(parents=True, exist_ok=True)
    original_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    captions, segments = await narration()
    path, end_hold, checks = await record(captions)
    trim = max(0, duration(path) - 60 - end_hold)
    print('Encoding final 1080p video...', flush=True)
    run([binary('ffmpeg'), '-y', '-v', 'error', '-threads', '4', '-ss', f'{trim:.6f}', '-i', path,
         '-i', WORK/'narration.wav', '-map', '0:v:0', '-map', '1:a:0', '-t', '60',
         '-vf', 'fps=30,tpad=stop_mode=clone:stop_duration=1', '-c:v', 'libx264', '-threads', '4',
         '-preset', 'fast', '-crf', '18', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '192k',
         '-movflags', '+faststart', OUTPUT])
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == original_hash, 'Frontend changed!'
    report = {'source_sha256': original_hash, 'segments': segments, 'checks': checks, 'ffprobe': verify_video()}
    (WORK/'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'Verified: {OUTPUT}', flush=True)


if __name__ == '__main__':
    asyncio.run(main())
