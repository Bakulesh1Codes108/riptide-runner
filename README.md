# Riptide Runner

A 3D jet-ski endless runner in the style of Subway Surfers and Temple Run. Ride from the rider's handlebar view (or a chase camera) through six worlds, with a checkpoint gate between each:

- **Glen Canyon** — Lake Powell, Utah: sandstone walls, the white "bathtub ring", mirror-calm water
- **Bali Coast** — Indonesia: palm beaches, huts, a volcano on the horizon
- **Phang Nga Bay** — Thailand: limestone karst towers and longtail boats
- **Dino Delta** — jungle river with sauropods and raptors
- **Planet Xeno** — glowing crystals and a giant planet in the sky
- **Dead Marsh** — a foggy bayou at night with zombies

Features: real-time water reflections, engine/jet-pump/water-slap sound, phone vibration, coins, ramps, magnet / shield / turbo power-ups, and a revive.

## Play

- **Android:** download [`dist/RiptideRunner.apk`](dist/RiptideRunner.apk) and install it (allow "Install unknown apps" when asked).
- **PC:** download [`dist/RiptideRunner-PC.html`](dist/RiptideRunner-PC.html) and open it in Chrome or Edge. Works offline.

### Controls

| Action | PC | Phone |
| --- | --- | --- |
| Change lane | ← → | Swipe left / right |
| Jump | ↑ or Space | Swipe up |
| Duck | ↓ | Swipe down |
| Pause | P or Esc | Pause button |

## Build from source

The game is a single HTML file (`game.html`) using [three.js](https://threejs.org) r149.

```bash
npm pack three@0.149.0 && tar xzf three-0.149.0.tgz   # provides package/build/three.min.js
python3 build.py local                                 # -> index.html (three.js inlined, offline)
python3 build_apk.py index.html RiptideRunner.apk signkey.pem
```

`build_apk.py` builds the Android app without the Android SDK: it assembles a small WebView launcher (`classes.dex`), the binary manifest, an icon resource, and signs the APK with APK Signature Scheme v2 (needs Python `cryptography` and `Pillow`). A signing key is generated on first run; keep it to publish updates.
