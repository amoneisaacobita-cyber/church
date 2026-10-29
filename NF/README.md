# Life Fountain Church

A responsive church website with sermons, short videos, audio livestreams, prayer requests, pastor and admin dashboards, announcements, daily Bible verses, church information, and a searchable King James Version Bible.

## Project structure

```text
life-fountain-church/
├── frontend/public/       # Website pages, styles, browser JavaScript, and Bible data
├── backend/
│   ├── server.js          # Node.js API, database, media, and streaming
│   ├── package.json       # Backend dependencies and tests
│   ├── Dockerfile         # Render container image, including FFmpeg
│   └── server.test.js
├── render.yaml            # Free Render web service configuration
└── start.bat              # Local Windows startup
```

## Deploy on Render

1. Push this repository to GitHub.
2. In Render, choose **New → Blueprint**, connect the repository, and deploy `render.yaml`.
3. Enter a strong, private value for `LFC_STUDIO_PASSWORD` when prompted. Never put passwords in source control or browser code.
4. After the first deployment, open the service logs and use the one-time administrator setup code to create the admin account.
5. Open the Render service URL. The frontend and API are served together from the same service.

The Blueprint uses Render's free web-service plan. Free services spin down after inactivity, can take about a minute to wake, and have an ephemeral filesystem. **The SQLite database, uploaded sermons/videos, wallpapers, and live recordings may be erased on spin-down, restart, or redeploy. Do not use this free setup for important church data or production livestreams.** Keep one instance because live-stream segments and SQLite are not designed for multiple instances. Render's free instance also has limited CPU and memory; large video uploads and conversions may be slow or fail. Free web-service availability, included hours, and bandwidth are subject to Render's current limits.

Set `LFC_STUDIO_PASSWORD` in the Render dashboard before the first deployment. The app binds to Render's `PORT` and uses HTTPS-aware secure cookies. Audio/video conversion requires FFmpeg, which is installed in the Docker image.

## Run locally

Install Node.js 22 or later and FFmpeg. On Windows, run `start.bat`, or from `backend/` run `npm install` and `npm start`. Open `http://127.0.0.1:8000`. Local development uses SQLite and stores its database and media in the repository's `data/` directory. Run backend tests from `backend/` with `npm test`.

## Features

- Admin-managed pastors and pastor-assigned prayer request responses.
- Audio livestreams with 500 ms audio segments, queued listener playback, and a saved WAV recording when the stream ends.
- Sermon and short-video publishing, title editing, playback counts, and optional full-image wallpapers.
- Audio uploads and resumable video uploads up to 20 GB; videos are converted to MP3 using FFmpeg.
- Discovery of complete audio files added to the media directory and its ordinary subfolders.
- Church profile and logo management, public and pastor-only announcements, custom daily verses, and the searchable KJV Bible.

The browser requires HTTPS for microphone access outside localhost. The free Render configuration does not provide permanent app storage. To preserve accounts and sermons, move to a paid Render service with a persistent disk or update the app to use an external database and object storage. The Bible text is provided locally by [`bible-kjv.json`](./frontend/public/bible-kjv.json) from the [Bible-kjv dataset](https://github.com/aruljohn/Bible-kjv); its MIT license and copyright notice are included in [`BIBLE-DATA-LICENSE.txt`](./frontend/BIBLE-DATA-LICENSE.txt).
