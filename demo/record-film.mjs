#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { unlinkSync } from 'node:fs';
import process from 'node:process';
import puppeteer from 'puppeteer-core';

import { createDemoServer } from './serve-demo.mjs';
import {
  chromeArgs,
  closeServer,
  numberArg,
  parseArgs,
  requireExtension,
  waitForExit,
} from './export-utils.mjs';

const args = parseArgs(process.argv.slice(2));
const rate = numberArg(args, 'rate', 1, { min: 0.25, max: 4 });
const fps = numberArg(args, 'fps', 30, { min: 1, max: 60, integer: true });
const durationSeconds = numberArg(args, 'duration', 180, { min: 0.1, max: 600 });
const width = numberArg(args, 'width', 1920, { min: 320, max: 3840, integer: true });
const height = numberArg(args, 'height', 1080, { min: 180, max: 2160, integer: true });
const port = numberArg(args, 'port', 43132, { min: 1024, max: 65535, integer: true });
const crf = numberArg(args, 'crf', 17, { min: 0, max: 51, integer: true });
const output = requireExtension(args.out || 'lifeline-final.mp4', '.mp4', 'out');
const capturePath = requireExtension(args.capture || 'lifeline-capture.webm', '.webm', 'capture');
const audio = args.audio || 'lifeline-voiceover.mp3';
const presets = new Set(['ultrafast', 'superfast', 'veryfast', 'faster', 'fast', 'medium', 'slow', 'slower', 'veryslow']);
const preset = args.preset || 'slow';
if (!presets.has(preset)) throw new RangeError(`unsupported preset: ${preset}`);

let server;
let browser;
let recorder;
try {
  server = await createDemoServer({ port });
  browser = await puppeteer.launch({
    executablePath: process.env.CHROME || '/usr/bin/google-chrome',
    headless: true,
    args: chromeArgs(args),
    defaultViewport: { width, height, deviceScaleFactor: 1 },
  });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.waitForFunction(() => window.__lifelineReady === true, { timeout: 30_000 });
  recorder = await page.screencast({ path: capturePath, fps, quality: 18, speed: 1 / rate, ffmpegPath: 'ffmpeg' });
  await page.evaluate((captureRate) => window.LIFELINE_START_CAPTURE(captureRate), rate);
  const realDurationMs = Math.ceil(durationSeconds / rate * 1000) + 1_000;
  console.log(`recording ${durationSeconds}s timeline at ${rate}x for ${(realDurationMs / 1000).toFixed(1)}s real time`);
  await new Promise((resolve) => setTimeout(resolve, realDurationMs));
  await recorder.stop();
  recorder = undefined;
} catch (error) {
  if (!args.unsafeNoSandbox && String(error).toLowerCase().includes('sandbox')) {
    error.message += ' (only for a trusted local fixture, retry with --unsafeNoSandbox=true)';
  }
  throw error;
} finally {
  if (recorder) await recorder.stop().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  await closeServer(server);
}

const ffmpeg = spawn('ffmpeg', [
  '-y', '-i', capturePath, '-i', audio,
  '-map', '0:v:0', '-map', '1:a:0', '-shortest',
  '-c:v', 'libx264', '-preset', preset, '-crf', String(crf),
  '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
  '-c:a', 'aac', '-b:a', '192k', output,
], { stdio: ['ignore', 'inherit', 'inherit'] });
try {
  await waitForExit(ffmpeg, 'ffmpeg');
} catch (error) {
  if (!ffmpeg.killed) ffmpeg.kill('SIGTERM');
  throw error;
}
if (args.keepCapture !== 'true') {
  try { unlinkSync(capturePath); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}
console.log(`wrote ${output}`);
