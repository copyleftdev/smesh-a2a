#!/usr/bin/env node
import { spawn } from 'node:child_process';
import process from 'node:process';
import puppeteer from 'puppeteer-core';

import { createDemoServer } from './serve-demo.mjs';
import {
  chromeArgs,
  closeServer,
  guardWritable,
  numberArg,
  parseArgs,
  requireExtension,
  waitForExit,
  writeChunk,
} from './export-utils.mjs';

const args = parseArgs(process.argv.slice(2));
const fps = numberArg(args, 'fps', 30, { min: 1, max: 60, integer: true });
const duration = numberArg(args, 'duration', 180, { min: 0.1, max: 600 });
const start = numberArg(args, 'start', 0, { min: 0, max: 600 });
const defaultFrames = Math.round(duration * fps);
const frames = numberArg(args, 'frames', defaultFrames, { min: 1, max: 36_000, integer: true });
const width = numberArg(args, 'width', 1920, { min: 320, max: 3840, integer: true });
const height = numberArg(args, 'height', 1080, { min: 180, max: 2160, integer: true });
const port = numberArg(args, 'port', 43131, { min: 1024, max: 65535, integer: true });
const crf = numberArg(args, 'crf', 17, { min: 0, max: 51, integer: true });
const output = requireExtension(args.out || 'lifeline-film.mp4', '.mp4', 'out');
const audio = args.audio || '';
const presets = new Set(['ultrafast', 'superfast', 'veryfast', 'faster', 'fast', 'medium', 'slow', 'slower', 'veryslow']);
const preset = args.preset || 'slow';
if (!presets.has(preset)) throw new RangeError(`unsupported preset: ${preset}`);

let server;
let browser;
let ffmpeg;
let ffmpegExit;
let ffmpegInput;
try {
  server = await createDemoServer({ port });
  browser = await puppeteer.launch({
    executablePath: process.env.CHROME || '/usr/bin/google-chrome',
    headless: true,
    args: chromeArgs(args),
    defaultViewport: { width, height, deviceScaleFactor: 1 },
  });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}/?frame=0`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.waitForFunction(() => window.__lifelineReady === true, { timeout: 30_000 });

  const ffmpegArgs = ['-y', '-f', 'image2pipe', '-framerate', String(fps), '-i', 'pipe:0'];
  if (audio) ffmpegArgs.push('-i', audio, '-map', '0:v:0', '-map', '1:a:0', '-shortest');
  ffmpegArgs.push('-c:v', 'libx264', '-preset', preset, '-crf', String(crf), '-pix_fmt', 'yuv420p', '-movflags', '+faststart');
  if (audio) ffmpegArgs.push('-c:a', 'aac', '-b:a', '192k');
  ffmpegArgs.push(output);
  ffmpeg = spawn('ffmpeg', ffmpegArgs, { stdio: ['pipe', 'inherit', 'inherit'] });
  ffmpegExit = waitForExit(ffmpeg, 'ffmpeg');
  ffmpegExit.catch(() => {});
  ffmpegInput = guardWritable(ffmpeg.stdin);

  for (let index = 0; index < frames; index += 1) {
    const absoluteFrame = Math.round(start * fps) + index;
    await page.evaluate(([frame, rate]) => window.LIFELINE_RENDER_FRAME(frame, rate), [absoluteFrame, fps]);
    const image = await page.screenshot({ type: 'jpeg', quality: 94, optimizeForSpeed: true });
    await writeChunk(ffmpeg.stdin, image, ffmpegInput);
    if (index % fps === 0) process.stdout.write(`\rframe ${index}/${frames}`);
  }
  ffmpeg.stdin.end();
  await ffmpegExit;
  if (ffmpegInput.error) throw ffmpegInput.error;
  console.log(`\nwrote ${output}`);
} catch (error) {
  if (ffmpeg && !ffmpeg.killed) {
    ffmpeg.stdin.destroy();
    ffmpeg.kill('SIGTERM');
  }
  if (ffmpegExit) await ffmpegExit.catch(() => {});
  if (!args.unsafeNoSandbox && String(error).toLowerCase().includes('sandbox')) {
    error.message += ' (only for a trusted local fixture, retry with --unsafeNoSandbox=true)';
  }
  throw error;
} finally {
  if (browser) await browser.close().catch(() => {});
  await closeServer(server);
}
