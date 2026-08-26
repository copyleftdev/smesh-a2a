import { once } from 'node:events';

export function parseArgs(argv) {
  return Object.fromEntries(argv.map((argument) => {
    if (!argument.startsWith('--')) throw new RangeError(`unexpected argument: ${argument}`);
    const [key, value = 'true'] = argument.slice(2).split('=', 2);
    if (!key) throw new RangeError('argument name cannot be empty');
    return [key, value];
  }));
}

export function numberArg(args, name, fallback, { min, max, integer = false } = {}) {
  const value = Number(args[name] ?? fallback);
  if (!Number.isFinite(value) || (integer && !Number.isInteger(value)) || value < min || value > max) {
    throw new RangeError(`${name} must be ${integer ? 'an integer' : 'a finite number'} from ${min} through ${max}`);
  }
  return value;
}

export function chromeArgs(args) {
  const values = ['--enable-unsafe-swiftshader', '--disable-dev-shm-usage'];
  if (args.unsafeNoSandbox === 'true') values.push('--no-sandbox');
  return values;
}

export async function closeServer(server) {
  if (!server?.listening) return;
  await new Promise((resolve) => server.close(resolve));
}

export function waitForExit(child, label) {
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${label} exited with ${code ?? signal ?? 'unknown status'}`));
    });
  });
}

export function guardWritable(stream) {
  const state = { error: null };
  stream.on('error', (error) => { state.error ??= error; });
  return state;
}

export async function writeChunk(stream, chunk, state) {
  if (state?.error) throw state.error;
  if (stream.destroyed || stream.writableEnded) throw new Error('ffmpeg input closed early');
  if (stream.write(chunk)) return;
  await once(stream, 'drain');
  if (state?.error) throw state.error;
}

export function requireExtension(path, extension, name) {
  if (typeof path !== 'string' || !path.toLowerCase().endsWith(extension)) {
    throw new RangeError(`${name} must end with ${extension}`);
  }
  return path;
}
