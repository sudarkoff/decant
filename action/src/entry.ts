import { defaultDeps } from './deps';
import { error } from './gh-io';
import { run } from './main';

run(defaultDeps()).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    error(e instanceof Error ? e.message : String(e));
    process.exitCode = 1;
  },
);
