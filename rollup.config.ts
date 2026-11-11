import { nodeResolve } from '@rollup/plugin-node-resolve';
import { execSync } from 'child_process';
import { OutputBundle, OutputOptions } from 'rollup';
import typescript from '@rollup/plugin-typescript';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'src/index.ts',
  output: {
    dir: 'dist',
    format: 'esm',
    sourcemap: false
  },
  plugins: [
    commonjs(),
    nodeResolve({
      extensions: ['.ts', '.js']
    }),
    typescript({
      tsconfig: './tsconfig.json'
    }),
    {
      name: 'postbuild',
      writeBundle(_options: OutputOptions, bundle: OutputBundle): void {
        for (const filename in bundle) {
          const file = bundle[filename];
          if ('chunk' === file.type) {
            execSync(`./build.command ../dist/${filename}`, { cwd: 'quickjs-native' });
          }
        }
      }
    }
  ]
};
