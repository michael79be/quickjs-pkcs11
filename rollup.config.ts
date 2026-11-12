import { nodeResolve } from '@rollup/plugin-node-resolve';
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
    })
  ]
};
