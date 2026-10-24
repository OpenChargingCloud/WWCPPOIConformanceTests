import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment:  'node',
        include:      [ 'test/**/*.test.ts' ],
        // ML-DSA verifications and the replay of both epochs in pure JavaScript take their time, the more so on the
        // Windows runners of GitHub.
        testTimeout:  120_000,
    },
});
