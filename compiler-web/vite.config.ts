import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'https://compiler.divine.video',
      },
    },
    setupFiles: ['./vitest.setup.ts'],
  },
})
