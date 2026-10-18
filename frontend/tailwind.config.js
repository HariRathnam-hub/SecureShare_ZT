/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0F1B2D',
        panel: '#172640',
        line: '#2A3C5A',
        fog: '#E6ECF5',
        mute: '#8FA1BC',
        signal: '#4CC9C0',
        danger: '#F07178',
      },
      fontFamily: { sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'] },
    },
  },
  plugins: [],
};
