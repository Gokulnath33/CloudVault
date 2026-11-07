/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/**/*.js"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
        },
        office: {
          word: '#2b579a',
          ppt: '#d24726',
          excel: '#217346',
          pdf: '#d32f2f'
        }
      }
    },
  },
  safelist: [
    {
      pattern: /(bg|text|border)-(pink|blue|orange|emerald|rose|purple|cyan|amber|slate|brand|indigo)-(400|500|600)/,
    },
    {
      pattern: /(bg|border)-(pink|blue|orange|emerald|rose|purple|cyan|amber|slate|brand|indigo)-500\/(10|20|25|30)/,
    }
  ],
  plugins: [],
}
