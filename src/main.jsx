import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import './index.css'

// Error handling for root element
const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Root element not found. Make sure you have a div with id="root" in your HTML.')
}

// Create root with error handling
const root = ReactDOM.createRoot(rootElement)

// Render app with error boundary
root.render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)

// Global error handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', {
    reason: event.reason?.message || event.reason,
    stack: event.reason?.stack
  })
  event.preventDefault()
})

// Global error handler for uncaught errors
window.addEventListener('error', (event) => {
  console.error('Uncaught error:', {
    message: event.error?.message || event.message,
    filename: event.filename,
    lineno: event.lineno,
    colno: event.colno,
    stack: event.error?.stack
  })
})
