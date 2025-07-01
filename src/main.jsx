import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#18181b',
            color: '#fafafa',
            border: '1px solid #3f3f46',
          },
          success: {
            iconTheme: {
              primary: '#0ea5e9',
              secondary: '#fafafa',
            },
          },
          error: {
            iconTheme: {
              primary: '#dc2626',
              secondary: '#fafafa',
            },
          },
        }}
      />
    </BrowserRouter>
  </React.StrictMode>,
)
