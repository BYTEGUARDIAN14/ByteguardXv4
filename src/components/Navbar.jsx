import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, Menu, X, Scan, FileText, LayoutDashboard, Settings, Puzzle } from 'lucide-react'

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false)
  const location = useLocation()

  const navigation = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Scan', href: '/scan', icon: Scan },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Plugins', href: '/plugins', icon: Puzzle },
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  const isActive = (path) => path === '/' ? location.pathname === '/' : location.pathname.startsWith(path)

  return (
    <nav className="sticky top-0 z-50 bg-desktop-panel border-b border-desktop-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-12">
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="p-1 bg-white/[0.04] rounded-desktop group-hover:bg-white/[0.06] transition-colors">
              <Shield className="h-4 w-4 text-primary-400" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-semibold text-text-primary tracking-tight">ByteGuardX</span>
              <span className="text-[9px] text-text-disabled -mt-0.5 font-medium tracking-wide">OFFLINE SECURITY SCANNER</span>
            </div>
          </Link>

          <div className="hidden md:flex items-center gap-0.5">
            {navigation.map(({ name, href, icon: Icon }) => (
              <Link key={name} to={href}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-desktop text-xs font-medium transition-colors ${isActive(href) ? 'bg-primary-500/10 text-primary-400' : 'text-text-muted hover:text-text-primary hover:bg-white/[0.03]'
                  }`}>
                <Icon className="h-3.5 w-3.5" />
                <span>{name}</span>
              </Link>
            ))}
          </div>

          <div className="hidden md:flex items-center">
            <span className="text-[10px] text-text-disabled bg-white/[0.03] px-1.5 py-0.5 rounded-desktop font-mono">v2.0.0</span>
          </div>

          <div className="md:hidden">
            <button onClick={() => setIsOpen(!isOpen)}
              className="p-1.5 rounded-desktop text-text-muted hover:text-text-primary hover:bg-white/[0.03] transition-colors">
              {isOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </div>

      {isOpen && (
        <div className="md:hidden border-t border-desktop-border bg-desktop-panel">
          <div className="px-3 py-2 space-y-0.5">
            {navigation.map(({ name, href, icon: Icon }) => (
              <Link key={name} to={href} onClick={() => setIsOpen(false)}
                className={`flex items-center gap-2 px-2.5 py-2 rounded-desktop text-xs font-medium transition-colors ${isActive(href) ? 'bg-primary-500/10 text-primary-400' : 'text-text-muted hover:text-text-primary hover:bg-white/[0.03]'
                  }`}>
                <Icon className="h-3.5 w-3.5" />
                <span>{name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </nav>
  )
}

export default Navbar
