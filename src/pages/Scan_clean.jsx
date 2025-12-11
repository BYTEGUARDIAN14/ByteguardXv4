import React, { useState } from 'react'
import { motion } from 'framer-motion'
import Sidebar from '../components/layout/Sidebar'
import Header from '../components/layout/Header'
import EnhancedScanInterface from '../components/EnhancedScanInterface'
import { slideUp } from '../utils/animations'

const Scan = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white">
      <Sidebar
        isCollapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      <Header
        onMenuToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        sidebarCollapsed={sidebarCollapsed}
      />

      <main className={`
        transition-all duration-300 pt-16
        ${sidebarCollapsed ? 'ml-20' : 'ml-72'}
      `}>
        <motion.div
          className="p-8"
          variants={slideUp}
          initial="hidden"
          animate="visible"
        >
          <EnhancedScanInterface />
        </motion.div>
      </main>
    </div>
  )
}

export default Scan
