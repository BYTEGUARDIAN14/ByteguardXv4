import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import Sidebar from '../components/layout/Sidebar'
import Header from '../components/layout/Header'
import PluginMarketplace from '../components/PluginMarketplace'
import { slideUp } from '../utils/animations'

const PluginMarketplacePage = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [pluginData, setPluginData] = useState(null)

  useEffect(() => {
    fetchPluginData()
  }, [])

  const fetchPluginData = async () => {
    try {
      const response = await fetch('/api/v2/plugins')
      if (response.ok) {
        const data = await response.json()
        setPluginData(data.marketplace)
      }
    } catch (error) {
      console.error('Failed to fetch plugin data:', error)
    }
  }

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
          <PluginMarketplace 
            pluginData={pluginData}
            onRefresh={fetchPluginData}
          />
        </motion.div>
      </main>
    </div>
  )
}

export default PluginMarketplacePage
