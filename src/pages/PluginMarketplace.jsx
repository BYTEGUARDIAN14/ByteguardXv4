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
    <div className="min-h-screen bg-black text-white">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      
      <main className={`transition-all duration-300 ${
        sidebarCollapsed ? 'ml-16' : 'ml-64'
      }`}>
        <Header
          title="Plugin Marketplace"
          subtitle="Extend ByteGuardX with community plugins"
          onMenuClick={() => setSidebarCollapsed(!sidebarCollapsed)}
        />
        
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
