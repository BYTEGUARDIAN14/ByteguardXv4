import React, { useState, useEffect } from 'react'
import PluginMarketplace from '../components/PluginMarketplace'

const PluginMarketplacePage = () => {
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
    <div className="p-6 overflow-y-auto">
      <div className="mb-6">
        <h1 className="text-lg font-semibold text-text-primary">Plugin Marketplace</h1>
        <p className="text-xs text-text-muted mt-0.5">Extend ByteGuardX with community plugins</p>
      </div>
      <PluginMarketplace
        pluginData={pluginData}
        onRefresh={fetchPluginData}
      />
    </div>
  )
}

export default PluginMarketplacePage
