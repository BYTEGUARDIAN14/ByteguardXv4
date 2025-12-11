import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Server,
  CheckCircle,
  AlertTriangle,
  X,
  ChevronRight,
  ChevronLeft,
  Download,
  Play,
  Eye,
  Settings,
  Database,
  Mail,
  Shield,
  Globe
} from 'lucide-react'

const DeploymentWizard = () => {
  const [currentStep, setCurrentStep] = useState(0)
  const [requirements, setRequirements] = useState(null)
  const [config, setConfig] = useState({
    db_name: 'byteguardx',
    db_user: 'byteguardx',
    db_password: '',
    admin_email: '',
    domain: 'localhost',
    frontend_port: '3000',
    backend_port: '5000',
    ssl_enabled: false,
    smtp_host: '',
    smtp_port: '587',
    smtp_username: '',
    smtp_password: '',
    email_from: ''
  })
  const [deploymentId, setDeploymentId] = useState(null)
  const [deploymentStatus, setDeploymentStatus] = useState(null)
  const [loading, setLoading] = useState(false)

  const steps = [
    {
      id: 'requirements',
      title: 'System Requirements',
      description: 'Check system requirements for deployment',
      icon: CheckCircle
    },
    {
      id: 'database',
      title: 'Database Configuration',
      description: 'Configure database settings',
      icon: Database
    },
    {
      id: 'application',
      title: 'Application Settings',
      description: 'Configure application and domain settings',
      icon: Settings
    },
    {
      id: 'email',
      title: 'Email Configuration',
      description: 'Setup email notifications (optional)',
      icon: Mail
    },
    {
      id: 'security',
      title: 'Security Settings',
      description: 'Configure SSL and security options',
      icon: Shield
    },
    {
      id: 'deploy',
      title: 'Deploy',
      description: 'Generate files and start deployment',
      icon: Play
    }
  ]

  useEffect(() => {
    if (currentStep === 0) {
      checkRequirements()
    }
  }, [currentStep])

  const checkRequirements = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/deploy/check-requirements')
      if (response.ok) {
        const data = await response.json()
        setRequirements(data)
      }
    } catch (error) {
      console.error('Error checking requirements:', error)
    } finally {
      setLoading(false)
    }
  }

  const generateConfig = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/deploy/generate-config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
      })
      
      if (response.ok) {
        const data = await response.json()
        return data.config
      }
      throw new Error('Failed to generate configuration')
    } catch (error) {
      console.error('Error generating config:', error)
      throw error
    } finally {
      setLoading(false)
    }
  }

  const startDeployment = async () => {
    try {
      setLoading(true)
      
      // Generate configuration
      const generatedConfig = await generateConfig()
      
      // Create deployment files
      const filesResponse = await fetch('/api/deploy/create-files', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ config: generatedConfig })
      })
      
      if (!filesResponse.ok) {
        throw new Error('Failed to create deployment files')
      }
      
      const filesData = await filesResponse.json()
      
      // Start deployment
      const deployResponse = await fetch('/api/deploy/deploy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ deployment_dir: filesData.deployment_dir })
      })
      
      if (deployResponse.ok) {
        const deployData = await deployResponse.json()
        setDeploymentId(deployData.deployment_id)
        
        // Start polling for status
        pollDeploymentStatus(deployData.deployment_id)
      }
    } catch (error) {
      console.error('Error starting deployment:', error)
    } finally {
      setLoading(false)
    }
  }

  const pollDeploymentStatus = async (id) => {
    try {
      const response = await fetch(`/api/deploy/status/${id}`)
      if (response.ok) {
        const status = await response.json()
        setDeploymentStatus(status)
        
        if (status.status !== 'completed' && status.status !== 'failed') {
          setTimeout(() => pollDeploymentStatus(id), 2000)
        }
      }
    } catch (error) {
      console.error('Error polling deployment status:', error)
    }
  }

  const nextStep = () => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(currentStep + 1)
    }
  }

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  const canProceed = () => {
    switch (currentStep) {
      case 0: // Requirements
        return requirements?.all_requirements_met
      case 1: // Database
        return config.db_name && config.db_user && config.admin_email
      case 2: // Application
        return config.domain
      case 3: // Email (optional)
        return true
      case 4: // Security
        return true
      default:
        return true
    }
  }

  const renderStepContent = () => {
    switch (currentStep) {
      case 0: // Requirements Check
        return (
          <div className="space-y-6">
            <div className="text-center">
              <Server className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">System Requirements</h3>
              <p className="text-gray-400">
                Checking if your system meets the requirements for ByteGuardX deployment
              </p>
            </div>

            {loading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
              </div>
            ) : requirements ? (
              <div className="space-y-4">
                {Object.entries(requirements.requirements).map(([key, req]) => (
                  <div key={key} className="flex items-center justify-between p-4 bg-gray-900/30 rounded-lg">
                    <div className="flex items-center space-x-3">
                      {req.status ? (
                        <CheckCircle className="h-5 w-5 text-green-400" />
                      ) : (
                        <X className="h-5 w-5 text-red-400" />
                      )}
                      <div>
                        <p className="text-white font-medium">{key.replace('_', ' ').toUpperCase()}</p>
                        <p className="text-gray-400 text-sm">{req.message}</p>
                      </div>
                    </div>
                  </div>
                ))}

                {requirements.recommendations.length > 0 && (
                  <div className="p-4 bg-yellow-500/20 border border-yellow-500/30 rounded-lg">
                    <div className="flex items-start space-x-3">
                      <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5" />
                      <div>
                        <h4 className="text-yellow-400 font-medium mb-2">Recommendations</h4>
                        <ul className="text-yellow-300 text-sm space-y-1">
                          {requirements.recommendations.map((rec, index) => (
                            <li key={index}>• {rec}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        )

      case 1: // Database Configuration
        return (
          <div className="space-y-6">
            <div className="text-center">
              <Database className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">Database Configuration</h3>
              <p className="text-gray-400">
                Configure your PostgreSQL database settings
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Database Name *
                </label>
                <input
                  type="text"
                  value={config.db_name}
                  onChange={(e) => setConfig(prev => ({ ...prev, db_name: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Database User *
                </label>
                <input
                  type="text"
                  value={config.db_user}
                  onChange={(e) => setConfig(prev => ({ ...prev, db_user: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Database Password
                </label>
                <input
                  type="password"
                  value={config.db_password}
                  onChange={(e) => setConfig(prev => ({ ...prev, db_password: e.target.value }))}
                  placeholder="Leave empty to auto-generate"
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Admin Email *
                </label>
                <input
                  type="email"
                  value={config.admin_email}
                  onChange={(e) => setConfig(prev => ({ ...prev, admin_email: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                  required
                />
              </div>
            </div>
          </div>
        )

      case 2: // Application Settings
        return (
          <div className="space-y-6">
            <div className="text-center">
              <Globe className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">Application Settings</h3>
              <p className="text-gray-400">
                Configure domain and port settings
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Domain *
                </label>
                <input
                  type="text"
                  value={config.domain}
                  onChange={(e) => setConfig(prev => ({ ...prev, domain: e.target.value }))}
                  placeholder="localhost or your-domain.com"
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Frontend Port
                </label>
                <input
                  type="number"
                  value={config.frontend_port}
                  onChange={(e) => setConfig(prev => ({ ...prev, frontend_port: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Backend Port
                </label>
                <input
                  type="number"
                  value={config.backend_port}
                  onChange={(e) => setConfig(prev => ({ ...prev, backend_port: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                />
              </div>
            </div>
          </div>
        )

      case 5: // Deploy
        return (
          <div className="space-y-6">
            <div className="text-center">
              <Play className="h-12 w-12 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">Ready to Deploy</h3>
              <p className="text-gray-400">
                All configuration is complete. Click deploy to start the installation.
              </p>
            </div>

            {deploymentStatus && (
              <div className="space-y-4">
                <div className="p-4 bg-gray-900/30 rounded-lg">
                  <h4 className="text-white font-medium mb-2">Deployment Progress</h4>
                  <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                    <div 
                      className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${deploymentStatus.progress}%` }}
                    />
                  </div>
                  <p className="text-gray-400 text-sm">{deploymentStatus.progress}% complete</p>
                </div>

                <div className="space-y-2">
                  {deploymentStatus.steps.map((step, index) => (
                    <div key={index} className="flex items-center space-x-3 p-2 bg-gray-900/20 rounded">
                      {step.status === 'completed' ? (
                        <CheckCircle className="h-4 w-4 text-green-400" />
                      ) : (
                        <div className="h-4 w-4 border-2 border-gray-600 rounded-full" />
                      )}
                      <span className="text-white text-sm">{step.name}</span>
                    </div>
                  ))}
                </div>

                {deploymentStatus.status === 'completed' && (
                  <div className="p-4 bg-green-500/20 border border-green-500/30 rounded-lg">
                    <h4 className="text-green-400 font-medium mb-2">Deployment Complete!</h4>
                    <div className="space-y-2">
                      <p className="text-green-300 text-sm">
                        Frontend: <a href={deploymentStatus.urls.frontend} target="_blank" rel="noopener noreferrer" className="underline">{deploymentStatus.urls.frontend}</a>
                      </p>
                      <p className="text-green-300 text-sm">
                        Admin: <a href={deploymentStatus.urls.admin} target="_blank" rel="noopener noreferrer" className="underline">{deploymentStatus.urls.admin}</a>
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )

      default:
        return <div>Step content not implemented</div>
    }
  }

  return (
    <div className="min-h-screen bg-black text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold gradient-text mb-2">Deployment Wizard</h1>
        <p className="text-gray-400">Self-hosted ByteGuardX deployment setup</p>
      </div>

      {/* Step Progress */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          {steps.map((step, index) => {
            const Icon = step.icon
            const isActive = index === currentStep
            const isCompleted = index < currentStep
            
            return (
              <div key={step.id} className="flex items-center">
                <div className={`
                  flex items-center justify-center w-10 h-10 rounded-full border-2 transition-all
                  ${isActive ? 'border-cyan-500 bg-cyan-500' :
                    isCompleted ? 'border-green-500 bg-green-500' :
                    'border-gray-600 bg-gray-800'}
                `}>
                  <Icon className={`h-5 w-5 ${isActive || isCompleted ? 'text-white' : 'text-gray-400'}`} />
                </div>
                
                {index < steps.length - 1 && (
                  <div className={`
                    w-16 h-0.5 mx-2
                    ${isCompleted ? 'bg-green-500' : 'bg-gray-600'}
                  `} />
                )}
              </div>
            )
          })}
        </div>
        
        <div className="mt-4">
          <h2 className="text-xl font-semibold text-white">{steps[currentStep].title}</h2>
          <p className="text-gray-400">{steps[currentStep].description}</p>
        </div>
      </div>

      {/* Step Content */}
      <div className="glass-card p-8 mb-8">
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.2 }}
          >
            {renderStepContent()}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={prevStep}
          disabled={currentStep === 0}
          className="btn-secondary flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <ChevronLeft className="h-4 w-4" />
          <span>Previous</span>
        </button>

        <div className="flex space-x-3">
          {currentStep === steps.length - 1 ? (
            <button
              onClick={startDeployment}
              disabled={loading || !canProceed()}
              className="btn-primary flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              ) : (
                <Play className="h-4 w-4" />
              )}
              <span>{loading ? 'Deploying...' : 'Deploy'}</span>
            </button>
          ) : (
            <button
              onClick={nextStep}
              disabled={!canProceed()}
              className="btn-primary flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <span>Next</span>
              <ChevronRight className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

export default DeploymentWizard
