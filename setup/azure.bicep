// ==============================================================================
// setup/azure.bicep - Azure AI Foundry & Claude 3.5 Sonnet Infrastructure
// ==============================================================================
// This Bicep template provisions:
// 1. Foundational Dependencies (Storage Account, Key Vault, Application Insights)
// 2. Azure AI Services Multi-Service Account (AIServices)
// 3. LLM Model Deployment (Claude 3.5 Sonnet with automatic EULA/terms acceptance)
// 4. Azure AI Foundry Hub Workspace (governance & shared connections)
// 5. Azure AI Foundry Project Workspace (runtime project for the investigator agent)
//
// Outputs:
// - PROJECT_ENDPOINT: Direct endpoint URL consumed by AIProjectClient
// - LLM_DEPLOYMENT_NAME: Name of the Claude model deployment (agent_llm)
// ==============================================================================

targetScope = 'resourceGroup'

// ==============================================================================
// CONFIGURABLE VARIABLES / PARAMETERS (Change these as needed)
// ==============================================================================

@description('Azure region for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Base name prefix used to generate unique resource names.')
param baseName string = 'btai-${uniqueString(resourceGroup().id)}'

@description('Name of the Azure AI Services multi-service account.')
param aiServicesName string = '${baseName}-aiservices'

@description('Name of the Azure AI Foundry Hub workspace.')
param hubName string = '${baseName}-hub'

@description('Name of the Azure AI Foundry Project workspace.')
param projectName string = '${baseName}-project'

// --- LLM Deployment Settings ---

@description('Name of the LLM deployment. Consumed by the agent as LLM_DEPLOYMENT_NAME.')
param deploymentName string = 'agent_llm'

@description('Model identifier in the Azure AI model catalog.')
param modelName string = 'gpt-4o'

@description('Format provider for the model.')
param modelFormat string = 'OpenAI'

@description('Version of the Claude Sonnet / GPT model.')
param modelVersion string = '2024-11-20'

@description('SKU name for the model deployment (GlobalStandard or Standard).')
param skuName string = 'GlobalStandard'

@description('Capacity allocated to the model deployment (in thousands of TPM).')
param capacity int = 10

// --- Partner Terms & EULA Acceptance Attestation ---

@description('Legal organization name for automated EULA acceptance of partner models.')
param organizationName string = 'BlueTeamingAI'

@description('Two-letter ISO country code for partner terms acceptance.')
param countryCode string = 'US'

@description('Industry category for partner terms acceptance.')
@allowed([
  'technology'
  'finance'
  'healthcare'
  'education'
  'retail'
  'manufacturing'
  'government'
  'media'
  'other'
])
param industry string = 'technology'

// --- Supporting Resource Names ---

@description('Name of the supporting Azure Storage Account (must be lowercase alphanumeric <= 24 chars).')
param storageAccountName string = take(replace('${baseName}sa', '-', ''), 24)

@description('Name of the supporting Azure Key Vault.')
param keyVaultName string = take('${baseName}-kv', 24)

@description('Name of the supporting Azure Application Insights.')
param appInsightsName string = '${baseName}-ai'

@description('Tags applied to all provisioned resources.')
param tags object = {
  Project: 'BlueTeamingAI'
  ManagedBy: 'Bicep'
  Environment: 'Development'
}

// ==============================================================================
// 1. SUPPORTING DEPENDENCIES (Storage, Key Vault, Application Insights)
// ==============================================================================

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

// ==============================================================================
// 2. AZURE AI SERVICES ACCOUNT (AIServices)
// ==============================================================================

resource aiServices 'Microsoft.CognitiveServices/accounts@2026-05-01' = {
  name: aiServicesName
  location: location
  tags: tags
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: aiServicesName
    publicNetworkAccess: 'Enabled'
  }
}

// ==============================================================================
// 3. LLM DEPLOYMENT (Claude Sonnet with EULA Approval via modelProviderData)
// ==============================================================================

resource claudeDeployment 'Microsoft.CognitiveServices/accounts/deployments@2026-05-01' = {
  parent: aiServices
  name: deploymentName
  sku: {
    name: skuName
    capacity: capacity
  }
  properties: {
    model: {
      format: modelFormat
      name: modelName
      version: modelVersion
    }
    // Automated EULA acceptance for partner models in Microsoft Foundry (Anthropic)
    #disable-next-line BCP037
    modelProviderData: modelFormat == 'Anthropic' ? {
      organizationName: organizationName
      countryCode: countryCode
      industry: industry
    } : null
  }
}

// ==============================================================================
// 4. AZURE AI FOUNDRY HUB WORKSPACE
// ==============================================================================

resource aiHub 'Microsoft.MachineLearningServices/workspaces@2024-04-01-preview' = {
  name: hubName
  location: location
  tags: tags
  kind: 'Hub'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    friendlyName: 'BlueTeamingAI Hub'
    description: 'Foundry Hub managing shared connections and models'
    storageAccount: storageAccount.id
    keyVault: keyVault.id
    applicationInsights: appInsights.id
  }
}

// Connect the AI Services account to the Foundry Hub
resource aiHubConnection 'Microsoft.MachineLearningServices/workspaces/connections@2024-04-01-preview' = {
  parent: aiHub
  name: '${hubName}-connection-AIServices'
  properties: {
    category: 'AzureOpenAI'
    target: aiServices.properties.endpoint
    authType: 'ApiKey'
    isSharedToAll: true
    credentials: {
      key: aiServices.listKeys().key1
    }
    metadata: {
      ApiType: 'Azure'
      ResourceId: aiServices.id
    }
  }
}

// ==============================================================================
// 5. AZURE AI FOUNDRY PROJECT WORKSPACE
// ==============================================================================

resource aiProject 'Microsoft.MachineLearningServices/workspaces@2024-04-01-preview' = {
  name: projectName
  location: location
  tags: tags
  kind: 'Project'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    friendlyName: 'BlueTeamingAI Investigator Project'
    description: 'Foundry Project workspace used by the LangGraph Investigator Agent'
    hubResourceId: aiHub.id
  }
  dependsOn: [
    aiHubConnection
  ]
}

// ==============================================================================
// OUTPUTS (Exported for .env and setup automation)
// ==============================================================================

@description('The Project Endpoint URL required for azure-ai-projects AIProjectClient.')
output PROJECT_ENDPOINT string = 'https://${aiServices.name}.services.ai.azure.com/api/projects/${aiProject.name}'

@description('The deployment name for the Claude 3.5 Sonnet LLM.')
output LLM_DEPLOYMENT_NAME string = deploymentName

@description('The direct Azure AI Services endpoint.')
output AI_SERVICES_ENDPOINT string = aiServices.properties.endpoint

@description('Name of the AI Services resource.')
output AI_SERVICES_NAME string = aiServices.name

@description('Name of the AI Foundry Hub.')
output HUB_NAME string = aiHub.name

@description('Name of the AI Foundry Project.')
output PROJECT_NAME string = aiProject.name
