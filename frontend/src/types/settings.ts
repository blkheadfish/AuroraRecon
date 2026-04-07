export interface LlmSettings {
  provider: 'deepseek' | 'openai' | 'anthropic' | 'custom' | string
  api_key: string
  model: string
  base_url: string
  max_tokens: number
}

export interface ExecutorSettings {
  docker_network: string
  toolbox_image: string
  persistent_container: boolean
  lhost: string
}

export interface EmbeddingSettings {
  enabled: boolean
  api_key: string
  base_url: string
  model: string
}

export interface WorkflowSettings {
  require_approval: boolean
  max_retries: number
  default_scope: string
  report_lang: 'zh' | 'en' | string
}

export interface SettingsPayload {
  llm?: Partial<LlmSettings>
  embedding?: Partial<EmbeddingSettings>
  executor?: Partial<ExecutorSettings>
  workflow?: Partial<WorkflowSettings>
}

export interface UserProfile {
  nickname: string
  avatar: string
  updated_at?: string
}

export interface ProfileUpdatePayload {
  nickname: string
  avatar: string
}

export interface PasswordChangePayload {
  old_password: string
  new_password: string
}
