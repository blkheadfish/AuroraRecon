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

/**
 * 全局 workflow 设置块只保留"新建任务默认值"类属性,
 * 不再承载会直接写回 os.environ 的 operator_role / success_gate 等字段。
 * 每个任务的审批策略 / 证据门槛 / 轮次上限都是 per-task,
 * 通过 CreateTaskRequest 传给后端。
 */
export interface WorkflowSettings {
  default_mode: 'pentest_engineer' | 'ctf_expert' | string
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
