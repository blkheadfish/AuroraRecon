import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import {
  Monitor, DataLine, List, Grid, Tools, Reading, ChatDotRound,
  User, Setting, Sunny, Moon, Fold, Expand, Plus, ArrowLeft,
  Warning, CopyDocument, Delete, Check, Cpu, Connection, Refresh,
  Loading, UserFilled, CircleCheckFilled, CircleCloseFilled,
  Remove, RemoveFilled, ArrowDown, Lock, Clock,
  SwitchButton, Edit, Key, InfoFilled, Share,
} from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import App from './App.vue'
import router from './router'
import './styles/main.css'
import { trackEvent } from '@/metrics/tracker'

const app = createApp(App)
const pinia = createPinia()

const icons = {
  Monitor, DataLine, List, Grid, Tools, Reading, ChatDotRound,
  User, Setting, Sunny, Moon, Fold, Expand, Plus, ArrowLeft,
  Warning, CopyDocument, Delete, Check, Cpu, Connection, Refresh,
  Loading, UserFilled, CircleCheckFilled, CircleCloseFilled,
  Remove, RemoveFilled, ArrowDown, Lock, Clock,
  SwitchButton, Edit, Key, InfoFilled, Share,
}
for (const [key, component] of Object.entries(icons)) {
  app.component(key, component)
}

app.use(pinia)
app.use(router)
app.use(ElementPlus)

router.afterEach((to) => {
  trackEvent('page.view', { path: to.fullPath })
})

app.mount('#app')
