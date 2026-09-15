import { useAuth } from '../../store/auth'
import InfoModal from '../modals/InfoModal'
import NewProjectModal from '../modals/NewProjectModal'
import ResultsModal from '../modals/ResultsModal'
import BlackboardView from '../../views/BlackboardView'
import ChatView from '../../views/ChatView'
import FindingsView from '../../views/FindingsView'
import HealthView from '../../views/HealthView'
import ProjectsView from '../../views/ProjectsView'
import SettingsView from '../../views/SettingsView'
import Rail from './Rail'

export default function AppShell() {
  const route = useAuth((state) => state.route)

  return (
    <div className="flex h-full overflow-hidden">
      <Rail />
      <div className="flex min-w-0 flex-1 flex-col">
        {route === 'chat' ? <ChatView /> : null}
        {route === 'blackboard' ? <BlackboardView /> : null}
        {route === 'projects' ? <ProjectsView /> : null}
        {route === 'findings' ? <FindingsView /> : null}
        {route === 'health' ? <HealthView /> : null}
        {route === 'settings' ? <SettingsView /> : null}
      </div>

      <InfoModal />
      <NewProjectModal />
      <ResultsModal />
    </div>
  )
}
