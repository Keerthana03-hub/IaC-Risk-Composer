import {
  LayoutDashboard,
  FolderGit2,
  UploadCloud,
  Network,
  ShieldAlert,
  FileText,
  Settings,
  Cpu,
} from 'lucide-react'

export const NAV_SECTIONS = [
  {
    title: 'WORKSPACE',
    items: [
      {
        to: '/dashboard',
        label: 'Dashboard',
        icon: LayoutDashboard,
        title: 'Security Dashboard',
        description: "Here's an overview of your infrastructure security posture.",
      },
      {
        to: '/projects',
        path: '/projects',
        label: 'Projects',
        icon: FolderGit2,
        title: 'Projects',
        description: 'Manage your infrastructure workspaces and scan history.',
      },
      {
        to: '/analyze?new=1',
        path: '/analyze',
        label: 'New Analysis',
        icon: UploadCloud,
        title: 'New Security Analysis',
        description: 'Upload your infrastructure configuration to identify security risks and potential threats.',
      },
    ],
  },
  {
    title: 'SECURITY',
    items: [
      {
        to: '/infrastructure',
        label: 'Infrastructure Map',
        icon: Network,
        title: 'Infrastructure Map',
        description: 'Explore detected cloud resources, dependencies, and highlighted risks.',
      },
      {
        to: '/threats',
        label: 'Threats',
        icon: ShieldAlert,
        title: 'Threats',
        description: 'Security threats and risks detected across your infrastructure.',
      },
      {
        to: '/reports',
        label: 'Security Reports',
        icon: FileText,
        title: 'Security Reports',
        description: 'Persisted security assessment reports and downloadable audit artifacts.',
      },
    ],
  },
  {
    title: 'SYSTEM',
    items: [
      {
        to: '/system-info',
        label: 'System & Engine',
        icon: Cpu,
        title: 'System Architecture',
        description: 'Backend connectivity, scoring methodology, and threat detection engine rules.',
      },
      {
        to: '/settings',
        label: 'Settings',
        icon: Settings,
        title: 'Settings',
        description: 'Manage developer profile, appearance, notifications, and account credentials.',
      },
    ],
  },
]

export const ALL_NAV_ITEMS = NAV_SECTIONS.flatMap(s => s.items)

export function pageMeta(pathname) {
  const cleanPath = pathname.split('?')[0]
  return ALL_NAV_ITEMS.find(i => (i.path ?? i.to).split('?')[0] === cleanPath) ?? ALL_NAV_ITEMS[0]
}
