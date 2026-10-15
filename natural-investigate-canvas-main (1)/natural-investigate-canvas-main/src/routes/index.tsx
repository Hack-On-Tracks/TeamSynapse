import { createFileRoute } from '@tanstack/react-router';
import { Workspace } from '@/components/workspace';
export const Route = createFileRoute('/')({
  head: () => ({ meta: [{ title: 'Security overview · CipherSentinel' }, { name: 'description', content: 'Review encrypted traffic signals and prioritise insider-risk investigations in CipherSentinel.' }, { property: 'og:title', content: 'Security overview · CipherSentinel' }, { property: 'og:description', content: 'A privacy-first security analyst workspace for encrypted traffic investigations.' }, { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary_large_image' }] }),
  component: () => <Workspace />,
});
