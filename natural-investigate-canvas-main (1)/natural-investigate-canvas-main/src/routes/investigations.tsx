import { createFileRoute } from '@tanstack/react-router';
import { Workspace } from '@/components/workspace';
export const Route = createFileRoute('/investigations')({
  head: () => ({ meta: [{ title: 'Investigations · CipherSentinel' }, { name: 'description', content: 'Triage pseudonymised cases and review the evidence behind encrypted traffic anomalies.' }, { property: 'og:title', content: 'Investigations · CipherSentinel' }, { property: 'og:description', content: 'Human-led review of metadata-only security cases.' }, { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary_large_image' }] }),
  component: () => <Workspace view="Investigations" />,
});