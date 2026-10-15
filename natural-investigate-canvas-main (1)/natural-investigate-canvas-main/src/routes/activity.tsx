import { createFileRoute } from '@tanstack/react-router';
import { Workspace } from '@/components/workspace';
export const Route = createFileRoute('/activity')({
  head: () => ({ meta: [{ title: 'Activity log · CipherSentinel' }, { name: 'description', content: 'Review the transparent activity history of the CipherSentinel security workspace.' }, { property: 'og:title', content: 'Activity log · CipherSentinel' }, { property: 'og:description', content: 'A transparent record of security investigation activity.' }, { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary_large_image' }] }),
  component: () => <Workspace view="Activity log" />,
});