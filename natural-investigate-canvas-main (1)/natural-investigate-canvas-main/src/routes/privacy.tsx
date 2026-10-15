import { createFileRoute } from '@tanstack/react-router';
import { Workspace } from '@/components/workspace';
export const Route = createFileRoute('/privacy')({
  head: () => ({ meta: [{ title: 'Privacy & controls · CipherSentinel' }, { name: 'description', content: 'Explore the privacy commitments behind metadata-only monitoring and human-led investigation.' }, { property: 'og:title', content: 'Privacy & controls · CipherSentinel' }, { property: 'og:description', content: 'Content privacy, protected identities, and accountable human decisions.' }, { property: 'og:type', content: 'website' }, { name: 'twitter:card', content: 'summary_large_image' }] }),
  component: () => <Workspace view="Privacy & controls" />,
});