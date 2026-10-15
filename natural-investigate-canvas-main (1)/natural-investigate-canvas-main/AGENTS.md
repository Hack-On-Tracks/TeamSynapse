<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Keep the CipherSentinel UI in TanStack file routes and shared workspace components; this preserves navigation and SSR conventions.
- Keep simulated evidence in a browser-safe typed module and all analyst decisions in session state until a real data service is requested; this makes the frontend prototype honest about its capabilities.
- Define all presentation colors and shared visual patterns in the global design system; this keeps the analyst workspace consistent.
