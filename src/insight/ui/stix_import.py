"""Upload a STIX bundle through the same authenticated import endpoint as an API client."""

from __future__ import annotations

from nicegui import ui

from .messages import problem_area, tell
from .workspace import Workspace

# Send the File as the request body. The browser handles the session cookie and the API enforces the size
# limit, CSRF token and sharing policy. Report contents do not travel over the workspace socket.
_UPLOAD = """
(async () => {
    const picker = document.querySelector('.stix-bundle-file');
    const file = picker?.files?.[0];
    if (!file) return {error: 'Choose a STIX bundle file first.'};
    if (file.size > 2000000) return {error: 'Choose a bundle of 2 MB or less.'};
    try {
        const session = await fetch('/api/session');
        if (!session.ok) return {error: 'Sign in again before importing a bundle.'};
        const {csrf_token} = await session.json();
        const response = await fetch('/api/import/stix', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf_token},
            body: file,
        });
        if (!response.ok) {
            const message = await response.json().catch(() => ({}));
            const detail = typeof message.detail === 'string'
                ? message.detail : 'The server refused this bundle.';
            return {error: detail};
        }
        const {created, reports} = await response.json();
        picker.value = '';
        return {created, reports};
    } catch {
        return {error: 'Connection interrupted. Check the inbox before retrying the import.'};
    }
})()
"""


def build_stix_import(ws: Workspace, dialog: ui.dialog) -> None:
    with ui.expansion('Import a STIX bundle').classes('w-full'):
        ui.label('Choose a STIX 2.1 JSON file up to 2 MB. The workspace sharing limit applies.').classes(
            'muted prose'
        )
        ui.element('input').props(
            'type=file accept=".json,.stix,application/json,application/stix+json" '
            'aria-label="STIX bundle file"'
        ).classes('stix-bundle-file w-full')
        problem = problem_area()

        async def submit() -> None:
            if not ws.authorized() or not button.enabled:
                return
            problem.set_text('')
            button.disable()
            try:
                result = await ui.run_javascript(_UPLOAD, timeout=120)
            except TimeoutError:
                problem.set_text(
                    'The server is still processing the request. Check the inbox before retrying.'
                )
                return
            finally:
                button.enable()
            if result is None:  # The browser tab was closed.
                return
            if 'error' in result:
                problem.set_text(result['error'])
                return
            if not ws.authorized():
                return
            dialog.close()
            ws.refresh_all()
            ws.show_inbox()
            count = result['created']
            existing = result['reports'] - count
            tell(
                f'Imported {count} new {"report" if count == 1 else "reports"}. Already present: {existing}.',
                'success',
            )

        button = ui.button('Import bundle', on_click=submit)
