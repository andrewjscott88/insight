"""Upload a local PDF using the signed-in session and the ingest dialog's metadata fields."""

from __future__ import annotations

from nicegui import ui

from .messages import problem_area, tell
from .workspace import Workspace

# Only the browser streams the PDF bytes. Metadata travels in a header so titles and publisher links
# stay out of request URLs. The API validates it and applies the same handling ceiling as the text form.
_UPLOAD = """
(async () => {
    const picker = document.querySelector('.pdf-advisory-file');
    const file = picker?.files?.[0];
    if (!file) return {error: 'Choose a PDF file first.'};
    if (file.size > 2000000) return {error: 'Choose a PDF of 2 megabytes or less.'};
    const fields = {
        title: document.querySelector('.pdf-report-title input').value,
        source_name: document.querySelector('.pdf-report-source input').value,
        source_url: document.querySelector('.pdf-report-url input').value,
        tlp: picker.dataset.tlp,
    };
    if (!fields.tlp) return {error: 'Choose a sharing label.'};
    if (!fields.title.trim()) return {error: 'Enter a title for the report.'};
    if (!fields.source_name.trim()) return {error: 'Enter where the report came from.'};
    try {
        const bytes = new TextEncoder().encode(JSON.stringify(fields));
        const header = btoa(String.fromCharCode(...bytes))
            .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
        const session = await fetch('/api/session');
        if (!session.ok) return {error: 'Sign in again before importing a PDF.'};
        const {csrf_token} = await session.json();
        const response = await fetch('/api/documents/pdf', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/pdf',
                'X-CSRF-Token': csrf_token,
                'X-Insight-Document': header,
            },
            body: file,
        });
        if (!response.ok) {
            const message = await response.json().catch(() => ({}));
            const detail = typeof message.detail === 'string'
                ? message.detail : 'The server refused this PDF.';
            return {error: detail};
        }
        const {created, document_id} = await response.json();
        picker.value = '';
        return {created, document_id};
    } catch {
        return {error: 'Connection interrupted. Check the inbox before retrying the import.'};
    }
})()
"""


def build_pdf_import(ws: Workspace, dialog: ui.dialog, tlp: ui.select) -> None:
    with ui.expansion('Import a PDF').classes('w-full'):
        ui.label(
            'Choose a PDF with text, up to 2 megabytes. Insight keeps the text and file fingerprint.'
        ).classes('muted prose')
        picker = (
            ui.element('input')
            .props('type=file accept=".pdf,application/pdf" aria-label="PDF advisory file"')
            .classes('pdf-advisory-file w-full')
        )
        tlp.bind_value_to(picker.props, 'data-tlp')
        problem = problem_area()

        async def submit() -> None:
            if not ws.authorized() or not button.enabled:
                return
            problem.set_text('')
            button.disable()
            try:
                result = await ui.run_javascript(_UPLOAD, timeout=120)
            except TimeoutError:
                problem.set_text('Check the inbox before retrying the import.')
                return
            finally:
                button.enable()
            if result is None or not ws.authorized():
                return
            if 'error' in result:
                problem.set_text(result['error'])
                return
            ws.state.selected = result['document_id']
            dialog.close()
            ws.refresh_all()
            ws.show_inbox()
            tell('PDF imported.' if result['created'] else 'You already have this PDF.', 'success')

        button = ui.button('Import PDF', on_click=submit)
