// The completed page establishes a same-site navigation context without relaxing Strict cookies.
// Check the stored session before continuing, so blocked cookies cannot cause another redirect loop.
document.addEventListener('DOMContentLoaded', async () => {
    const status = document.getElementById('entry-status');
    try {
        const response = await fetch('/api/session', {
            credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        });
        if (response.status === 200) {
            window.location.replace('/');
        } else if (status) {
            status.textContent = 'Allow cookies for this site, then try again.';
        }
    } catch {
        if (status) status.textContent = 'Could not open the workspace. Try the link below.';
    }
});
