// The identity provider sent the browser back from another site, so the Strict session cookie was left out.
// Sending the code and state on from this page is a same-site request, which carries the cookie.
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('sso-continue');
    if (form) form.submit();
});
