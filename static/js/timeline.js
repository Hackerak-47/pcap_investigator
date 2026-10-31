// timeline.js - Interactive filtering and controls for the timeline

document.addEventListener('DOMContentLoaded', () => {
    // Smooth scrolling for timeline steps if navigated via anchor
    const hash = window.location.hash;
    if (hash) {
        const target = document.querySelector(hash);
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            target.classList.add('border-info');
        }
    }
});
