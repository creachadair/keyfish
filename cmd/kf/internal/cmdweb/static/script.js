(()=>{
    // The "correct" way to copy text to the clipboard is navigator.clipboard,
    // but that API is only available in a secure context.  When running on
    // Tailscale without HTTPS, or for local testing, use a shim that falls
    // back to execCommand.
    if (window.isSecureContext && navigator.hasOwnProperty('clipboard')) {
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text);
        }
    } else {
        // Create an element outside the viewport to copy from.
        const pasteBuf = document.createElement('textarea');
        pasteBuf.style.display = 'none';
        pasteBuf.style.position = 'absolute';
        pasteBuf.style.left = '-999999px'; // off the viewport

        function copyToClipboard(text) {
            pasteBuf.value = text;
            document.body.prepend(pasteBuf);

            // We can't select unless the element is displayed.
            pasteBuf.style.display = 'inline-block';
            pasteBuf.select();
            try {
                document.execCommand('copy');
            } finally {
                pasteBuf.remove();
                pasteBuf.style.display = 'none';
            }
        }
    }

    // Add a listener for the HTMX event our API handler reports when injecting
    // the text requested by clicking a copy button, to copy the text from the
    // element where it was stored (identified in the detail) to the clipboard.
    window.addEventListener('copyText', (evt) => {
        const id = evt.detail.value;
        const text = document.getElementById(id);

        copyToClipboard(text.value);
        text.value = '';
    });

    // Add a listener to the button injected when a hidden detail value is
    // installed in the DOM, allowing the user to toggle it on and off without
    // another round trip to the server.
    window.addEventListener('setValueToggle', (evt) => {
        const base = evt.detail.value;
        const vis = document.getElementById(base+'vis');
        let vdisp = vis.style.display; // save original display style

        // The "hidden" element is initially invisible by the stylesheet, but
        // we want to be able to make it visible when the button is pushed, so
        // explicity remove its initial style class (.nvis).
        const nvis = document.getElementById(base+'nvis');
        let ndisp = nvis.style.display; // save original display style
        nvis.style.display = 'none';
        nvis.className = '';

        const btn = document.getElementById(base+'btn');

        let visible = true;
        btn.addEventListener('click', (evt) => {
            visible = !visible;
            if (visible) {
                nvis.style.display = 'none';
                vis.style.display = vdisp;
                btn.innerHTML = 'Hide'
            } else {
                vis.style.display = 'none';
                nvis.style.display = ndisp;
                btn.innerHTML = 'Show'
            }
        });
    });

    function pulse(elt, cls, time) {
        elt.classList.toggle(cls)
        setTimeout(() => { elt.classList.toggle(cls); }, time);
    }

    function setLockPin() {
        const lockPin = document.getElementById('lockpin');
        if (lockPin) {
            lockPin.addEventListener('htmx:responseError', (evt) => {
                pulse(lockPin, 'failing', 200);
                console.log("Error: "+evt.detail.xhr.response);
                lockPin.value = '';
            })
        }
    }

    // After htmx is done settling the DOM, attach click handlers to copyable
    // things so that the user can click to copy their contents.
    window.addEventListener('htmx:afterSettle', (evt) => {
        evt.target.querySelectorAll('.copyable').forEach((elt) => {
            elt.addEventListener('click', (ign) => {
                pulse(elt, 'copying', 300); // match transition timing
                copyToClipboard(elt.innerText);
            });
        });

        // Give the user an indication if they enter the wrong lock PIN.
        setLockPin();

        // If a query fails with status 403, go back to the lock page.
        window.addEventListener('htmx:responseError', (evt) => {
            if (evt.detail.xhr.status == 403) {
                document.getElementById('lockbtn').click();
            }
        }, {once: true})
    });
})()
