function showLoading(event) {

    event.preventDefault(); // IMPORTANT

    const button = document.getElementById("analyzeBtn");
    const btnText = document.getElementById("btnText");

    btn.disabled = true;

    let steps = [
        "THREAD INITIALIZING...",
        "ANALYZING...",
        "SCANNING URL..."
    ];

    let i = 0;
    text.innerText = steps[i];

    let interval = setInterval(() => {

        i++;

        if (i < steps.length) {
            text.innerText = steps[i];
        } else {
            clearInterval(interval);
            text.innerText = "FINALIZING...";

            // after animation → send to Flask
            setTimeout(() => {
                event.target.submit();
            }, 500);
        }

    }, 800);
}