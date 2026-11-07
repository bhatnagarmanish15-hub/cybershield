
const analyzeForm = document.getElementById("analyzeForm");
const analyzeButton = document.getElementById("analyzeButton");
const statusMessage = document.getElementById("statusMessage");
const results = document.getElementById("results");

analyzeForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const url = document.getElementById("websiteUrl").value.trim();

    if (!url) {
        statusMessage.textContent = "Please enter a website URL.";
        return;
    }

    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyzing...";
    statusMessage.textContent = "Connecting to the website...";
    results.classList.add("hidden");

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        showResults(data);
        statusMessage.textContent = "Analysis completed successfully.";

    } catch (error) {
        statusMessage.textContent = error.message;
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analyze Website";
    }
});


function showResults(data) {
    results.classList.remove("hidden");

    document.getElementById("score").textContent =
        data.score + "/100";

    document.getElementById("risk").textContent =
        data.risk;

    document.getElementById("passed").textContent =
        data.passed;

    document.getElementById("failed").textContent =
        data.failed;

    document.getElementById("analyzedUrl").textContent =
        data.url;

    document.getElementById("httpStatus").textContent =
        data.status_code;

    const redirectInfo = document.getElementById("redirectInfo");

    if (data.redirect_location) {
        redirectInfo.textContent =
            "Redirect returned but not followed: " + data.redirect_location;
    } else {
        redirectInfo.textContent = "No redirect was returned.";
    }

    document.getElementById("analysisNote").textContent =
        data.note;

    const checksList = document.getElementById("checksList");
    checksList.innerHTML = "";

    data.checks.forEach(function (check) {
        const card = document.createElement("div");
        card.className = "check-card";

        const heading = document.createElement("h3");
        heading.textContent =
            (check.passed ? "✓ " : "✗ ") + check.name;

        const message = document.createElement("p");
        message.textContent = check.message;

        const recommendation = document.createElement("p");
        recommendation.textContent =
            "Recommendation: " + check.recommendation;

        const points = document.createElement("small");
        points.textContent = "Score weight: " + check.weight + " points";

        card.classList.add(check.passed ? "passed" : "failed");

        card.appendChild(heading);
        card.appendChild(message);
        card.appendChild(recommendation);
        card.appendChild(points);

        checksList.appendChild(card);
    });
}
