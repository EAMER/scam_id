const params = new URLSearchParams(window.location.search);
const blockedDomain = (params.get("domain") || "").trim().toLowerCase();

document.addEventListener("DOMContentLoaded", initializeBlockedPage);

function initializeBlockedPage() {
    const domainLabel = document.getElementById("blockedDomain");
    const message = document.getElementById("blockedMessage");

    domainLabel.textContent = blockedDomain || "this site";

    if (!blockedDomain) {
        message.textContent = "The blocked domain could not be identified from this redirect.";
    }

    document.getElementById("goBackBtn").addEventListener("click", handleGoBack);
    document.getElementById("unblockBtn").addEventListener("click", handleUnblock);
}

function handleGoBack() {
    if (window.history.length > 1) {
        window.history.back();
        return;
    }

    window.location.href = "about:blank";
}

async function handleUnblock() {
    const unblockBtn = document.getElementById("unblockBtn");
    const message = document.getElementById("blockedMessage");

    if (!blockedDomain) {
        message.textContent = "This page cannot unblock the site because no domain was provided.";
        return;
    }

    try {
        unblockBtn.disabled = true;
        unblockBtn.textContent = "Unblocking...";

        const response = await chrome.runtime.sendMessage({
            action: "unblockDomain",
            domain: blockedDomain
        });

        if (!response?.success) {
            throw new Error(response?.error || "We could not remove this block.");
        }

        message.textContent = response.message || "The domain was removed from your block list.";
        unblockBtn.textContent = "Opening site...";

        window.setTimeout(() => {
            window.location.href = `https://${blockedDomain}`;
        }, 500);
    } catch (error) {
        console.error("Unable to unblock domain:", error);
        message.textContent = error.message || "We could not remove this block.";
        unblockBtn.textContent = "Unblock and continue";
        unblockBtn.disabled = false;
    }
}
