document.addEventListener("DOMContentLoaded", () => {
    const toggleCheckbox = document.getElementById("toggleOn");
    const detailCheckbox = document.getElementById("toggleDetail");
    console.log("i'm popup.js");

    chrome.storage.sync.get(["toggleTrueLinks"], res => {
        toggleCheckbox.checked = res.toggleTrueLinks ?? true;
    });
    chrome.storage.sync.get(["detailTrueLinks"], res => {
        detailCheckbox.checked = res.detailTrueLinks ?? false;
    });

    toggleCheckbox.addEventListener("change", () => {
        chrome.storage.sync.set({
            toggleTrueLinks: toggleCheckbox.checked
        });
    });
    detailCheckbox.addEventListener("change", () => {
        chrome.storage.sync.set({
            detailTrueLinks: detailCheckbox.checked
        });
    });
});
