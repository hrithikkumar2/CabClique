document.addEventListener("DOMContentLoaded", function() {
    const filterBtns = document.querySelectorAll(".filter-btn");

    filterBtns.forEach(function(btn) {
        btn.addEventListener("click", function() {
            // Get the filter text input value
            const filterText = document.getElementById(`filter-${btn.dataset.filter}`).value.toLowerCase();

            // Get all tab elements
            const tabs = document.querySelectorAll(".tab1");

            // Loop through each tab and check if it matches the filter text
            tabs.forEach(function(tab) {
                // Get the text content of the tab based on the data-filter attribute
                const tabText = tab.querySelector(`.${btn.dataset.filter}`).innerText.toLowerCase();

                // If the tab text contains the filter text, display the tab, otherwise hide it
                if (tabText.includes(filterText)) {
                    tab.style.display = "block";
                } else {
                    tab.style.display = "none";
                }
            });
        });
    });
});



















