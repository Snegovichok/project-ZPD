document.addEventListener("DOMContentLoaded", () => {
    const chatIdInput = document.getElementById("chat_id");
    const passwordInput = document.getElementById("password");
    const joinBtn = document.getElementById("joinBtn");

    function validateForm() {
        joinBtn.disabled = !(chatIdInput.value.trim() && passwordInput.value.trim());
    }

    chatIdInput.addEventListener("input", validateForm);
    passwordInput.addEventListener("input", validateForm);
});

