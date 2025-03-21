document.addEventListener("DOMContentLoaded", function () {
    var fileInput = document.getElementById("fileInput");
    var uploadBtn = document.getElementById("uploadBtn");

    fileInput.addEventListener("change", function () {
        uploadBtn.disabled = !this.files.length;
    });
});

