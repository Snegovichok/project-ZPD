document.addEventListener("DOMContentLoaded", function () {
    var room = document.getElementById("chat").dataset.room;
    var username = document.getElementById("chat").dataset.username;
    var socket = io();

    socket.emit("join", { room: room, username: username });

    socket.on("message", function (data) {
        var chat = document.getElementById("chat");
        var p = document.createElement("p");
        p.innerHTML = "<strong>" + data.username + ":</strong> " + data.message;
        chat.appendChild(p);
    });

    document.getElementById("messageForm").addEventListener("submit", function (e) {
        e.preventDefault();
        var msg = document.getElementById("message").value.trim();
        if (msg === "") return;
        socket.emit("send_message", { room: room, username: username, message: msg });
        document.getElementById("message").value = "";
    });

    socket.on("chat_deleted", function (data) {
        if (data.chat_id === room) {
            alert("Чат был удален");
            fetch("/remove_joined_chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ chat_id: data.chat_id }),
            }).then(() => {
                window.location.href = "/join_private_chat";
            });
        }
    });
});

