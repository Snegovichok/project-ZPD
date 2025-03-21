document.addEventListener("DOMContentLoaded", function () {
    var socket = io();
    var chat = document.getElementById('chat');
    var messageInput = document.getElementById('message');
    var sendMessageButton = document.getElementById('sendMessageButton');

    // Функция для автоматической прокрутки чата вниз
    function scrollToBottom() {
        chat.scrollTop = chat.scrollHeight;
    }

    // Получаем имя пользователя из data-атрибута в HTML
    var username = document.body.getAttribute("data-username") || "Гость";

    socket.emit('join', { room: 'general', username: username });

    socket.on('message', function (data) {
        var p = document.createElement('p');
        p.innerHTML = '<strong>' + data.username + ':</strong> ' + data.message;
        chat.appendChild(p);
        scrollToBottom();
    });

    sendMessageButton.addEventListener('click', function () {
        var msg = messageInput.value.trim();
        if (msg !== "") {
            socket.emit('send_message', { room: 'general', username: username, message: msg });
            messageInput.value = '';
            messageInput.focus();
        }
    });

    // Прокручиваем вниз при загрузке
    scrollToBottom();
});

