document.addEventListener("DOMContentLoaded", function () {
    var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // Функция для получения CSRF-токена из cookie (если используется Flask-WTF)
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            let cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i].trim();
                if (cookie.startsWith(name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Автоматическое добавление CSRF-токена во все формы
    document.querySelectorAll('form').forEach(function (form) {
        if (!form.querySelector('input[name="csrf_token"]')) {
            let input = document.createElement("input");
            input.setAttribute("type", "hidden");
            input.setAttribute("name", "csrf_token");
            input.setAttribute("value", csrfToken);
            form.appendChild(input);
        }
    });

    // Настройка AJAX-запросов (если используется jQuery)
    if (window.jQuery) {
        $.ajaxSetup({
            beforeSend: function (xhr) {
                xhr.setRequestHeader("X-CSRFToken", csrfToken);
            }
        });
    }
});

