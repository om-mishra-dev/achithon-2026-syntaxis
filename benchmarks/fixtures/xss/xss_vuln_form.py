"""XSS-003: Vulnerable - render_template_string with request.form input."""
from flask import request, render_template_string


def show_message():
    msg = request.form.get('message')
    return render_template_string('<div>' + msg + '</div>')

