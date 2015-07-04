import os
import smtplib
from email.mime.text import MIMEText
from uuid import uuid4

import dataset
from pydiscourse.sso import sso_validate, sso_redirect_url
from pydiscourse.exceptions import DiscourseError
from gettext import gettext as _
from flask import Flask, request, render_template, flash, redirect
from itsdangerous import TimestampSigner, SignatureExpired, \
                         base64_encode, base64_decode

from pwd_context import pwd_context

SECRET = os.environ.get('SSO_SECRET')
SOCIALHELP = 'https://socialhelp.sugarlabs.org'
RESET_PASSWORD_TIMEOUT = 24 * 60 * 60
RESET_PASSWORD_EMAIL = 'socialhelp@sugarlabs.org'

SMTP_ADDRESS = 'smtp.sugarlabs.org'
SMTP_PORT = 587
SMTP_USER_NAME = 'socialhelp'
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')


app = Flask(__name__)
app.secret_key = SECRET
app.jinja_env.add_extension('jinja2.ext.i18n')
app.jinja_env.install_null_translations(newstyle=True)
db = dataset.connect('sqlite:////data/data.sqlite')
signer = TimestampSigner(SECRET + 'itsdangerous email signer')


@app.route('/sso/view')
def view():
    if 'nonce' in request.args:
        nonce = request.args.get('nonce')
    else:
        payload = request.args.get('sso')
        signature = request.args.get('sig')
        try:
            nonce = sso_validate(payload, signature, SECRET)
        except DiscourseError as e:
            return render_template('error.html', error=e)
        nonce = nonce.rstrip('&return_sso_url')  # IDK???!!!!

    return render_template('view.html', nonce=nonce)

@app.route('/sso/login', methods=['POST'])
def login():
    nonce = request.form.get('nonce')
    name_or_email = request.form.get('id')
    password = request.form.get('password')
    if not name_or_email or not password or not nonce:
        flash(_('Please enter all fields'))
        return redirect_back()

    info = db['users'].find_one(name=name_or_email) or \
           db['users'].find_one(email=name_or_email)
    if info is None or not pwd_context.verify(password, info['hash']):
        flash(_('Wrong username or password'))
        return redirect_back()

    return user_ok(info)

@app.route('/sso/signup', methods=['POST'])
def signup():
    nonce = request.form.get('nonce')
    name = request.form.get('name')
    password = request.form.get('password')
    if not name or not password or not nonce:
        flash(_('Please enter all fields'))
        return redirect_back()

    email = request.form.get('email')
    coppa_email = False
    if not email:
        # Underage users
        email = 'coppa-user+{}@socialhelp.sugarlabs.org'.format(uuid4())
        coppa_email = True

    if db['users'].find_one(name=name) or db['users'].find_one(email=email):
        flash(_('Username or email already in use'))
        return redirect_back()

    hash = pwd_context.encrypt(password)
    info = dict(name=name, email=email, hash=hash, coppa_email=coppa_email)
    info['id'] = db['users'].insert(info)

    return user_ok(info)


def redirect_back():
    nonce = request.form.get('nonce')
    return redirect('/sso/view?nonce=' + nonce)


def user_ok(info):
    nonce = request.form.get('nonce')
    require_activiation = 'false' if info['coppa_email'] else 'true'
    try:
        url = sso_redirect_url(
            nonce, SECRET, info['email'], info['id'], info['name'],
            require_activation=require_activiation)
    except DiscourseError as e:
        return render_template('error.html', error=e)
    return redirect(SOCIALHELP + url)


@app.route('/sso/request_reset_password', methods=['POST'])
def request_reset_password():
    email = request.form.get('email')
    info = db['users'].find_one(email=email)
    if info is None:
        return render_template('reset_password_sent.html')
    token = base64_encode(signer.sign(email))

    msg = MIMEText(render_template('reset_password.email', token=token))
    msg['Subject'] = _('Password reset')
    msg['From'] = RESET_PASSWORD_EMAIL
    msg['To'] = email

    s = smtplib.SMTP(SMTP_ADDRESS, SMTP_PORT)
    s.starttls()
    s.login(SMTP_USER_NAME, SMTP_PASSWORD)
    s.sendmail(RESET_PASSWORD_EMAIL, [email], msg.as_string())
    s.quit()

    return render_template('reset_password_sent.html')


@app.route('/sso/reset_password')
def reset_password_form():
    token = request.args.get('token')
    return render_template('reset_password.html', token=token)


@app.route('/sso/reset_password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    password = request.form.get('password')
    if not password:
        flash(_('Please enter a new password'))
        return render_template('reset_password.html', token=token)

    try:
        email = signer.unsign(base64_decode(token),
                              max_age=RESET_PASSWORD_TIMEOUT)
    except SignatureExpired as e:
        return render_template('error.html', error=e)

    hash = pwd_context.encrypt(password)
    db['users'].update(dict(email=email, hash=hash), ['email'])
    return render_template('reset_password_success.html')


app.run(debug=False, host='0.0.0.0')
