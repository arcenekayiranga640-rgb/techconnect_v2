from datetime import datetime, timedelta
import json
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'techconnectsupport13@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
mail = Mail(app)

DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'rwanda_locations.json')
if os.path.exists(DATA_PATH):
    with open(DATA_PATH, 'r', encoding='utf-8') as f_json:
        RWANDA_LOCATIONS = json.load(f_json)
else:
    RWANDA_LOCATIONS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/districts/<province>')
def get_districts(province):
    districts = list(RWANDA_LOCATIONS.get(province, {}).get('districts', {}).keys())
    return jsonify(districts)

@app.route('/api/sectors/<province>/<district>')
def get_sectors(province, district):
    sectors = RWANDA_LOCATIONS.get(province, {}).get('districts', {}).get(district, [])
    return jsonify(sectors)

@app.route('/cookie-policy')
def cookie_policy():
    technician = session.get('technician_email')
    return render_template('cookie_policy.html', technician=technician)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
