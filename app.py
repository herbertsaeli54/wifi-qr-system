# -*- coding: utf-8 -*-

import os
os.makedirs('qrcodes', exist_ok=True)
os.makedirs('instance', exist_ok=True)


from flask import Flask, request, jsonify
from collections import defaultdict
from flask import render_template
from flask import Flask, render_template, request,jsonify, redirect, url_for
from flask import render_template
from flask import send_file
from datetime import datetime,timedelta
from flask import send_file
from flask import render_template
from functools import wraps
import qrcode
import base64

from config import Config
from models import db, User, Session

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json

    # Basic validation
    if not data or 'name' not in data or 'email' not in data:
        return jsonify({'error': 'Name and email are required'}), 400


    #checking for existing user
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'error': 'A user with that email already exists'}), 400

    connection_start = datetime.utcnow()
    connection_end = connection_start + timedelta(hours=6)


    name = data['name']
    email = data['email']
    password = data['password']

    new_user = User(name=name, email=email)
    new_user.set_password(password)
    new_user.registered_at = connection_start
    

    db.session.add(new_user)
    db.session.commit()

    qr_data = {
        "user_id": new_user.id,
        "email": new_user.email,
        "valid_from": connection_start.isoformat(),
        "valid_until": connection_end.isoformat()
    }

    session = Session(
        user_id=new_user.id,
        start_time=connection_start,
        end_time=connection_end,
        qr_token=str(qr_data)
    )
    db.session.add(session)
    db.session.commit()

    print('Saved QR Token:', str(qr_data))

    qr = qrcode.make(str(qr_data))
    qr_path = f'qrcodes/user_{new_user.id}.png'
    qr.save(qr_path)

    

    with open(qr_path, "rb") as image_file:
         encoded_qr = base64.b64encode(image_file.read()).decode('utf-8')


    return jsonify({
    'message': 'User registered successfully.',
    'user_id': new_user.id,
    'qr_code_path': qr_path,
    'qr_code_preview': f"data:image/png;base64,{encoded_qr}"

    }),200



@app.route('/download_qr/<int:user_id>', methods=['GET'])
def download_qr(user_id):
    qr_path = f'qrcodes/user_{user_id}.png'
    
    try:
        return send_file(qr_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'QR code not found for this user'}), 40


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect('/admin/dashboard')  # or user dashboard
        else:
            return 'Invalid credentials', 401

    return render_template('login.html')


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function






@app.route('/')
def home():
    return render_template('register.html')  # Or whichever is your main HTML page

@app.route('/active_sessions', methods=['GET'])
def active_sessions():
    now = datetime.utcnow()
    sessions = Session.query.filter(Session.end_time > now).all()
    
    active = []

    for session in sessions:
        user = User.query.get(session.user_id)
        active.append({
            'user_id': user.id,
            'name': user.name,
            'email': user.email,
            'session_start': session.start_time.isoformat(),
            'session_end': session.end_time.isoformat()
        })

    return jsonify(active)

@app.route('/users', methods=['GET'])
def list_users():
    users = User.query.all()
    user_list = []

    for user in users:
        # Check if they have an active session
        session = Session.query.filter_by(user_id=user.id).order_by(Session.end_time.desc()).first()
        session_info = None

        if session:
            session_info = {
                'session_start': session.start_time.isoformat(),
                'session_end': session.end_time.isoformat(),
                'qr_token': session.qr_token
            }

        user_list.append({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'registered_at': user.registered_at.isoformat(),
            'session': session_info
        })

    return jsonify(user_list)




@app.route('/cleanup_sessions', methods=['POST'])
def cleanup_sessions():
    now = datetime.utcnow()
    expired_sessions = Session.query.filter(Session.end_time < now).all()

    count = len(expired_sessions)
    for session in expired_sessions:
        db.session.delete(session)

    db.session.commit()

    return jsonify({'message': f'{count} expired session(s) deleted.'})




@app.route('/admin/users', methods=['GET'])
def admin_list_users():
    users = User.query.all()
    user_data = []

    for user in users:
        sessions = Session.query.filter_by(user_id=user.id).all()
        session_info = [{
            'start_time': s.start_time.isoformat(),
            'end_time': s.end_time.isoformat(),
            'qr_token': s.qr_token
        } for s in sessions]

        user_data.append({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'registered_at': user.registered_at.isoformat(),
            'sessions': session_info
        })

    return jsonify({'users': user_data})

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle form data
        ...
    return render_template('register.html')



@app.route('/dashboard')
def dashboard():
    # Example dummy data – replace with your real query later
    dates = ['2025-05-15', '2025-05-16', '2025-05-17']
    counts = [4, 7, 2]

    return render_template('admin_dashboard.html', dates=dates, counts=counts)




@app.route('/validate_qr', methods=['POST'])
def validate_qr():
    data = request.get_json()
    qr_token = data.get('qr_token')

    if not qr_token:
        return jsonify({'error': 'Missing QR token'}), 400


    session = Session.query.filter_by( qr_token=qr_token).first()

    if not session:
        return jsonify({'message': 'Invalid QR code'}), 400

    now = datetime.utcnow()
    if session.start_time <= now <= session.end_time:
        return jsonify({'message': 'QR code is valid','user_id': session.user_id}), 200
    else:
        return jsonify({'message': 'QR code has expired'}), 403




@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Delete all sessions for this user
    Session.query.filter_by(user_id=user_id).delete()

    # Delete user
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'User {user_id} and sessions deleted successfully.'})

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_users(user_id):
    user = User.query.get(user_id)
    session = Session.query.filter_by(user_id=user_id).first()
    if session:
        db.session.delete(session)
    if user:
        db.session.delete(user)
    db.session.commit()
    return redirect('/admin/dashboard')

@app.route('/admin/regenerate_qr/<int:user_id>', methods=['POST'])
def regenerate_qr(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    connection_start = datetime.utcnow()
    connection_end = connection_start + timedelta(hours=6)
    
    qr_data = {
        "user_id": user.id,
        "email": user.email,
        "valid_from": connection_start.isoformat(),
        "valid_until": connection_end.isoformat()
    }

    session = Session.query.filter_by(user_id=user.id).first()
    if session:
        session.start_time = connection_start
        session.end_time = connection_end
        session.qr_token = str(qr_data)
    else:
        session = Session(
            user_id=user.id,
            start_time=connection_start,
            end_time=connection_end,
            qr_token=str(qr_data)
        )
        db.session.add(session)

    qr = qrcode.make(str(qr_data))
    qr_path = f'qrcodes/user_{user.id}.png'
    qr.save(qr_path)

    db.session.commit()
    return redirect('/admin/dashboard')



@app.route('/admin/dashboard')
def admin_dashboard():
    search_query = request.args.get('search', '')
    users = User.query
    if search_query:
        users = users.filter(User.name.contains(search_query) | User.email.contains(search_query))
    users = users.order_by(User.registered_at.desc()).all()

    sessions = Session.query.all()
    session_map = {s.user_id: s for s in sessions}

    # Stats
    total_users = User.query.count()
    total_sessions = Session.query.count()
    now = datetime.utcnow()
    active_sessions = Session.query.filter(Session.start_time <= now, Session.end_time >= now).count()
    expired_sessions = total_sessions - active_sessions

    # User registrations for chart
    daily_counts = db.session.query(
        db.func.date(User.registered_at),
        db.func.count(User.id)
    ).group_by(db.func.date(User.registered_at)).all()

    dates = [str(row[0]) for row in daily_counts]
    counts = [row[1] for row in daily_counts]

    return render_template('admin_dashboard.html',
                           users=users,
                           session_map=session_map,
                           total_users=total_users,
                           active_sessions=active_sessions,
                           expired_sessions=expired_sessions,
                           dates=dates,
                           counts=counts,
                           search_query=search_query)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



