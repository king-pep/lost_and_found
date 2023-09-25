import json
import logging
import os
import re
import time
import uuid
from datetime import datetime
from datetime import timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
from secrets import token_urlsafe

import flask
import numpy as np
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, render_template, redirect, url_for, flash, jsonify, g, current_app, abort, Response, request
from flask import session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail
from flask_migrate import Migrate
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer
from keras.src.applications import MobileNetV2
from keras.src.applications.convnext import preprocess_input, decode_predictions
from prometheus_client import Histogram, generate_latest, REGISTRY, Counter
from sqlalchemy import or_, and_
from sqlalchemy.exc import IntegrityError
from termcolor import colored
from werkzeug.utils import secure_filename

from config import Config
from forms import RegistrationForm, LoginForm, ItemForm, AdminRegistrationForm, ResetPasswordForm
from models import User, db, Item, Message, Conversation, Claim  # Import db from models
from PIL import Image

# from keras.preprocessing import image as kimage
# from keras.applications.vgg16 import VGG16, preprocess_input
# import numpy as np
# from sklearn.metrics.pairwise import cosine_similarity
logs = []
app = Flask(__name__)
app.config.from_object(Config)
app.config['MAIL_DEBUG'] = True
mail = Mail(app)
socketio = SocketIO(app)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress warning

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

db.init_app(app)  # Bind the app to the db
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# metrics = PrometheusMetrics(app)
# metrics = PrometheusMetrics(app)
s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
logging.basicConfig(level=logging.INFO)
# Load the pre-trained MobileNetV2 model + higher level layers
model = MobileNetV2()
last_notified = {}
app.logger.info(colored('Your Application startup', 'green'))
ITEMS_PER_PAGE = 10

# model = VGG16(weights='imagenet', include_top=False)

# # Define the templates
# user_template = "INSERT INTO user (first_name, last_name, username, email, phone, password, is_admin, email_verified, profile_visibility, created_at, is_active) VALUES ('{first_name}', '{last_name}', '{username}', '{email}', '{phone}', '{hashed_password}', {is_admin}, {email_verified}, '{profile_visibility}', '{created_at}', {is_active});"
# item_template = "INSERT INTO item (name, description, category, location, user_id, type, created_at, time, is_verified, image_file) VALUES ('{name}', '{description}', '{category}', '{location}', {user_id}, '{type}', '{created_at}', '{time}', {is_verified}, '{image_file}');"
#
# # Categories from the form
# categories = ['Electronics', 'Clothes', 'Accessories', 'Vehicle', 'Books', 'Stationery', 'Wallet', 'Jewellery', 'Keys',
#               'Documents', 'Others']
#
# # Generate the SQL
# user_sql = []
# item_sql = []
#
# for i in range(1, 51):
#     password = f'password{i}'
#     hashed_password = generate_password_hash(password)
#     created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
#
#     user_sql.append(user_template.format(first_name=f'First{i}', last_name=f'Last{i}', username=f'user{i}',
#                                          email=f'user{i}@example.com', phone=f'123456789{i}',
#                                          hashed_password=hashed_password, is_admin='FALSE', email_verified='FALSE',
#                                          profile_visibility='public', created_at=created_at, is_active='TRUE'))
#
#     # Choose a category from the list of categories
#     category = categories[i % len(categories)]
#
#     item_sql.append(
#         item_template.format(name=f'Item{i}', description=f'Item{i} Description', category=category,
#                              location=f'Location{i}', user_id=i, type='lost', created_at=created_at, time=created_at,
#                              is_verified='FALSE', image_file='default.jpg'))
#
# # Output the SQL
# print("\n".join(user_sql))
# print("\n".join(item_sql))

# setup production metrics via Prometheus.
# metrics.info('app_info', 'Application info', version='1.0.3')
#
# # setup some standard metrics
# metrics.info('requests_by_status_and_path', 'Request latencies by status and path',
#              labels={'status': lambda r: r.status_code, 'path': lambda: request.path})
# metrics.info('requests_by_method_and_path', 'Request latencies by method and path',
#              labels={'method': lambda: request.method, 'path': lambda: request.path})
# metrics.info('requests_by_status', 'Request latencies by status',
#              labels={'status': lambda r: r.status_code})
# metrics.info('requests_by_method', 'Request latencies by method',
#              labels={'method': lambda: request.method})
# metrics.info('requests_by_path', 'Request latencies by path',
#              labels={'path': lambda: request.path})
# metrics.info('requests_by_endpoint', 'Request latencies by endpoint',
#              labels={'endpoint': lambda: request.endpoint})
#
# # setup the summary histogram for requests
# metrics.info('requests_latency', 'Request latency in seconds',
#              labels={'method': lambda: request.method, 'path': lambda: request.path})
#
# # setup the endpoint for the health check
# metrics.info('health', 'Health status of the service')
#
# if not app.debug:
#     if not os.path.exists('logs'):
#         os.mkdir('logs')
#     file_handler = RotatingFileHandler('logs/system.log', maxBytes=10240, backupCount=3)
#     file_handler.setFormatter(logging.Formatter(
#         '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
#     file_handler.setLevel(logging.INFO)
#     app.logger.addHandler(file_handler)
#
#     app.logger.setLevel(logging.INFO)
#     app.logger.info('Your Application startup')

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/system.log', maxBytes=10240, backupCount=3)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info(colored('Your Application startup', 'green'))


def log_message(level, message):
    color = 'white'  # default color
    if level == 'INFO':
        color = 'green'
    elif level == 'WARNING':
        color = 'yellow'
    elif level == 'ERROR':
        color = 'red'
    elif level == 'DEBUG':
        color = 'blue'

    app.logger.log(logging.getLevelName(level), colored(message, color))


# Usage
log_message('INFO', 'This is an info message')
log_message('ERROR', 'This is an error message')
log_message('WARNING', 'This is a warning message')
log_message('DEBUG', 'This is a debug message')

# Define your metrics here
http_requests_total = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint'])
request_duration_seconds = Histogram('request_duration_seconds', 'Histogram of requests duration (s)')


@app.route('/metrics', methods=['GET'])
def metrics():
    return Response(generate_latest(REGISTRY), mimetype='text/plain')


@app.before_request
def before_request():
    flask.g.start_time = time.time()


@app.after_request
def increment_request_count(response):
    http_requests_total.labels(method=request.method, endpoint=request.endpoint).inc()
    request_duration_seconds.observe(time.time() - flask.g.start_time)
    return response


@app.route('/health', methods=['GET'])
def health():
    return jsonify(status='UP'), 200


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)
    session.modified = True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def landing_page():
    logging.info("Landing page accessed")

    with open('features.json', 'r') as f:
        features = json.load(f)
    return render_template('landing_page.html', features=features)


@app.route('/portal')
def portal():
    logging.info("Portal accessed")
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    from flask_mail import Message
    logging.info("Register route accessed")

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            profile_visibility=form.profile_visibility.data,
            is_admin=False,
            is_active=False
        )
        user.set_password(form.password.data)

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists, please choose another one.', 'danger')
            return render_template('register.html', form=form)

        token = s.dumps(user.email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message("Confirm your email",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[user.email])
        msg.body = f"""Dear {user.first_name} {user.last_name},

Thank you for registering. To complete your registration, 
please click on the link below to confirm your email address:

{confirm_url}

The link will expire in 1 hour.

Best regards,
The Support Team"""
        mail.send(msg)

        flash('A confirmation email has been sent to your email address. Please confirm your email to proceed.',
              'success')
        return redirect(url_for('email_sent'))
    logging.info("Registration successful for username: %s", form.username.data)

    return render_template('register.html', form=form)


@app.route("/email_sent")
def email_sent():
    logging.info("Email sent page accessed")
    return render_template('email_sent.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return render_template('email_confirmation_fail.html')

    user = User.query.filter_by(email=email).first()

    if user:
        user.email_verified = True  # Assuming you have this field in your model
        db.session.commit()
        flash('Your email has been verified!', 'success')
        return render_template('email_confirmation_success.html')
    else:
        flash('User not found.', 'danger')
        return render_template('email_confirmation_fail.html')


@login_manager.unauthorized_handler
def unauthorized():
    # Store the original URL the user was trying to access
    logging.info("Unauthorized request")
    session['next_url'] = request.url
    return redirect(url_for('login'))


@app.route('/logs_and_audits')
def logs_and_audits():
    log_file_path = 'logs/system.log'

    try:
        with open(log_file_path, 'r') as file:
            raw_logs = file.readlines()
    except FileNotFoundError:
        raw_logs = ['ERROR Log file not found.']

    log_pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (?P<level>INFO|WARNING|ERROR): (?P<message>.+)')

    for raw_log in raw_logs:
        match = log_pattern.search(raw_log)
        if match:
            logs.append({
                'timestamp': match.group('timestamp'),
                'level': match.group('level'),
                'message': match.group('message').strip()
            })

    return render_template('logs_and_audits.html', logs=logs, active_page='logs_and_audits')


@app.route('/change_log_level/<logId>/<newLevel>', methods=['POST'])
def change_log_level(logId, newLevel):
    global logs
    for log in logs:
        if log['id'] == logId:
            log['level'] = newLevel
            return jsonify(success=True)
    return jsonify(success=False, error='Log not found'), 404


@app.errorhandler(404)
def page_not_found(e):
    logging.error("404 error encountered: %s", str(e))
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    logging.error("500 error encountered: %s", str(e))
    return render_template('500.html'), 500


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print(f"Session data before login: {session}")  # Debugging line
    if form.validate_on_submit():
        print("Form Validated")  # Debugging line
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print(f"User found: {user.username}")  # Debugging line
            if user.check_password(form.password.data):
                user.last_login = datetime.utcnow()
                db.session.commit()
                print("Password correct")  # Debugging line
                if user.email_verified:
                    login_user(user)
                    user.is_active = True
                    db.session.commit()
                    print(f"Is user logged in? {current_user.is_authenticated}")  # Debugging line
                    next_url = session.pop('next_url', None) or url_for('dashboard')
                    print(f"Next URL from session: {next_url}")  # Debugging line
                    if next_url == url_for('logout'):
                        print("Next URL is logout, setting it to dashboard")  # Debugging line
                        next_url = url_for('dashboard')
                    print(f"Redirecting to {next_url}")  # Debugging line
                    return redirect(next_url)

                else:
                    print("Email not verified")  # Debugging line
                    flash('Your email has not been verified. Please check your inbox.', 'warning')
            else:
                print("Password incorrect")  # Debugging line
                flash('Incorrect password. Please try again.', 'danger')
        else:
            print("User not found")  # Debugging line
            flash('This email is not registered. Please check or register a new account.', 'danger')
    else:
        print(f"Form Errors: {form.errors}")  # Debugging line
    return render_template('login.html', form=form)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    from flask_mail import Message

    if request.method == 'POST':
        email = request.form.get('email')
        # Find user by email
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate reset token
            token = user.get_reset_token()

            # Send reset email
            msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}
If you did not make this request, please ignore this email.
'''
            mail.send(msg)
            flash('A password reset link has been sent to your email address', 'info')
            return redirect(url_for('login'))

        else:
            flash('No account found with that email address', 'error')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = User.set_password(form.password.data)
        user.password = hashed_password
        db.session.commit()
        login_user(user)
        flash('Your password has been updated! You are now logged in.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('reset_password.html', title='Reset Password', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/dashboard")
@login_required
def dashboard():
    # Query both lost and found items reported by the user
    lost_items = Item.query.filter_by(user_id=current_user.id, type='lost').all()
    found_items = Item.query.filter_by(user_id=current_user.id, type='found').all()

    # Initialize dictionaries to hold the items and their associated claim status
    lost_items_with_status = {}
    found_items_with_status = {}

    # Loop through the lost items and retrieve the associated claim status
    for item in lost_items:
        claim = Claim.query.filter_by(item_id=item.id).first()
        status = claim.status if claim else "Not Claimed"
        lost_items_with_status[item] = status

    # Loop through the found items and retrieve the associated claim status
    for item in found_items:
        claim = Claim.query.filter_by(item_id=item.id).first()
        status = claim.status if claim else "Not Claimed"
        found_items_with_status[item] = status

    return render_template(
        'dashboard.html',
        lost_items_with_status=lost_items_with_status,
        found_items_with_status=found_items_with_status
    )


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.before_request
def before_request():
    if current_user.is_authenticated:
        g.unread_messages_count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    else:
        g.unread_messages_count = 0


@app.context_processor
def inject_unread_messages_count():
    if current_user.is_authenticated:
        unread_messages_count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    else:
        unread_messages_count = 0
    return dict(unread_messages_count=unread_messages_count)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def extract_keywords(text):
    return set(re.findall(r'\w+', text.lower()))


def notify_user(user, similar_items):
    if user.id in last_notified and (datetime.utcnow() - last_notified[user.id]).days < 1:
        return  # Do not notify the user if we've notified them within the last day

    msg = Message('Potential Matches Found', sender=current_app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = "We found potential matches for your items:\n"

    for item in similar_items:
        item_link = url_for('item_details', item_id=item.id, _external=True)
        msg.body += f"Item ID: {item.id}, Description: {item.description}, [View Item]({item_link})\n"

    mail.send(msg)
    last_notified[user.id] = datetime.utcnow()


def find_similar_items(new_item):
    one_month_ago = datetime.utcnow() - timedelta(days=30)
    query = Item.query.filter(Item.time >= one_month_ago)

    if new_item.type == 'lost':
        query = query.filter_by(type='found')
    else:
        query = query.filter_by(type='lost')

    all_items = query.all()
    similar_items = []

    new_item_keywords = extract_keywords(new_item.description)

    for item in all_items:
        if item.id == new_item.id:
            continue

        item_keywords = extract_keywords(item.description)
        common_keywords = item_keywords & new_item_keywords
        total_keywords = item_keywords | new_item_keywords

        if total_keywords and len(common_keywords) / len(total_keywords) >= 0.5:
            similar_items.append(item)

    return similar_items


# def check_for_potential_matches(new_item):
#     all_items = Item.query.all()
#
#     new_item_keywords = extract_keywords(new_item.description)
#
#     similar_items = []
#
#     for item in all_items:
#         if item.id == new_item.id:
#             continue  # Skip the item itself
#
#         item_keywords = extract_keywords(item.description)
#
#         # Calculate the overlap as a percentage
#         common_keywords = item_keywords & new_item_keywords
#         total_keywords = item_keywords | new_item_keywords
#
#         if len(total_keywords) == 0:
#             continue
#
#         overlap = len(common_keywords) / len(total_keywords)
#
#         # If the overlap is more than 50%, consider it a potential match
#         if overlap >= 0.5:
#             similar_items.append(item)
#             # Create a new Notification
#             notification = Notification(
#                 user_id=item.owner_id,
#                 message=f"A potential match for your item has been found!",
#                 item_id=new_item.id
#             )
#             db.session.add(notification)
#
#     if similar_items:
#         # Commit the transaction
#         db.session.commit()
#
#         # Notify the user (this function will be implemented next)
#         notify_user_of_potential_matches(new_item.owner, similar_items)


def save_image(image):
    # Generate a unique filename by appending a UUID
    unique_filename = f"{uuid.uuid4().hex}_{secure_filename(image.filename)}"
    logging.info(f"Saving image: {unique_filename}")
    # Save the image
    image_path = os.path.join(app.config['IMAGE_UPLOAD_FOLDER'], unique_filename)
    image.save(image_path)

    return unique_filename


@app.route('/notifications')
@login_required
def notifications():
    # Your logic to fetch and display notifications here
    return render_template('notifications.html')


@app.route('/all_conversations', methods=['GET'])
@login_required
def all_conversations():
    # Fetch all unique users who have had a conversation with the current user.
    involved_users = set()
    conversations = Message.query.filter(
        or_(Message.sender_id == current_user.id, Message.receiver_id == current_user.id)
    ).all()

    for conversation in conversations:
        involved_users.add(conversation.sender)
        involved_users.add(conversation.receiver)

    involved_users.discard(current_user)  # Remove the current user from the set

    # Add additional details to each user object
    for user in involved_users:
        last_message_obj = Message.query.filter(
            or_(and_(Message.sender_id == current_user.id, Message.receiver_id == user.id),
                and_(Message.sender_id == user.id, Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()

        user.last_message = last_message_obj.content if last_message_obj else None
        user.last_message_time = last_message_obj.timestamp if last_message_obj else None

        user.unread_count = Message.query.filter_by(
            sender_id=user.id, receiver_id=current_user.id, is_read=False
        ).count()

    return render_template('all_conversations.html', involved_users=involved_users)


@app.route("/report_item", methods=['GET', 'POST'])
@login_required
def report_item():
    form = ItemForm()
    if form.validate_on_submit():
        # Handle image upload
        image_filename = None
        if form.image.data:
            image_filename = save_image(form.image.data)

        # Explicitly convert the time string to a datetime object
        report_time = None
        if form.time.data:
            try:
                report_time = datetime.strptime(form.time.data, "%Y-%m-%dT%H:%M")
            except Exception as e:
                print(f"Error converting time: {e}")
        else:
            report_time = datetime.utcnow()

        # Debugging print statements to check data types
        print(f"Form time data type: {type(form.time.data)}")
        print(f"Converted report_time data type: {type(report_time)}")

        # Create the item with the converted datetime
        item = Item(
            name=form.name.data,
            description=form.description.data,
            category=form.category.data,
            location=form.location.data,
            type=form.type.data,  # Add this line
            image_file=image_filename,
            user_id=current_user.id,
            time=report_time,  # Set the time
            is_verified=False
        )

        db.session.add(item)
        db.session.commit()

        flash('Your item has been reported!', 'success')

        # Check for potential matches and notify the user if any are found
        similar_items = find_similar_items(item)
        if similar_items:
            notify_user(current_user, similar_items)

        return redirect(url_for('dashboard'))
    else:
        print(form.errors)

    return render_template('report_item.html', form=form)


@app.route("/find_matches", methods=['POST'])
@login_required
def find_matches():
    # Getting the data from a form
    description = request.form.get('description')
    category = request.form.get('category')
    location = request.form.get('location')

    # Step 1: Database Querying
    # Find items that match the category and location
    potential_matches = Item.query.filter_by(category=category, location=location).all()

    # Additionally, filter by a substring of the description if needed:
    # potential_matches = Item.query.filter(Item.description.contains(description), Item.category==category, Item.location==location).all()

    # Step 2: Thresholds and Rankings
    # Rank the matches based on the number of matching fields
    ranked_matches = []
    for item in potential_matches:
        rank = 0
        if category and item.category == category:
            rank += 1
        if location and item.location == location:
            rank += 1
        if description and description.lower() in item.description.lower():
            rank += 1
        ranked_matches.append((item, rank))

    # Sort the matches based on the rank
    ranked_matches.sort(key=lambda x: x[1], reverse=True)

    # Extract the sorted items
    sorted_items = [item[0] for item in ranked_matches]

    return render_template('matches.html',
                           items=sorted_items)


@app.route('/search', methods=['POST'])
def search():
    search_type = request.form.get('search_type')  # This should get the value "lost" or "found" from the dropdown
    item_query = request.form.get('item_query')
    location_query = request.form.get('location_query')

    # Filter items based on the type (lost or found)
    items = Item.query.filter_by(type=search_type, is_verified=True)

    if item_query:
        items = items.filter(Item.description.contains(item_query))

    if location_query:
        items = items.filter(Item.location.contains(location_query))

    results = items.all()

    # Render a template to display the results or send the results as JSON, based on your preference
    return render_template('search_results.html', results=results)


@app.route('/search_results', methods=['GET'])
def search_results():
    search_type = request.args.get('search_type')  # Use request.args.get() for GET requests
    item_query = request.args.get('item_query')
    location_query = request.args.get('location_query')

    # Build the query
    query = Item.query.filter_by(is_verified=True)

    if search_type:
        query = query.filter(Item.type == search_type)

    if item_query:
        query = query.filter(Item.description.like(f"%{item_query}%"))

    if location_query:
        query = query.filter(Item.location.like(f"%{location_query}%"))

    items = query.all()

    # print the item using loop
    for item in items:
        print(item.name)

    return render_template('search_results.html', items=items, search_type=search_type,
                           item_query=item_query, location_query=location_query)


@app.route('/load_more', methods=['GET'])
def load_more():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category')
    location = request.args.get('location')

    # Debug Prints
    print("Page:", page)
    print("Category:", category)
    print("Location:", location)

    query = Item.query.filter_by(is_verified=True)

    if category and category != "":
        query = query.filter(Item.category == category)
    if location and location != "":
        query = query.filter(Item.location.like(f"%{location}%"))

    items = query.paginate(page=page, per_page=10, error_out=False).items

    items_list = [
        {
            'id': item.id,
            'description': item.description,
            'category': item.category,
            'location': item.location,
            'time': item.time.strftime('%Y-%m-%d %H:%M'),
            'image_file': url_for('static', filename='images/' + item.image_file) if item.image_file else None
        }
        for item in items
    ]

    return jsonify(items_list)



@app.route('/item_details/<int:item_id>', methods=['GET'])
def item_details(item_id):
    item = Item.query.get(item_id)  # Fetch item from the database using the item_id
    if not item:
        flash('Item not found!', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('item_details.html', item=item)


@app.route('/start_conversation/<int:reporter_id>', methods=['GET'])
def start_conversation(reporter_id):
    # Check if conversation already exists
    existing_conversation = Conversation.query.filter_by(
        user1_id=current_user.id,
        user2_id=reporter_id
    ).first()

    if not existing_conversation:
        new_conversation = Conversation(user1_id=current_user.id, user2_id=reporter_id)
        db.session.add(new_conversation)
        db.session.commit()
        return redirect(url_for('conversation', conversation_id=new_conversation.id))

    return redirect(url_for('conversation', conversation_id=existing_conversation.id))


@app.route('/send_message/<int:conversation_id>', methods=['POST'])
def send_message(conversation_id):
    # Create a new message for the conversation
    # Return to the conversation page
    pass


@app.route('/conversation/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def conversation(receiver_id):
    if current_user.id == receiver_id:
        flash('You cannot have a conversation with yourself.', 'warning')
        return redirect(url_for('dashboard'))  # Or wherever you want to redirect in case of error

    other_user = User.query.get_or_404(receiver_id)

    if request.method == 'POST':
        message_content = request.form.get('message_content')
        if message_content:
            message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=message_content)
            db.session.add(message)
            db.session.commit()
            return redirect(url_for('conversation',
                                    receiver_id=receiver_id))  # Redirect to GET after POST to avoid form resubmission issues

    messages = Message.query.filter(
        db.or_(
            db.and_(Message.sender_id == current_user.id, Message.receiver_id == receiver_id),
            db.and_(Message.sender_id == receiver_id, Message.receiver_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    # Mark all messages from the other user to the current user as read
    unread_messages = Message.query.filter_by(sender_id=receiver_id, receiver_id=current_user.id, is_read=False).all()
    for message in unread_messages:
        message.is_read = True
    db.session.commit()

    return render_template('conversation.html', other_user=other_user, messages=messages)


@app.route('/check_new_messages')
@login_required
def check_new_messages():
    unread_messages_count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    return jsonify(new_messages=unread_messages_count)


@app.route('/get_unread_messages_count')
@login_required
def get_unread_messages_count():
    unread_messages_count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    return jsonify(unread_messages_count=unread_messages_count)


@socketio.on('send_message')
def handle_message(data):
    # Your message handling code here
    sender_id = current_user.id
    receiver_id = data['receiver_id']
    message_content = data['message_content']

    new_message = Message(sender_id=sender_id, receiver_id=receiver_id, content=message_content)
    db.session.add(new_message)
    db.session.commit()

    # Emit a message to update the chat on the receiver's side
    socketio.emit('receive_message', data)

    unread_messages = Message.query.filter_by(sender_id=receiver_id, receiver_id=current_user.id, is_read=False).all()
    for message in unread_messages:
        message.is_read = True
    db.session.commit()
    # Emit an event to update the unread message count
    socketio.emit('update_unread_count')


@app.route('/claim_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def claim_item(item_id):
    from flask_mail import Message

    if request.method == 'POST':
        submitted_proof_file = request.files['submitted_proof_file']

        if submitted_proof_file and submitted_proof_file.filename != '':
            filename = secure_filename(submitted_proof_file.filename)
            submitted_proof_file.save(os.path.join(app.config['CLAIMS_DOCUMENT_UPLOAD_FOLDER'], filename))

            try:
                claim = Claim(item_id=item_id, user_id=current_user.id, claim_status='PENDING',
                              submitted_proof=filename)
                db.session.add(claim)
                db.session.commit()

                # Professional Email Notification
                msg = Message("Your Claim Submission: Status Pending",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=['benam.telkom@gmail.com'])
                msg.body = f"""Dear {current_user.username},
We have successfully received your claim submission for Item ID: {item_id}.

Status: PENDING

Your claim is currently under review. We will notify you once the status changes.

Thank you for using our service.

Best regards,
The Support Team
"""

                mail.send(msg)

                # Return a JSON response
                return jsonify({'status': 'success'})

            except Exception as e:
                print(f"An error occurred: {e}")
                return jsonify({'status': 'error'})
        else:
            return jsonify({'status': 'no_file'})

    return render_template('claim_item.html', item_id=item_id)


@app.route('/manage_claims')
def manage_claims():
    print(request.args.get('status'))
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', None)

    if status == 'Verified' or status == 'Rejected' or status == 'Pending':
        claims = Claim.query.filter_by(claim_status=status).paginate(page=page, per_page=10)
    else:
        claims = Claim.query.paginate(page=page, per_page=10)

    return render_template('manage_claims.html', claims=claims, active_page='manage_claims', status=status)


@app.route('/verify_claim/<int:claim_id>', methods=['POST'])
def verify_claim(claim_id):
    from flask_mail import Message
    claim = Claim.query.get_or_404(claim_id)
    try:
        claim.claim_status = 'Verified'
        db.session.commit()

        # Send Email Notification
        msg = Message("Claim Status Updated", sender=app.config['MAIL_USERNAME'], recipients=[claim.user.email])
        msg.body = f"Your claim with ID {claim_id} has been verified."
        mail.send(msg)

        flash('Claim has been verified and user has been notified.', 'success')
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while verifying the claim. Please try again.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    from flask import send_from_directory

    return send_from_directory(app.config['CLAIMS_DOCUMENT_UPLOAD_FOLDER'], filename)


@app.route('/reject_claim/<int:claim_id>', methods=['POST'])
def reject_claim(claim_id):
    from flask_mail import Message
    claim = Claim.query.get_or_404(claim_id)
    try:
        claim.claim_status = 'Rejected'
        db.session.commit()

        # Send Email Notification
        msg = Message("Claim Status Updated", sender=app.config['MAIL_USERNAME'], recipients=[claim.user.email])
        msg.body = f"Your claim with ID {claim_id} has been rejected."
        mail.send(msg)

        flash('Claim has been rejected and user has been notified.', 'success')
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while rejecting the claim. Please try again.', 'error')
    return redirect(url_for('admin_dashboard'))


# def extract_features(img_path):
#     img = kimage.load_img(img_path, target_size=(224, 224))
#     img_array = kimage.img_to_array(img)
#     img_array = np.expand_dims(img_array, axis=0)
#     img_array = preprocess_input(img_array)
#     features = model.predict(img_array)
#     return features.flatten()
#
#
# def find_matching_images(uploaded_img_path, features_db):
#     uploaded_img_features = extract_features(uploaded_img_path)
#     matching_images = []
#     for img_name, features in features_db.items():
#         similarity = cosine_similarity([uploaded_img_features], [features])
#         if similarity[0][0] > 0.7:  # for example, if similarity is more than 70%
#             matching_images.append(img_name)
#     return matching_images

#
@app.route('/image_recognition', methods=['GET', 'POST'])
def image_recognition():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['IMAGE_UPLOAD_FOLDER'], filename)
            file.save(filepath)

            img = Image.open(filepath)
            if img.mode == 'RGBA':
                img = img.convert('RGB')  # Convert RGBA to RGB
            img = img.resize((224, 224))
            img_array = np.array(img)[np.newaxis, ...]
            img_array = preprocess_input(img_array)

            predictions = model.predict(img_array)
            results = decode_predictions(predictions)[0]  # Removed .numpy()

            return render_template('image_recognition.html', results=results)

    return render_template('image_recognition.html')


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # Forbidden access
        return f(*args, **kwargs)

    return decorated_function


@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    try:
        claim_page = request.args.get('claim_page', 1, type=int)
        user_page = request.args.get('user_page', 1, type=int)
        item_page = request.args.get('item_page', 1, type=int)

        claims = Claim.query.filter_by(claim_status='PENDING').paginate(page=claim_page, per_page=10)
        users = User.query.paginate(page=user_page, per_page=10)
        items = Item.query.paginate(page=item_page, per_page=10)

        return render_template('admin_dashboard.html', users=users, items=items, User=User, claims=claims,
                               active_page='admin_dashboard')
    except Exception as e:
        print(f"Error occurred: {e}")
        flash('An error occurred. Please try again later.', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str)

    if search_term:
        users = User.query.filter(
            or_(
                User.first_name.ilike(f"%{search_term}%"),
                User.last_name.ilike(f"%{search_term}%"),
                User.email.ilike(f"%{search_term}%"),
                User.username.ilike(f"%{search_term}%")
            )
        ).paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)
    else:
        users = User.query.paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)

        if action == "deactivate":
            user.is_active = False
        elif action == "activate":
            user.is_active = True
        elif action == "make_admin":
            user.is_admin = True
        elif action == "remove_admin":
            user.is_admin = False

        db.session.commit()
        return redirect(url_for('manage_users', search=search_term))

    return render_template('admin_manage_users.html', users=users, active_page='manage_users', search_term=search_term)


@app.route('/admin/manage_items', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_items():
    page = request.args.get('page', 1, type=int)
    item_search = request.args.get('item_search', '', type=str)

    # Server-side search functionality
    if item_search:
        items_query = Item.query.filter(Item.description.contains(item_search))
    else:
        items_query = Item.query

    pagination = items_query.paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)
    items = pagination.items  # items for the current page

    if request.method == 'POST':
        print("POST request received")  # Debugging print
        action = request.form.get('action')
        selected_items = request.form.getlist('selected_items')  # getlist for multiple items
        print(f"Action: {action}, Selected Items: {selected_items}")  # Debugging print

        # Handle bulk actions
        if action in ["verify_selected", "delete_selected"]:
            for item_id in selected_items:
                item = Item.query.get(item_id)
                if action == "verify_selected":
                    item.is_verified = True
                    flash(f'Item {item_id} has been verified', 'success')
                elif action == "delete_selected":
                    db.session.delete(item)
                    flash(f'Item {item_id} has been deleted', 'success')

        # Single item actions
        else:
            item_id = request.form.get('item_id')
            print(f"Received item_id: {item_id}")  # Debug
            item = Item.query.get(item_id)
            print(f"Item ID: {item_id}, Item: {item}")  # Debugging print
            if action == "verify":
                item.is_verified = True
                print("Item verified")  # Debugging print
                flash('Item has been verified', 'success')
            elif action == "delete":
                db.session.delete(item)
                flash('Item has been deleted', 'success')

        db.session.commit()
        return redirect(url_for('manage_items', page=page, item_search=item_search))

    return render_template(
        'admin_manage_items.html',
        items=items,
        pagination=pagination,
        active_page='manage_items',
        item_search=item_search  # Pass the current search term back to the template
    )


@app.route('/admin/statistics')
@login_required
@admin_required
def statistics():
    total_users = User.query.count()
    total_items = Item.query.count()
    total_messages = Message.query.count()
    # Add more statistics as needed

    return render_template('admin_statistics.html', total_users=total_users, total_items=total_items,
                           total_messages=total_messages, active_page='statistics')


# Function to generate and print a new token every hour
def generate_and_print_token():
    global admin_registration_token
    admin_registration_token = token_urlsafe(16)
    print(admin_registration_token)


# Generate a secure token and print it. Store this somewhere safe!
admin_registration_token = token_urlsafe(16)
print(admin_registration_token)
scheduler = BackgroundScheduler()
scheduler.add_job(generate_and_print_token, 'interval', hours=1)
scheduler.start()


# @app.teardown_appcontext
# def shutdown_scheduler(response_or_exc):
#     scheduler.shutdown()


@app.route('/register_admin/<token>', methods=['GET', 'POST'])
def register_admin(token):
    if token != admin_registration_token:
        abort(403)  # Forbidden

    form = AdminRegistrationForm()  # This form can be similar to your regular registration form

    if form.validate_on_submit():
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            email_verified=True,
            is_admin=True
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Admin registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register_admin.html', form=form)


@app.route('/user_detail/<int:user_id>', methods=['GET'])
@login_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    # Further code to load user details and render a template
    return render_template('user_detail.html', user=user)


@app.route('/admin/metrics')
@login_required
@admin_required
def admin_metrics():
    # User metrics
    total_users = User.query.count()
    recent_users = User.query.filter(User.created_at > datetime.utcnow() - timedelta(days=7)).count()
    recent_logins = User.query.filter(User.last_login > datetime.utcnow() - timedelta(days=1)).count()

    # Item metrics
    total_items = Item.query.count()
    recent_items = Item.query.filter(Item.created_at > datetime.utcnow() - timedelta(days=7)).count()
    items_by_category = db.session.query(Item.category, db.func.count(Item.category)).group_by(Item.category).all()
    verified_items = Item.query.filter_by(is_verified=True).count()
    unverified_items = total_items - verified_items

    return render_template('admin_metrics.html', total_users=total_users, recent_users=recent_users,
                           recent_logins=recent_logins, total_items=total_items,
                           recent_items=recent_items, items_by_category=items_by_category,
                           verified_items=verified_items,
                           unverified_items=unverified_items,
                           active_page='admin_metrics')


for rule in app.url_map.iter_rules():
    print(rule)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)  # , use_reloader=False
