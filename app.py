import os
import socket
import random
import string
import logging
import random
from datetime import datetime, timezone
from flask import Flask, flash, render_template, redirect, request, url_for, session, jsonify
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError
import requests
from google.oauth2 import id_token
from google.auth.transport.requests import Request
import bcrypt
from flask_login import UserMixin, login_required, current_user, LoginManager, login_user, logout_user
from bson import ObjectId
from oauthlib.oauth2 import WebApplicationClient

app = Flask(__name__)
CORS(app)

# Configuration
app.config.update(
    MONGO_URI=os.getenv('MONGO_URI', 'mongodb://localhost:27017'),
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    GOOGLE_CLIENT_ID=os.getenv('GOOGLE_CLIENT_ID'),
    GOOGLE_CLIENT_SECRET=os.getenv('GOOGLE_CLIENT_SECRET'),
    SECRET_KEY=os.getenv('SECRET_KEY', 'my-secret-key'),
    UPLOAD_FOLDER='static/uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  
)

# MongoDB setup
client = MongoClient(app.config['MONGO_URI'])
db = client['weatherapp']
users = db['users']
weather_shares = db['weather_shares']

# Flask extensions
mail = Mail(app)
oauth = OAuth(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
logging.basicConfig(level=logging.INFO)

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)
# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=GOOGLE_DISCOVERY_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

def test_smtp_connection():
    try:
        sock = socket.create_connection(('smtp.gmail.com', 587), timeout=10)
        sock.close()
        return True
    except Exception as e:
        logging.error(f"SMTP connection test failed: {str(e)}")
        return False
    
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.profile_image = user_data.get('profile_image', '')
        self.confirmed = user_data.get('confirmed', False)

@login_manager.user_loader
def load_user(user_id):
    user_data = users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def send_confirmation_email(email, token):
    try:
        # Test the SMTP connection first
        with mail.connect() as conn:
            confirm_url = url_for('confirm_email', token=token, _external=True)
            msg = Message(
                'Confirm Your Email',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f'Please click the link to confirm your email: {confirm_url}'
            conn.send(msg)
        return True
    except Exception as e:
        logging.error(f"Detailed email error: {str(e)}")
        # Log additional connection details for debugging
        logging.error(f"SMTP Server: {app.config['MAIL_SERVER']}")
        logging.error(f"SMTP Port: {app.config['MAIL_PORT']}")
        logging.error(f"Username configured: {'Yes' if app.config['MAIL_USERNAME'] else 'No'}")
        return False


ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'gif', 'png', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = users.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            if not user.get('confirmed', False):
                flash('Please confirm your email first.', 'error')
                return render_template('login.html', email=email, user=user)  # Pass user object here
            
            login_user(User(user))
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password', 'error')
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']

        if users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        token = generate_token()
        unique_id = ''.join(random.choices(string.digits, k=8))
        
        try:
            users.insert_one({
                'email': email,
                'password': hashed_password,
                'unique_id': unique_id,
                'name': name,
                'confirmed': False,
                'confirmation_token': token,
                'created_at': datetime.now(timezone.utc)
            })
        except Exception as e:
            logging.error(f"Error during registration: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))

        if not send_confirmation_email(email, token):
            flash('Registration was successful, but the confirmation email failed to send.', 'warning')
            return redirect(url_for('login'))

        flash('Registration successful! Please check your email to confirm your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    user = users.find_one({'confirmation_token': token})
    if user:
        users.update_one(
            {'_id': user['_id']},
            {
                '$set': {'confirmed': True},
                '$unset': {'confirmation_token': ''}
            }
        )
        flash('Email confirmed successfully! You can now login.', 'success')
    else:
        flash('Invalid or expired confirmation token.', 'error')
    return redirect(url_for('login'))

@app.route('/resend_confirmation_email', methods=['POST'])
def resend_confirmation_email():
    email = request.form['email']
    
    user = users.find_one({'email': email})
    if user and not user.get('confirmed', False):
        token = user['confirmation_token']
        
        if not send_confirmation_email(email, token):
            flash('Failed to send confirmation email. Please try again later.', 'error')
        else:
            flash('A new confirmation email has been sent to your email address.', 'success')
        
        return redirect(url_for('login'))
    
    flash('The email address is either not registered or already confirmed.', 'error')
    return redirect(url_for('login'))

@app.route('/login/google')
def google_login():
    session['nonce'] = generate_token()  
    redirect_uri = url_for('google_callback', _external=True)
    
    return oauth.google.authorize_redirect(
        redirect_uri=redirect_uri,
        nonce=session['nonce']
    )

@app.route('/login/google/authorize')
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        
        resp = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        
        if user_info.get('email_verified'):
            unique_id = user_info['sub']
            user_email = user_info['email']
            user_name = user_info.get('name')
            picture = user_info.get('picture')

            user = users.find_one({'email': user_email})
            
            if not user:
                user_data = {
                    'email': user_email,
                    'name': user_name,
                    'profile_image': picture,
                    'google_id': unique_id,
                    'confirmed': True,
                    'created_at': datetime.now(timezone.utc)
                }
                users.insert_one(user_data)
                user = users.find_one({'email': user_email})
            
            user_obj = User(user)
            login_user(user_obj)
            
            return redirect(url_for('dashboard'))
        else:
            flash('Please verify your Google account first.', 'error')
            return redirect(url_for('login'))
            
    except Exception as e:
        print(f"Error in Google callback: {str(e)}")
        flash('Failed to log in with Google. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/share-weather', methods=['POST'])
@login_required
def share_weather():
    city_info = request.form['city']
    weather_data = request.form['weather_data']
    
    share_token = generate_token()

    short_url = generate_token()[:8]  
    weather_shares.insert_one({
        'token': share_token,
        'short_url': short_url,
        'city_info': city_info,
        'weather_data': weather_data,
        'user_id': ObjectId(current_user.id),
        'created_at': datetime.now(timezone.utc)
    })
    
    print(f"Generated short_url: {short_url}")
    
    return jsonify({
        'short_url': f'http://localhost:5002/s/{short_url}' 
    })

@app.route('/s/<short_url>')
def redirect_to_weather(short_url):
    # Find the weather share by its short URL
    share = weather_shares.find_one({'short_url': short_url})
    
    if not share:
        flash('Invalid or expired share link.', 'error')
        return redirect(url_for('login'))

    return redirect(url_for('view_shared_weather', token=share['token'], _external=True))

@app.route('/w/<token>')
def view_shared_weather(token):
    share = weather_shares.find_one({'token': token})
    if not share:
        flash('Invalid or expired share link.', 'error')
        return redirect(url_for('login'))
    
    if not current_user.is_authenticated:
        session['next'] = request.url
        return redirect(url_for('login'))
    
    return render_template('share.html', weather_data=share['weather_data'], city_info=share['city_info'])

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename == '':
                flash('No selected file.', 'error')
                return redirect(url_for('profile'))

            if not allowed_file(file.filename):
                flash('File type not allowed. Please upload an image file.', 'error')
                return redirect(url_for('profile'))

            try:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                users.update_one(
                    {'_id': ObjectId(current_user.id)},
                    {'$set': {'profile_image': filename}}
                )
                flash('Profile image updated successfully!', 'success')
            except Exception as e:
                flash(f"Error saving the file: {str(e)}", 'error')

    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/get_weather')
@login_required
def get_weather():
    city = request.args.get('city')
    datetime_str = request.args.get('datetime')  # Date and time for filtering the data

    api_key = os.getenv('API_KEY')
    base_url = f'https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/{city}'
    url = f"{base_url}?unitGroup=metric&key={api_key}&contentType=json"

    try:
        response = requests.get(url)
        data = response.json()
        
        if response.status_code != 200 or 'days' not in data:
            return jsonify({'error': 'Failed to retrieve weather data'}), 500

        # Convert the datetime_str into a datetime object for comparison
        if datetime_str:
            filter_datetime = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M")
        
        # Check the weather data for the requested day
        weather_info = None
        for day in data['days']:
            day_datetime = datetime.strptime(day['datetime'], "%Y-%m-%d")
            if datetime_str and day_datetime.date() == filter_datetime.date():
                # Find the closest time if the datetime provided is within the day's data
                for hour in day['hours']:
                    hour_datetime = datetime.strptime(hour['datetime'], "%H:%M:%S").replace(year=day_datetime.year, month=day_datetime.month, day=day_datetime.day)
                    if hour_datetime >= filter_datetime:
                        weather_info = hour
                        break
            if weather_info:
                break
        else:
            # If no data matches, use the default or latest available data
            weather_info = data['days'][0]

        # Prepare the weather data to return
        weather_data = {
            'temperature': weather_info['temp'],  # Current temperature
            'condition': weather_info['conditions'],  # Weather condition (e.g., "Partially cloudy")
            'city': data['resolvedAddress'],  # City (Resolved address)
            'datetime': weather_info['datetime'],  # Date and time for the weather data
            'humidity': weather_info['humidity'],  # Humidity percentage
            'windspeed': weather_info['windspeed'],  # Wind speed in km/h
            'feelslike': weather_info['feelslike'],  # Feels like temperature
            'precipitation': weather_info['precip'],  # Precipitation in mm
            'windgust': weather_info['windgust'],  # Wind gust speed in km/h
            'visibility': weather_info['visibility'],  # Visibility in km
            'uvindex': weather_info['uvindex'],  # UV Index
            'dewPoint': weather_info['dew'],
        }

        # Return weather data as JSON
        return jsonify(weather_data)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching weather data: {str(e)}")
        return jsonify({'error': 'Error fetching weather data'}), 500



@app.route('/')
def index():
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
