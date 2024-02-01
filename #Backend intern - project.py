


from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.yourmailserver.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_ops_user = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, password=hashed_password, email=email)
    db.session.add(user)
    db.session.commit()

    token = serializer.dumps(email, salt='email-verify')
    verification_url = url_for('verify_email', token=token, _external=True)

    msg = Message('Verify your email', sender='your_email@example.com', recipients=[email])
    msg.body = f'To verify your email, click on the following link: {verification_url}'
    mail.send(msg)

    return jsonify({'message': 'User created successfully. Check your email for verification link.'})

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
        user = User.query.filter_by(email=email).first()

        if user:
            user.is_verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully'})
        else:
            return jsonify({'message': 'Invalid token'}), 401

    except:
        return jsonify({'message': 'Invalid or expired token'}), 401

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password) and user.is_verified:
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
def upload_file():
    data = request.get_json()
    username = data['username']
    password = data['password']
    file_name = data['file_name']

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password) and user.is_ops_user:
        if file_name.lower().endswith(('pptx', 'docx', 'xlsx')):
            new_file = File(filename=file_name, user=user)
            db.session.add(new_file)
            db.session.commit()
            return jsonify({'message': 'File uploaded successfully'})
        else:
            return jsonify({'message': 'Invalid file type. Only pptx, docx, and xlsx allowed.'}), 400
    else:
        return jsonify({'message': 'Invalid credentials or insufficient privileges'}), 401

@app.route('/download-file/<file_id>')
def download_file(file_id):
    file = File.query.get(file_id)

    if file:
        if file.user.is_verified:
            # Generate a secure, time-limited URL for file download
            token = serializer.dumps(file_id, salt='file-download')
            download_url = url_for('verify_file_download', token=token, _external=True)
            return jsonify({'download-link': download_url, 'message': 'success'})
        else:
            return jsonify({'message': 'User not verified. File download access denied.'}), 403
    else:
        return jsonify({'message': 'File not found'}), 404

@app.route('/verify-file-download/<token>')
def verify_file_download(token):
    try:
        file_id = serializer.loads(token, salt='file-download', max_age=3600)
        file = File.query.get(file_id)

        if file and file.user.is_verified:
            # Provide the actual file for download
            return jsonify({'file_data': f'Sample file content for {file.filename}', 'message': 'success'})
        else:
            return jsonify({'message': 'Invalid token or user not verified'}), 401

    except:
        return jsonify({'message': 'Invalid or expired token'}), 401

@app.route('/list-files/<username>', methods=['GET'])
def list_files(username):
    user = User.query.filter_by(username=username).first()

    if user:
        if user.is_verified:
            files = [{'id': file.id, 'filename': file.filename} for file in user.files]
            return jsonify({'files': files, 'message': 'success'})
        else:
            return jsonify({'message': 'User not verified. File list access denied.'}), 403
    else:
        return jsonify({'message': 'User not found'}), 404

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)