# routes.py
from app import app, db, bcrypt
from flask import render_template, redirect, url_for, flash, request, abort, send_file
from forms import RegistrationForm, LoginForm, PatientProfileForm, HealthDataForm, CommentForm, PrescriptionForm, SearchForm
from models import User, Patient, HealthData, Comment, Prescription
from flask_login import login_user, logout_user, login_required, current_user
from decorators import role_required
from utils import encrypt_data, decrypt_data
from werkzeug.utils import secure_filename
from key_management import encrypt_with_public_key, decrypt_with_private_key
from datetime import datetime
import os
from io import BytesIO

# A dictionary to store decrypted AES keys: {user_id: aes_key_in_bytes}
user_keys = {}

def get_patient_aes_key(patient_id):
    """Retrieve the patient's AES key. If not in user_keys, decrypt it from the DB."""
    if patient_id in user_keys:
        return user_keys[patient_id]
    # Load from DB and decrypt
    patient_user = User.query.get(patient_id)
    if not patient_user or not patient_user.encrypted_aes_key:
        return None
    aes_key = decrypt_with_private_key(patient_user.encrypted_aes_key)
    user_keys[patient_id] = aes_key
    return aes_key

def allowed_file(filename):
    allowed_extensions = {'pdf', 'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Generate a random 32-byte AES key for this user
        aes_key = os.urandom(32)  # AES-256 key
        encrypted_aes_key = encrypt_with_public_key(aes_key)

        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role_name=form.role_name.data,
            encrypted_aes_key=encrypted_aes_key
        )
        db.session.add(user)
        db.session.commit()

        if user.role_name == 'patient':
            patient = Patient(user_id=user.id)
            db.session.add(patient)
            db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.email == form.email_or_username.data) | (User.username == form.email_or_username.data)
        ).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            # Decrypt user's AES key and store it
            if user.encrypted_aes_key:
                aes_key = decrypt_with_private_key(user.encrypted_aes_key)
                user_keys[user.id] = aes_key
            
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your credentials.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role_name == 'patient':
        return redirect(url_for('patient_dashboard'))
    elif current_user.role_name == 'nurse':
        return redirect(url_for('nurse_dashboard'))
    elif current_user.role_name == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    else:
        abort(403)

# Patient Routes
@app.route('/patient_dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    return render_template('patient_dashboard.html')

@app.route('/patient/profile', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def patient_profile():
    patient = Patient.query.get(current_user.id)
    form = PatientProfileForm()

    # Get patient's AES key
    session_key = user_keys.get(current_user.id)
    if form.validate_on_submit():
        if not session_key:
            flash('No AES key set. Something went wrong.', 'danger')
            return redirect(url_for('patient_profile'))
        encrypted_address = encrypt_data(form.address.data, session_key)
        patient.address = encrypted_address
        patient.age = form.age.data
        patient.height = form.height.data
        patient.weight = form.weight.data
        patient.sex = form.sex.data
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('patient_profile'))
    elif request.method == 'GET':
        if patient.address and session_key:
            decrypted_address = decrypt_data(patient.address, session_key)
            form.address.data = decrypted_address
        form.age.data = patient.age
        form.height.data = patient.height
        form.weight.data = patient.weight
        form.sex.data = patient.sex

    return render_template('patient_profile.html', patient=patient, form=form)

@app.route('/patient/patient_view_health_data', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def patient_view_health_data():
    health_records = HealthData.query.filter_by(patient_id=current_user.id).all()
    session_key = user_keys.get(current_user.id)
    if session_key:
        for record in health_records:
            record.symptoms = decrypt_data(record.symptoms, session_key)
    else:
        flash('No AES key found. Cannot decrypt health data.', 'danger')
    return render_template('patient_view_health_data.html', health_records=health_records)

@app.route('/patient/modify_health_data/<int:record_id>', methods=['POST'])
@login_required
@role_required('patient')
def modify_health_data(record_id):
    session_key = user_keys.get(current_user.id)
    if not session_key:
        abort(403, description="No AES key set for user.")
    record = HealthData.query.filter_by(id=record_id, patient_id=current_user.id).first()
    if not record:
        abort(404)
    new_symptoms = request.form.get('symptoms')
    encrypted_symptoms = encrypt_data(new_symptoms, session_key)
    record.symptoms = encrypted_symptoms
    db.session.commit()
    flash('Health data updated successfully.', 'success')
    return redirect(url_for('patient_view_health_data'))

@app.route('/patient/delete_health_file/<int:record_id>', methods=['POST'])
@login_required
@role_required('patient')
def delete_health_file(record_id):
    record = HealthData.query.filter_by(id=record_id, patient_id=current_user.id).first()
    if not record or not record.file_data:
        flash('No file to delete.', 'danger')
        return redirect(url_for('patient_view_health_data'))
    record.file_data = None
    record.filename = None
    db.session.commit()
    flash('File deleted successfully.', 'success')
    return redirect(url_for('patient_view_health_data'))

@app.route('/patient/update_health_file/<int:record_id>', methods=['POST'])
@login_required
@role_required('patient')
def update_health_file(record_id):
    session_key = user_keys.get(current_user.id)
    if not session_key:
        abort(403, description="No AES key set for user.")
    record = HealthData.query.filter_by(id=record_id, patient_id=current_user.id).first()
    if not record:
        abort(404)
    file = request.files.get('new_file')
    if file and allowed_file(file.filename):
        file_data = file.read()
        encrypted_file_data = encrypt_data(file_data, session_key)
        filename = secure_filename(file.filename)
        record.file_data = encrypted_file_data
        record.filename = filename
        db.session.commit()
        flash('File updated successfully.', 'success')
    else:
        flash('Invalid file type or no file uploaded.', 'danger')
    return redirect(url_for('patient_view_health_data'))

@app.route('/patient/submit_health_data', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def submit_health_data():
    form = HealthDataForm()
    session_key = user_keys.get(current_user.id)
    if not session_key:
        flash('No AES key. Unable to encrypt health data.', 'danger')
    if form.validate_on_submit() and session_key:
        file = form.file.data
        symptoms = form.symptoms.data
        if file and allowed_file(file.filename):
            file_data = file.read()
            encrypted_file_data = encrypt_data(file_data, session_key)
            filename = secure_filename(file.filename)
            encrypted_symptoms = encrypt_data(symptoms, session_key)
            health_data = HealthData(
                patient_id=current_user.id,
                file_data=encrypted_file_data,
                filename=filename,
                symptoms=encrypted_symptoms
            )
            db.session.add(health_data)
            db.session.commit()
            flash('Health data submitted successfully.', 'success')
            return redirect(url_for('patient_dashboard'))
        else:
            flash('Invalid file type or no file uploaded.', 'danger')
    return render_template('submit_health_data.html', form=form)

@app.route('/patient/prescriptions')
@login_required
@role_required('patient')
def view_prescriptions():
    prescriptions = Prescription.query.filter_by(patient_id=current_user.id).all()
    session_key = user_keys.get(current_user.id)
    if session_key:
        for p in prescriptions:
            p.prescription = decrypt_data(p.prescription, session_key)
    else:
        flash('No AES key. Unable to decrypt prescriptions.', 'danger')
    return render_template('patient_prescriptions.html', prescriptions=prescriptions)

@app.route('/patient/nurse_comments')
@login_required
@role_required('patient')
def view_nurse_comments():
    comments = Comment.query.filter_by(patient_id=current_user.id, role='nurse').all()
    session_key = user_keys.get(current_user.id)
    if session_key:
        for c in comments:
            c.comment = decrypt_data(c.comment, session_key)
    else:
        flash('No AES key. Unable to decrypt nurse comments.', 'danger')
    return render_template('patient_nurse_comments.html', comments=comments)

@app.route('/uploads/<int:record_id>')
@login_required
def uploaded_file(record_id):
    health_data = HealthData.query.get(record_id)
    if not health_data or not health_data.file_data:
        abort(404)
    patient_id = health_data.patient_id

    # Check if authorized
    if current_user.role_name == 'patient' and patient_id == current_user.id:
        pass
    elif current_user.role_name in ['doctor', 'nurse']:
        pass
    else:
        abort(403)

    # Get patient's AES key
    session_key = get_patient_aes_key(patient_id)
    if not session_key:
        return "No key for this patient. Unable to decrypt.", 403

    decrypted_file_data = decrypt_data(health_data.file_data, session_key)
    file_stream = BytesIO(decrypted_file_data)
    filename = health_data.filename
    return send_file(file_stream, download_name=filename, as_attachment=True)

# Doctor Routes
@app.route('/doctor_dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    return render_template('doctor_dashboard.html')

@app.route('/doctor/search_patients', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def search_patients():
    form = SearchForm()
    patients = []
    if form.validate_on_submit():
        search_query = form.search_query.data
        patients = User.query.filter(
            (User.role_name == 'patient') &
            ((User.username.contains(search_query)) | (User.email.contains(search_query)))
        ).all()
    return render_template('doctor_search_patients.html', patients=patients, form=form)

@app.route('/doctor/view_patient/<int:patient_id>')
@login_required
@role_required('doctor')
def doctor_view_patient(patient_id):
    patient = Patient.query.get(patient_id)
    if not patient:
        abort(404)
    user = User.query.get(patient.user_id)
    health_data = HealthData.query.filter_by(patient_id=patient_id).all()
    comments = Comment.query.filter_by(patient_id=patient_id, role='doctor').all()
    prescriptions = Prescription.query.filter_by(patient_id=patient_id).all()

    # Decrypt using patient's AES key
    session_key = get_patient_aes_key(patient_id)
    if session_key:
        for hd in health_data:
            hd.symptoms = decrypt_data(hd.symptoms, session_key)
        for c in comments:
            c.comment = decrypt_data(c.comment, session_key)
        for p in prescriptions:
            p.prescription = decrypt_data(p.prescription, session_key)

        patient_data = {
            'age': patient.age,
            'height': patient.height,
            'weight': patient.weight,
            'sex': patient.sex
        }
    else:
        patient_data = {
            'age': patient.age,
            'height': patient.height,
            'weight': patient.weight,
            'sex': patient.sex
        }
        for hd in health_data:
            hd.symptoms = "[Encrypted - No key]"
        for c in comments:
            c.comment = "[Encrypted - No key]"
        for p in prescriptions:
            p.prescription = "[Encrypted - No key]"

    return render_template('doctor_view_patient.html', user=user, patient_data=patient_data, health_data=health_data, comments=comments, prescriptions=prescriptions)

@app.route('/doctor/add_comment/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def doctor_add_comment(patient_id):
    form = CommentForm()
    session_key = get_patient_aes_key(patient_id)
    if form.validate_on_submit():
        if not session_key:
            flash('No key for this patient. Unable to encrypt comment.', 'danger')
            return redirect(url_for('doctor_view_patient', patient_id=patient_id))
        comment_text = form.comment.data
        encrypted_comment = encrypt_data(comment_text, session_key)
        comment = Comment(
            patient_id=patient_id,
            author_id=current_user.id,
            comment=encrypted_comment,
            role='doctor'
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
        return redirect(url_for('doctor_view_patient', patient_id=patient_id))
    return render_template('doctor_add_comment.html', patient_id=patient_id, form=form)

@app.route('/doctor/add_prescription/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def doctor_add_prescription(patient_id):
    form = PrescriptionForm()
    session_key = get_patient_aes_key(patient_id)
    if form.validate_on_submit():
        if not session_key:
            flash('No key for this patient. Unable to encrypt prescription.', 'danger')
            return redirect(url_for('doctor_view_patient', patient_id=patient_id))
        prescription_text = form.prescription.data
        encrypted_prescription = encrypt_data(prescription_text, session_key)
        prescription = Prescription(
            patient_id=patient_id,
            doctor_id=current_user.id,
            prescription=encrypted_prescription
        )
        db.session.add(prescription)
        db.session.commit()
        flash('Prescription added successfully.', 'success')
        return redirect(url_for('doctor_view_patient', patient_id=patient_id))
    return render_template('doctor_add_prescription.html', patient_id=patient_id, form=form)

# Nurse Routes
@app.route('/nurse_dashboard')
@login_required
@role_required('nurse')
def nurse_dashboard():
    return render_template('nurse_dashboard.html')

@app.route('/nurse/search_patients', methods=['GET', 'POST'])
@login_required
@role_required('nurse')
def nurse_search_patients():
    form = SearchForm()
    patients = []
    if form.validate_on_submit():
        search_query = form.search_query.data
        patients = User.query.filter(
            (User.role_name == 'patient') &
            ((User.username.contains(search_query)) | (User.email.contains(search_query)))
        ).all()
    return render_template('nurse_search_patients.html', patients=patients, form=form)

@app.route('/nurse/view_patient/<int:patient_id>')
@login_required
@role_required('nurse')
def nurse_view_patient(patient_id):
    patient = Patient.query.get(patient_id)
    if not patient:
        abort(404)
    user = User.query.get(patient.user_id)
    comments = Comment.query.filter_by(patient_id=patient_id).all()
    prescriptions = Prescription.query.filter_by(patient_id=patient_id).all()

    session_key = get_patient_aes_key(patient_id)
    if session_key:
        decrypted_address = decrypt_data(patient.address, session_key) if patient.address else None
        for c in comments:
            c.comment = decrypt_data(c.comment, session_key)
        for p in prescriptions:
            p.prescription = decrypt_data(p.prescription, session_key)
    else:
        decrypted_address = "[Encrypted - No key]"
        for c in comments:
            c.comment = "[Encrypted - No key]"
        for p in prescriptions:
            p.prescription = "[Encrypted - No key]"

    return render_template(
        'nurse_view_patient.html',
        user=user,
        patient=patient,
        comments=comments,
        prescriptions=prescriptions,
        decrypted_address=decrypted_address
    )

@app.route('/nurse/add_comment/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('nurse')
def nurse_add_comment(patient_id):
    form = CommentForm()
    session_key = get_patient_aes_key(patient_id)
    if form.validate_on_submit():
        if not session_key:
            flash('No key for this patient. Unable to encrypt comment.', 'danger')
            return redirect(url_for('nurse_view_patient', patient_id=patient_id))
        comment_text = form.comment.data
        encrypted_comment = encrypt_data(comment_text, session_key)
        comment = Comment(
            patient_id=patient_id,
            author_id=current_user.id,
            comment=encrypted_comment,
            role='nurse'
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
        return redirect(url_for('nurse_view_patient', patient_id=patient_id))
    return render_template('nurse_add_comment.html', patient_id=patient_id, form=form)

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404
