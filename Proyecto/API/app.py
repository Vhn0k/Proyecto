from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import json
import uuid

app = Flask(__name__)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = 'una_clave_secreta_muy_larga_y_dificil_de_adivinar_CAMBIAR_EN_PRODUCCION'
app.config['SESSION_TYPE'] = 'filesystem'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# FILTRO PERSONALIZADO PARA JINJA2: Para parsear JSON strings en las plantillas
@app.template_filter('from_json')
def from_json_filter(value):
    if value is None:
        return []
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return []

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'info'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=True, default='')
    last_name = db.Column(db.String(50), nullable=True, default='')
    phone = db.Column(db.String(20), nullable=True, default='')
    about_me = db.Column(db.Text, nullable=True, default='')
    location = db.Column(db.String(100), nullable=True, default='')
    profile_image_url = db.Column(db.String(255), nullable=True, default='img/default_profile.png')

    reports = db.relationship('Report', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(50), nullable=False)
    location_text = db.Column(db.String(200), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=False)
    urgency_level = db.Column(db.String(20), nullable=False)
    reporter_email = db.Column(db.String(120), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    image_filenames = db.Column(db.Text, nullable=True, default='[]')

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f'<Report {self.report_type} at {self.location_text}>'

    def to_dict(self):
        image_list = json.loads(self.image_filenames) if self.image_filenames else []
        return {
            'id': self.id,
            'report_type': self.report_type,
            'location_text': self.location_text,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'description': self.description,
            'urgency_level': self.urgency_level,
            'reporter_email': self.reporter_email,
            'timestamp': self.timestamp.isoformat(),
            'image_filenames': image_list
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    recent_reports = Report.query.order_by(Report.timestamp.desc()).limit(10).all()
    now = datetime.now()
    return render_template('index.html', reportes=recent_reports, now=now)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not email or not password or not confirm_password:
            flash('Por favor, rellena todos los campos.', 'error')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'error')
            return redirect(url_for('register'))
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Este correo ya está registrado. Intenta iniciar sesión.', 'error')
            return redirect(url_for('login'))
        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('¡Registro exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'¡Bienvenido, {user.first_name if user.first_name else user.email}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Correo o contraseña incorrectos.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('index'))

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    user = current_user
    if request.method == 'POST':
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.phone = request.form.get('phone')
        # user.about_me = request.form.get('about_me') # Eliminado a petición del usuario
        # user.location = request.form.get('location') # Eliminado a petición del usuario

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename == '':
                # Si el usuario abrió el diálogo de archivo pero no seleccionó nada, no hacemos nada.
                pass 
            elif file and allowed_file(file.filename):
                # Si ya tiene una imagen de perfil y no es la por defecto, la eliminamos primero.
                if user.profile_image_url and 'default_profile.png' not in user.profile_image_url:
                    old_filename = os.path.basename(user.profile_image_url)
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], old_filename)
                    if os.path.exists(old_filepath):
                        try:
                            os.remove(old_filepath)
                            print(f"Antigua imagen eliminada: {old_filepath}") # Para depuración
                        except Exception as e:
                            print(f"Error al eliminar antigua imagen {old_filepath}: {e}") # Para depuración
                            flash(f'Error al eliminar la imagen anterior: {e}', 'warning')

                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                try:
                    file.save(filepath)
                    user.profile_image_url = 'uploads/' + unique_filename
                    flash('Imagen de perfil actualizada.', 'success')
                    print(f"Nueva imagen guardada: {filepath}") # Para depuración
                except Exception as e:
                    flash(f'Error al guardar la nueva imagen de perfil: {e}', 'error')
                    print(f"Error al guardar nueva imagen: {e}") # Para depuración
            else:
                flash('Tipo de archivo no permitido para la imagen de perfil.', 'error')
        db.session.commit()
        flash('Tu perfil ha sido actualizado correctamente.', 'success')
        return redirect(url_for('perfil'))

    # Cálculo de reputación para la página de perfil
    report_count = user.reports.count()
    # Cada 5 reportes = 1 estrella. Máximo 5 estrellas (25 reportes).
    user_stars = min(report_count // 5, 5)
    
    # Texto de valoración basado en estrellas
    if user_stars == 0:
        rating_text = "Necesita Reportes"
    elif user_stars == 1:
        rating_text = "Principiante"
    elif user_stars == 2:
        rating_text = "Participante Activo"
    elif user_stars == 3:
        rating_text = "Colaborador Destacado"
    elif user_stars == 4:
        rating_text = "Ciudadano Ejemplar"
    elif user_stars == 5:
        rating_text = "Héroe Local"
    else:
        rating_text = "Sin Valoración" # Esto no debería ocurrir si el límite es 5

    return render_template('profile.html', user=user, user_stars=user_stars, rating_text=rating_text)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        if not current_user.check_password(old_password):
            flash('La contraseña actual es incorrecta.', 'error')
        elif new_password != confirm_new_password:
            flash('La nueva contraseña y la confirmación no coinciden.', 'error')
        elif len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Tu contraseña ha sido actualizada correctamente.', 'success')
            return redirect(url_for('perfil'))
    return render_template('change_password.html')

@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        password = request.form.get('password')
        if not current_user.check_password(password):
            flash('Contraseña incorrecta.', 'error')
        elif User.query.filter_by(email=new_email).first():
            flash('Este correo electrónico ya está en uso.', 'error')
        else:
            current_user.email = new_email
            db.session.commit()
            flash('Tu correo electrónico ha sido actualizado correctamente.', 'success')
            return redirect(url_for('perfil'))
    return render_template('change_email.html')

@app.route('/delete_account_confirm', methods=['GET', 'POST'])
@login_required
def delete_account_confirm():
    if request.method == 'POST':
        password = request.form.get('password')
        if not current_user.check_password(password):
            flash('Contraseña incorrecta. No se pudo eliminar la cuenta.', 'error')
        else:
            if current_user.profile_image_url and 'default_profile.png' not in current_user.profile_image_url:
                try:
                    filename = os.path.basename(current_user.profile_image_url)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception as e:
                    flash(f'Error al eliminar la imagen de perfil: {e}', 'warning')
            db.session.delete(current_user)
            db.session.commit()
            logout_user()
            flash('Tu cuenta ha sido eliminada permanentemente.', 'success')
            return redirect(url_for('index'))
    return render_template('delete_account_confirm.html')

@app.route('/delete_profile_picture', methods=['POST'])
@login_required
def delete_profile_picture():
    if current_user.profile_image_url and 'default_profile.png' not in current_user.profile_image_url:
        try:
            filename = os.path.basename(current_user.profile_image_url)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            current_user.profile_image_url = 'img/default_profile.png'
            db.session.commit()
            flash('Tu imagen de perfil ha sido eliminada.', 'success')
        except Exception as e:
            flash(f'Error al eliminar la imagen: {e}', 'error')
    else:
        flash('No hay imagen de perfil para eliminar.', 'info')
    return redirect(url_for('perfil'))

@app.route('/reportar', methods=['GET', 'POST'])
@login_required
def reportar():
    if request.method == 'GET':
        session['report_data'] = {
            'step': 1,
            'location_text': '',
            'latitude': '',
            'longitude': '',
            'description': '',
            'report_type': '',
            'urgency_level': '',
            'reporter_email': current_user.email if current_user.is_authenticated else '',
            'image_filenames': []
        }
        return render_template('report.html', report_data=session['report_data'])

    elif request.method == 'POST':
        current_step = int(request.form.get('current_step', 1))
        action = request.form.get('action')

        report_data = session.get('report_data', {
            'step': 1,
            'location_text': '',
            'latitude': '',
            'longitude': '',
            'description': '',
            'report_type': '',
            'urgency_level': '',
            'reporter_email': current_user.email if current_user.is_authenticated else '',
            'image_filenames': []
        })

        if current_step == 1:
            report_data['location_text'] = request.form.get('location_text', '')
            report_data['latitude'] = float(request.form.get('latitude')) if request.form.get('latitude') else None
            report_data['longitude'] = float(request.form.get('longitude')) if request.form.get('longitude') else None
        elif current_step == 2:
            if 'images' in request.files:
                uploaded_files = request.files.getlist('images')
                new_image_filenames = []
                for file in uploaded_files:
                    if file and allowed_file(file.filename):
                        unique_filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        file.save(filepath)
                        new_image_filenames.append(unique_filename)
                    elif file.filename != '':
                        flash(f'Archivo no permitido: {file.filename}', 'error')
                report_data['image_filenames'].extend(new_image_filenames)
        elif current_step == 3:
            report_data['report_type'] = request.form.get('report_type', '')
            report_data['description'] = request.form.get('description', '')
            report_data['urgency_level'] = request.form.get('urgency_level', '')
        elif current_step == 4:
            report_data['reporter_email'] = request.form.get('email_optional', '')

        if action == 'next':
            if current_step == 1:
                if not report_data['location_text'].strip() or not (report_data['latitude'] is not None and report_data['longitude'] is not None):
                    flash('Por favor, ingresa una dirección y asegúrate de que se obtenga una ubicación válida (latitud y longitud) antes de continuar.', 'error')
                    report_data['step'] = 1
                else:
                    report_data['step'] = current_step + 1
            elif current_step == 2:
                report_data['step'] = current_step + 1
            elif current_step == 3:
                if not report_data['report_type'] or not report_data['description'].strip() or not report_data['urgency_level']:
                    flash('Por favor, completa el tipo de problema, descripción y nivel de urgencia para continuar.', 'error')
                    report_data['step'] = 3
                else:
                    report_data['step'] = current_step + 1
            else:
                report_data['step'] = current_step + 1
        elif action == 'prev':
            report_data['step'] = current_step - 1 if current_step > 1 else 1
        elif action == 'submit':
            if not report_data['report_type'] or not report_data['description'].strip() or not report_data['urgency_level']:
                flash('Faltan datos obligatorios del reporte. Vuelve al Paso 3 para completarlos.', 'error')
                report_data['step'] = 3
                session['report_data'] = report_data
                return render_template('report.html', report_data=report_data)
            
            if report_data['latitude'] is None or report_data['longitude'] is None:
                flash('La ubicación del reporte no es válida. Vuelve al Paso 1 para obtener una ubicación correcta.', 'error')
                report_data['step'] = 1
                session['report_data'] = report_data
                return render_template('report.html', report_data=report_data)

            if not request.form.get('accept_terms'):
                flash('Debes aceptar los términos y condiciones para enviar el reporte.', 'error')
                report_data['step'] = 4
                session['report_data'] = report_data
                return render_template('report.html', report_data=report_data)

            user_id = current_user.id if current_user.is_authenticated else None
            final_email = report_data['reporter_email'] if report_data['reporter_email'] else (current_user.email if current_user.is_authenticated else None)

            try:
                new_report = Report(
                    report_type=report_data['report_type'],
                    location_text=report_data['location_text'],
                    latitude=report_data['latitude'],
                    longitude=report_data['longitude'],
                    description=report_data['description'],
                    urgency_level=report_data['urgency_level'],
                    reporter_email=final_email,
                    user_id=user_id,
                    image_filenames=json.dumps(report_data['image_filenames'])
                )
                db.session.add(new_report)
                db.session.commit()

                flash('¡Tu reporte ha sido enviado con éxito! Gracias por tu contribución.', 'success')
                session.pop('report_data', None)
                return redirect(url_for('reportes_mapa'))
            except Exception as e:
                db.session.rollback()
                flash(f'Ocurrió un error al guardar el reporte: {e}', 'error')
                report_data['step'] = 4
                session['report_data'] = report_data
                return render_template('report.html', report_data=report_data)
        
        session['report_data'] = report_data
        return render_template('report.html', report_data=report_data)

@app.route('/instructions')
def instructions():
    now = datetime.now()
    return render_template('instructions.html', now=now)

@app.route('/api/reportes', methods=['GET'])
def get_reportes():
    reportes = Report.query.all()
    reportes_data = [report.to_dict() for report in reportes]
    return jsonify(reportes_data)

@app.route('/reportes_mapa')
def reportes_mapa():
    now = datetime.now()
    return render_template('reportes_mapa.html', now=now)

@app.route('/mis_reportes')
@login_required
def mis_reportes():
    # Obtener todos los reportes donde el user_id coincide con el id del usuario actual
    user_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.timestamp.desc()).all()
    # Pasa los reportes a la plantilla para que se muestren
    return render_template('my_reports.html', reportes=user_reports)

# Nueva ruta para los Términos y Condiciones
@app.route('/terminos_y_condiciones')
def terminos_y_condiciones():
    return render_template('terms_and_conditions.html') # Asegúrate que el nombre de archivo coincida con el que creaste

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)