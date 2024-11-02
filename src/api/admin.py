import os
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask import redirect, url_for, request, flash, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db, User
from functools import wraps

class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin.login', next=request.url))

class SecureAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('.login'))
        return super(SecureAdminIndexView, self).index()

    @expose('/login', methods=['GET', 'POST'])
    def login(self):
        if current_user.is_authenticated:
            return redirect(url_for('.index'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
            ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'your-secure-password')
            
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                user = AdminUser(1)  # Create an instance of AdminUser
                login_user(user)
                next_url = request.args.get('next')
                if next_url:
                    return redirect(next_url)
                return redirect(url_for('.index'))
            else:
                flash('Invalid username or password', 'error')
        
        return render_template('admin/login.html')

    @expose('/logout')
    def logout(self):
        logout_user()
        return redirect(url_for('.login'))

def setup_admin(app):
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'admin.login'

    @login_manager.user_loader
    def load_user(user_id):
        return AdminUser(int(user_id))

    app.secret_key = os.environ.get('FLASK_APP_KEY', 'sample key')
    app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
    
    # Create custom admin base template
    admin_base_template = """
    {% extends 'admin/base.html' %}
    {% block access_control %}
    {% if current_user.is_authenticated %}
        <div class="navbar-nav d-flex">
            <a class="nav-link" href="{{ url_for('admin.logout') }}">Log out</a>
        </div>
    {% endif %}
    {% endblock %}
    """
    
    # Write the template to a file
    template_dir = os.path.join(app.root_path, 'templates', 'admin')
    os.makedirs(template_dir, exist_ok=True)
    with open(os.path.join(template_dir, 'master.html'), 'w') as f:
        f.write(admin_base_template)
    
    # Initialize Admin with secure index view and custom base template
    admin = Admin(app, 
                 name='4Geeks Admin', 
                 template_mode='bootstrap3',
                 index_view=SecureAdminIndexView(),
                 base_template='admin/master.html')

    # Add your models with secure views
    admin.add_view(SecureModelView(User, db.session))
    return admin