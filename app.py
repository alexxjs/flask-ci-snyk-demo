from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_file,session,jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Product, Cart, Order
from functools import wraps
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from sqlalchemy.sql import text
from datetime import datetime, timedelta

import pyotp
import qrcode
import os
import stripe
import io 
import uuid
from io import BytesIO







app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diskjock.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'IhpqnkRLGOiDQI69L45uegn_M8ZAG9SrhNT27jpbHuY='

stripe.api_key = app.config['STRIPE_SECRET_KEY']
# Initialize the database once
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_attempts = {}

# Create tables at app startup
with app.app_context():
    db.create_all()
    print("Using database at:", app.config['SQLALCHEMY_DATABASE_URI'])


encryption_key = b'IhpqnkRLGOiDQI69L45uegn_M8ZAG9SrhNT27jpbHuY=' 
cipher = Fernet(encryption_key)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Load user from database


# Home route
@app.route('/')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        secret = pyotp.random_base32() # Generates pyotp secrete code
        session['two_factor_secret'] = secret  # stores it in session rather than on db
        flash('Two-factor authentication enabled. Use the OTP to log in.', 'success')
        return redirect(url_for('dashboard'))

    if 'two_factor_secret' not in session:
        secret = pyotp.random_base32()
        session['two_factor_secret'] = secret
        qr_code_url = pyotp.TOTP(secret).provisioning_uri(
            name=current_user.username,
            issuer_name="DiskJock App"
        )
        return render_template('enable_2fa.html', qr_code_url=qr_code_url)

    flash('Two-factor authentication is already enabled.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Handle setting up 2FA for the user."""
    user = User.query.get(current_user.id)
    if not user:
        abort(404, "User not found.")

    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("OTP code is required!", "danger")
            return redirect(url_for('setup_2fa'))

        
        totp = pyotp.TOTP(user.two_factor_secret)
        # Verifies the OTP gathered from the HTML form
        if totp.verify(otp):                        
            user.two_factor_enabled = True  
            db.session.commit()   # Updates user on the database to show 2FA has been enabled 
            flash("Two-Factor Authentication setup complete!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('setup_2fa.html')






@app.route('/generate_qr')
@login_required
def generate_qr():
    """Generate and return QR code as an image for embedding."""
    user = current_user 
    if not user.two_factor_secret:
        abort(404, "2FA secret not found.")

    totp = pyotp.TOTP(user.two_factor_secret)
    qr_code_url = totp.provisioning_uri(name=f"{user.username}@DiskJock", issuer_name="DiskJock")

    qr_image = qrcode.make(qr_code_url)
    buffer = BytesIO()
    qr_image.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype='image/png')





@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    user = db.session.get(User, session.get('user_id'))

    if not user:
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(otp, valid_window=2):      # Verify process completed through the pyotp module 
            login_user(user)
            flash("2FA verification successful!", "success")

            # Clear temporary session data and redirect to the dashboard
            session.pop('user_id', None)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('verify_2fa.html')


@app.route('/admin/orders', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_orders():
    orders = Order.query.all()  

    if request.method == 'POST':
        order_id = request.form.get('order_id')
        new_status = request.form.get('status')
        order = Order.query.get(order_id)
        if order:
            order.status = new_status
            db.session.commit()
            flash(f"Order {order.order_number} updated to {new_status}.", 'success')
        else:
            flash("Order not found.", 'danger')

        return redirect(url_for('admin_orders'))

    return render_template('admin_orders.html', orders=orders)




@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard to manage users and products."""
    users = User.query.all()
    products = Product.query.all()

    # Decrypt emails for display
    for user in users:
        user.decrypted_email = cipher.decrypt(user.email_encrypted).decode()

    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')
        entity_id = request.form.get('id')

        if entity == 'user':
            user = User.query.get(entity_id)
            if action == 'delete' and user:
                db.session.delete(user)
                db.session.commit()
                flash(f"User {user.username} deleted successfully!", 'success')
            elif action == 'edit' and user:
                user.username = request.form.get('username')
                user.email_encrypted = cipher.encrypt(request.form.get('email').encode())
                db.session.commit()
                flash(f"User {user.username} updated successfully!", 'success')

        elif entity == 'product':
            product = Product.query.get(entity_id)
            if action == 'delete' and product:
                db.session.delete(product)
                db.session.commit()
                flash(f"Product {product.name} deleted successfully!", 'success')
            elif action == 'edit' and product:
                product.name = request.form.get('name')
                product.price = float(request.form.get('price'))
                product.image = request.form.get('image')
                db.session.commit()
                flash(f"Product {product.name} updated successfully!", 'success')

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users, products=products)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Check if the username already exists (parameterised query)
        user_exists_query = text("SELECT 1 FROM user WHERE username = :username")
        result = db.session.execute(user_exists_query, {"username": username}).fetchone()

        if result:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Encrypt email
        encrypted_email = cipher.encrypt(email.encode())

        # Add the new user (parameterised query)
        add_user_query = text("""
            INSERT INTO user (username, email_encrypted, password, two_factor_secret, role) 
            VALUES (:username, :email_encrypted, :password, :two_factor_secret, :role)
        """)
        db.session.execute(
            add_user_query,
            {
                "username": username,
                "email_encrypted": encrypted_email,
                "password": generate_password_hash(password),  # Store the hashed password in the `password` column
                "two_factor_secret": pyotp.random_base32(),  # Generate 2FA secret
                "role": "user"  # Assign the default role
            }
        )
        db.session.commit()
        # Log in the user immediately after registration
        user = User.query.filter_by(username=username).first()  # Retrieve the user instance
        login_user(user)
        flash('Registration successful! Please set up Two-Factor Authentication.', 'success')
        return redirect(url_for('setup_2fa'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # SQL query
        raw_query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
        result = db.session.execute(text(raw_query)).fetchone()

        if result:
            user = User.query.first() 
            login_user(user)
            flash('Login successful! (login)', 'success')
            return redirect(url_for('dashboard'))


        flash('Invalid login (login)', 'danger')

    return render_template('login.html')



@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    """Update the user's email securely after verifying the current password."""
    current_password = request.form.get('current_password')
    new_email = request.form.get('email')

    if not current_password or not new_email:
        flash("All fields are required.", "danger")
        return redirect(url_for('dashboard'))

    # Verify the current password
    if not current_user.check_password(current_password):
        flash("Incorrect current password. Please try again.", "danger")
        return redirect(url_for('dashboard'))

    # Encrypt the new email
    encrypted_email = cipher.encrypt(new_email.encode())

    # Use a parameterised query to update the email
    update_email_query = text("""
        UPDATE user
        SET email_encrypted = :email_encrypted
        WHERE id = :user_id
    """)
    db.session.execute(
        update_email_query,
        {"email_encrypted": encrypted_email, "user_id": current_user.id}
    )
    db.session.commit()

    flash("Your email has been updated successfully!", "success")
    return redirect(url_for('dashboard'))


@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    """Update the user's password securely after verifying the current password."""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    if not current_password or not new_password:
        flash("All fields are required.", "danger")
        return redirect(url_for('dashboard'))

    # Verify the current password
    if not current_user.check_password(current_password):
        flash("Incorrect current password. Please try again.", "danger")
        return redirect(url_for('dashboard'))

    # Hash the new password
    hashed_password = generate_password_hash(new_password)

    # Use a parameterised query to update the password
    update_password_query = text("""
        UPDATE user
        SET password = :password
        WHERE id = :user_id
    """)
    db.session.execute(
        update_password_query,
        {"password": hashed_password, "user_id": current_user.id}
    )
    db.session.commit()

    flash("Your password has been updated successfully!", "success")
    return redirect(url_for('dashboard'))


@app.route('/cart')
@login_required
def cart():
    items = Cart.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product.price * item.quantity for item in items)
    return render_template('cart.html', items=items, total_price=total_price)


@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    # Check if the product exists
    product = Product.query.get(product_id)
    if not product:
        flash('Product does not exist.', 'danger')
        return redirect(url_for('home'))
    cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = Cart(user_id=current_user.id, product_id=product_id, quantity=1)
        db.session.add(cart_item)

    db.session.commit()
    flash('Product added to cart!', 'success')
    return redirect(url_for('cart'))



@app.route('/remove_from_cart/<int:cart_id>')
@login_required
def remove_from_cart(cart_id):
    cart_item = Cart.query.get(cart_id)
    if not cart_item or cart_item.user_id != current_user.id:
        flash('Item not found in your cart.', 'danger')
        return redirect(url_for('cart'))

    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart.', 'success')
    return redirect(url_for('cart'))

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        # Fetch the cart items for the current user
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()

        # Calculate the total price
        total_price = sum(item.product.price * item.quantity for item in cart_items)
        total_amount_cents = int(total_price * 100)  # Convert to cents

        # Create a new Checkout Session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'gbp',
                        'product_data': {
                            'name': item.product.name,
                        },
                        'unit_amount': int(item.product.price * 100),
                    },
                    'quantity': item.quantity,
                }
                for item in cart_items
            ],
            mode='payment',
            success_url=url_for('checkout_success', _external=True),
            cancel_url=url_for('cart', _external=True),
        )

        return jsonify({'sessionId': session['id']})
    # Error Message
    except Exception as e:
        print(f"Error creating checkout session: {e}")
        return jsonify({'error': str(e)}), 500



@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    try:
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()

        # Calculate the total price
        total_price = sum(item.product.price * item.quantity for item in cart_items)
        total_amount_cents = int(total_price * 100)  # Amount in cents

        print(f"Cart Items: {cart_items}")
        print(f"Total Price: {total_price}")

        # Create a PaymentIntent
        intent = stripe.PaymentIntent.create(
            amount=total_amount_cents,
            currency='gbp',
            automatic_payment_methods={'enabled': True},
        )

        print(f"PaymentIntent created: {intent}")
        return jsonify({'client_secret': intent['client_secret']})
    except Exception as e:
        print(f"Error creating PaymentIntent: {e}")
        return jsonify({'error': str(e)}), 500


# If stripe payment goes through this will run
@app.route('/checkout-success')
@login_required
def checkout_success():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product.price * item.quantity for item in cart_items)

    order_number = str(uuid.uuid4())[:8].upper()

    new_order = Order(
        order_number=order_number,
        user_id=current_user.id,
        total_price=total_price,
        status="Waiting to be Shipped"
    )
    db.session.add(new_order)
    db.session.commit()

    for item in cart_items:
        db.session.delete(item)
    db.session.commit()

    return render_template('checkout_success.html', order_number=order_number)


@app.route('/checkout')
@login_required
def checkout():
    user_cart = Cart.query.filter_by(user_id=current_user.id).all()
    if not user_cart:
        flash('Your cart is empty!', 'danger')
        return redirect(url_for('cart'))

    total_price = sum(item.product.price * item.quantity for item in user_cart)
    return render_template('checkout.html', total_price=total_price, stripe_public_key="pk_test_51Qgn3WGLdU05YBbTg5CJTzM7XhF2VSslPITyEFrckQSPaUEyzv26pz3DXYpitZqS8uTEQNiWhpK07v1ZD0Acp3Bn00lhnznScu")

@app.route('/orders')
@login_required
def orders():
    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('orders.html', orders=user_orders)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Render the dashboard with current account details."""
    decrypted_email = cipher.decrypt(current_user.email_encrypted).decode()
    return render_template('dashboard.html', decrypted_email=decrypted_email)



if __name__ == "__main__":
    app.run(debug=True)