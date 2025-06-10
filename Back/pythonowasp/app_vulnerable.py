from flask import Flask, request, jsonify
import sqlite3
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
import logging
import os

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear aplicación Flask
app = Flask(__name__)

# Configuración
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'security_project_key_David_Tovar_Crud')
    TOKEN_EXPIRY_MINUTES = int(os.getenv('TOKEN_EXPIRY_MINUTES', 5))
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'database.db')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

app.config['DEBUG'] = Config.DEBUG

# ============ UTILIDADES ============

def hash_password(password):
    """Hash una contraseña usando bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    """Verificar contraseña contra su hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_db_connection():
    """Conectar a la base de datos con manejo de errores"""
    try:
        conn = sqlite3.connect(Config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # Para acceso por nombre de columna
        return conn
    except sqlite3.Error as e:
        logger.error(f"Error conectando a BD: {e}")
        raise

def response_format(status_code, message, data=None, error=None):
    """Formato estándar de respuesta"""
    response = {
        'status_code': status_code,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }
    if data is not None:
        response['data'] = data
    if error:
        response['error'] = error
    return jsonify(response), status_code

# ============ JWT FUNCIONES ============

def create_token(username, user_id):
    """Crear nuevo token JWT"""
    payload = {
        'exp': datetime.utcnow() + timedelta(minutes=Config.TOKEN_EXPIRY_MINUTES),
        'iat': datetime.utcnow(),
        'sub': username,
        'user_id': user_id
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

def verify_token():
    """Verificar validez del token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, "Token no encontrado o formato incorrecto"
    
    try:
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token expirado"
    except jwt.InvalidTokenError:
        return None, "Token inválido"
    except Exception as e:
        return None, f"Error verificando token: {str(e)}"

def token_required(f):
    """Decorador para endpoints que requieren token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token_data, error = verify_token()
        if error:
            return response_format(401, error)
        
        request.current_user = token_data['sub']
        request.current_user_id = token_data.get('user_id')
        return f(*args, **kwargs)
    return decorated

# ============ BASE DE DATOS ============

def init_database():
    """Inicializar base de datos con tablas y datos por defecto"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tabla usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            birthdate TEXT,
            status TEXT DEFAULT 'active',
            secret_question TEXT,
            secret_answer TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla productos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            precio_llegada DECIMAL(10,2) NOT NULL,
            precio_menudeo DECIMAL(10,2) NOT NULL,
            precio_mayoreo DECIMAL(10,2) NOT NULL,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Usuarios por defecto
    default_users = [
        ('admin', hash_password('1234'), 'admin@example.com', '2002-07-02', '¿Color favorito?', 'azul'),
        ('user', hash_password('pass'), 'user@example.com', '2002-07-02', '¿Color favorito?', 'azul')
    ]
    
    for user_data in default_users:
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, email, birthdate, secret_question, secret_answer)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', user_data)
    
    # Productos por defecto
    default_products = [
        ('Laptop Dell', 'Laptop Dell Inspiron 15 3000', 15000.00, 18000.00, 16500.00),
        ('Mouse Logitech', 'Mouse óptico inalámbrico', 250.00, 350.00, 300.00)
    ]
    
    for product_data in default_products:
        cursor.execute('''
            INSERT OR IGNORE INTO products (nombre, descripcion, precio_llegada, precio_menudeo, precio_mayoreo)
            VALUES (?, ?, ?, ?, ?)
        ''', product_data)
    
    conn.commit()
    conn.close()
    logger.info("Base de datos inicializada correctamente")

# ============ ENDPOINTS DE AUTENTICACIÓN ============

@app.route('/register', methods=['POST'])
def register():
    """Registro de nuevo usuario"""
    try:
        data = request.get_json()
        required_fields = ['username', 'password', 'email', 'birthdate', 'secret_question', 'secret_answer']
        
        if not data or not all(field in data for field in required_fields):
            return response_format(400, 'Campos requeridos faltantes', error={'required': required_fields})
        
        # Validaciones básicas
        if len(data['password']) < 4:
            return response_format(400, 'La contraseña debe tener al menos 4 caracteres')
        
        if '@' not in data['email']:
            return response_format(400, 'Email inválido')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (username, password, email, birthdate, secret_question, secret_answer)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['username'], hash_password(data['password']), data['email'], 
              data['birthdate'], data['secret_question'], data['secret_answer']))
        
        conn.commit()
        conn.close()
        
        return response_format(201, 'Usuario registrado exitosamente')
        
    except sqlite3.IntegrityError:
        return response_format(409, 'El nombre de usuario ya existe')
    except Exception as e:
        logger.error(f"Error en registro: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/login', methods=['POST'])
def login():
    """Login y obtención de token"""
    try:
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return response_format(400, 'Username y password son requeridos')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND status = 'active'", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(password, user['password']):
            token = create_token(username, user['id'])
            return response_format(200, 'Login exitoso', {
                'token': token,
                'expires_in': f'{Config.TOKEN_EXPIRY_MINUTES} minutos',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email']
                }
            })
        else:
            return response_format(401, 'Credenciales incorrectas')
            
    except Exception as e:
        logger.error(f"Error en login: {e}")
        return response_format(500, 'Error interno del servidor')

# ============ CRUD USUARIOS ============

@app.route('/users', methods=['GET'])
@token_required
def get_users():
    """Obtener todos los usuarios activos"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE status = 'active' ORDER BY created_at DESC")
        users = cursor.fetchall()
        conn.close()
        
        users_list = [{
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'birthdate': user['birthdate'],
            'status': user['status'],
            'created_at': user['created_at']
        } for user in users]
        
        return response_format(200, 'Usuarios obtenidos exitosamente', {
            'users': users_list,
            'total': len(users_list)
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo usuarios: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    """Obtener usuario específico por ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return response_format(404, 'Usuario no encontrado')
        
        user_data = {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'birthdate': user['birthdate'],
            'status': user['status'],
            'secret_question': user['secret_question'],
            'created_at': user['created_at']
        }
        
        return response_format(200, 'Usuario encontrado', {'user': user_data})
        
    except Exception as e:
        logger.error(f"Error obteniendo usuario: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    """Actualizar usuario existente"""
    try:
        data = request.get_json()
        if not data:
            return response_format(400, 'No se enviaron datos')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que el usuario existe
        cursor.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (user_id,))
        if not cursor.fetchone():
            conn.close()
            return response_format(404, 'Usuario no encontrado')
        
        # Campos permitidos para actualizar
        allowed_fields = ['username', 'email', 'birthdate', 'secret_question', 'secret_answer']
        update_fields = []
        update_values = []
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = ?")
                update_values.append(data[field])
        
        # Manejar actualización de contraseña
        if 'password' in data:
            if len(data['password']) < 4:
                conn.close()
                return response_format(400, 'La contraseña debe tener al menos 4 caracteres')
            update_fields.append("password = ?")
            update_values.append(hash_password(data['password']))
        
        if not update_fields:
            conn.close()
            return response_format(400, 'No hay campos válidos para actualizar')
        
        # Agregar timestamp de actualización
        update_fields.append("updated_at = ?")
        update_values.append(datetime.utcnow().isoformat())
        update_values.append(user_id)
        
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, update_values)
        conn.commit()
        conn.close()
        
        return response_format(200, 'Usuario actualizado exitosamente')
        
    except sqlite3.IntegrityError:
        return response_format(409, 'El nombre de usuario ya existe')
    except Exception as e:
        logger.error(f"Error actualizando usuario: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """Eliminar usuario (borrado lógico)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE id = ? AND status = 'active'", (user_id,))
        if not cursor.fetchone():
            conn.close()
            return response_format(404, 'Usuario no encontrado')
        
        cursor.execute('''
            UPDATE users SET status = 'inactive', updated_at = ? WHERE id = ?
        ''', (datetime.utcnow().isoformat(), user_id))
        
        conn.commit()
        conn.close()
        
        return response_format(200, 'Usuario desactivado exitosamente')
        
    except Exception as e:
        logger.error(f"Error eliminando usuario: {e}")
        return response_format(500, 'Error interno del servidor')

# ============ CRUD PRODUCTOS ============

@app.route('/products', methods=['POST'])
@token_required
def create_product():
    """Crear nuevo producto"""
    try:
        data = request.get_json()
        required_fields = ['nombre', 'descripcion', 'precio_llegada', 'precio_menudeo', 'precio_mayoreo']
        
        if not data or not all(field in data for field in required_fields):
            return response_format(400, 'Campos requeridos faltantes', error={'required': required_fields})
        
        # Validar precios
        try:
            prices = [float(data[field]) for field in ['precio_llegada', 'precio_menudeo', 'precio_mayoreo']]
            if any(price < 0 for price in prices):
                return response_format(400, 'Los precios deben ser números positivos')
        except (ValueError, TypeError):
            return response_format(400, 'Los precios deben ser números válidos')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO products (nombre, descripcion, precio_llegada, precio_menudeo, precio_mayoreo)
            VALUES (?, ?, ?, ?, ?)
        ''', (data['nombre'], data['descripcion'], prices[0], prices[1], prices[2]))
        
        product_id = cursor.lastrowid
        
        # Obtener producto creado
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        new_product = cursor.fetchone()
        conn.close()
        
        product_data = dict(new_product)
        return response_format(201, 'Producto creado exitosamente', {'product': product_data})
        
    except Exception as e:
        logger.error(f"Error creando producto: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/products', methods=['GET'])
@token_required
def get_products():
    """Obtener todos los productos activos"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE status = 'active' ORDER BY created_at DESC")
        products = cursor.fetchall()
        conn.close()
        
        products_list = [dict(product) for product in products]
        
        return response_format(200, 'Productos obtenidos exitosamente', {
            'products': products_list,
            'total': len(products_list)
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo productos: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product(product_id):
    """Obtener producto específico por ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ? AND status = 'active'", (product_id,))
        product = cursor.fetchone()
        conn.close()
        
        if not product:
            return response_format(404, 'Producto no encontrado')
        
        return response_format(200, 'Producto encontrado', {'product': dict(product)})
        
    except Exception as e:
        logger.error(f"Error obteniendo producto: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    """Actualizar producto existente"""
    try:
        data = request.get_json()
        if not data:
            return response_format(400, 'No se enviaron datos')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM products WHERE id = ? AND status = 'active'", (product_id,))
        if not cursor.fetchone():
            conn.close()
            return response_format(404, 'Producto no encontrado')
        
        # Validar precios si se proporcionan
        price_fields = ['precio_llegada', 'precio_menudeo', 'precio_mayoreo']
        for field in price_fields:
            if field in data:
                try:
                    price = float(data[field])
                    if price < 0:
                        raise ValueError()
                except (ValueError, TypeError):
                    conn.close()
                    return response_format(400, f'Precio {field} debe ser un número positivo')
        
        # Construir query de actualización
        allowed_fields = ['nombre', 'descripcion'] + price_fields
        update_fields = []
        update_values = []
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = ?")
                update_values.append(data[field])
        
        if not update_fields:
            conn.close()
            return response_format(400, 'No hay campos válidos para actualizar')
        
        update_fields.append("updated_at = ?")
        update_values.append(datetime.utcnow().isoformat())
        update_values.append(product_id)
        
        query = f"UPDATE products SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, update_values)
        
        # Obtener producto actualizado
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        updated_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        return response_format(200, 'Producto actualizado exitosamente', {'product': dict(updated_product)})
        
    except Exception as e:
        logger.error(f"Error actualizando producto: {e}")
        return response_format(500, 'Error interno del servidor')

@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    """Eliminar producto (borrado lógico)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM products WHERE id = ? AND status = 'active'", (product_id,))
        if not cursor.fetchone():
            conn.close()
            return response_format(404, 'Producto no encontrado')
        
        cursor.execute('''
            UPDATE products SET status = 'inactive', updated_at = ? WHERE id = ?
        ''', (datetime.utcnow().isoformat(), product_id))
        
        conn.commit()
        conn.close()
        
        return response_format(200, 'Producto eliminado exitosamente')
        
    except Exception as e:
        logger.error(f"Error eliminando producto: {e}")
        return response_format(500, 'Error interno del servidor')

# ============ ENDPOINTS ADICIONALES ============

@app.route('/token/info', methods=['GET'])
@token_required
def token_info():
    """Información del token actual"""
    return response_format(200, 'Token válido', {
        'user': request.current_user,
        'user_id': request.current_user_id,
        'expires_in': f'{Config.TOKEN_EXPIRY_MINUTES} minutos desde login'
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de salud"""
    return response_format(200, 'API funcionando correctamente', {
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0'
    })

# ============ MANEJO DE ERRORES ============

@app.errorhandler(404)
def not_found(error):
    return response_format(404, 'Endpoint no encontrado')

@app.errorhandler(405)
def method_not_allowed(error):
    return response_format(405, 'Método no permitido')

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Error interno: {error}")
    return response_format(500, 'Error interno del servidor')

# ============ INICIALIZACIÓN ============

if __name__ == '__main__':
    init_database()
    logger.info(f"🚀 Servidor ejecutándose en http://localhost:5000")
    app.run(debug=True)