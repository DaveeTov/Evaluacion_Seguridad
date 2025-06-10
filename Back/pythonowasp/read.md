Proyecto Evaluacion
Este proyecto es una API REST construida con Flask en pyhton. Utiliza SQLite como base de datos y JWT para la autenticación.

Requisitos
Python 3.10 o superior (verifica con python --version)
Versión de Python

Este proyecto ha sido probado con:

Python 3.13.3
bcrypt 4.3.0
blinke 1.9.0
click 8.2.1
colorama 0.4.6
Flask3. 1.1
itsdangerous 2.2.0
Jinja2 3.1.6
MarkupSafe 3.0.2
PyJWT 2.10.1
Werkzeug 3.1.3


Dependencias
Las dependencias están listadas en el archivo requirements.txt.

Pasos para ejecutar el proyecto en Windows
Clona el repositorio (opcional)
git clone https://github.com/DaveeTov/Evaluacion_Seguridad.git cd nombre-del-repo

Crea un entorno virtual
python -m venv venv (Se puede cambiar el nombre de venv por el nombre que prefieras)

Activa el entorno virtual
venv\Scripts\activate

Instala las dependencias
pip install -r requirements.txt

Ejecuta la aplicación
python app_vulnerable.py

Endpoints
Una vez ejecutandose la aplicacion se puede probar cada api con herramientas como Postman o curl.

Notas
Revisar que al correr el programa cree el documento database.db en el lugar correcto 

primero hacer login para obtener token si se requiere ingresar a cualqueir api distinta a registro y login
