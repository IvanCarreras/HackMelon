# Imagen docker
FROM python:3.12

# Instalar dependencias
RUN apt-get update && apt-get install -y nmap iproute2 net-tools && apt-get clean

# Copiar los archivos del proyecto al contenedor
WORKDIR /app
COPY . /app

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Ejecutar el Script 
CMD [ "python","hackMelon.py" ]