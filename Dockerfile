# Dockerfile para desplegar Katrix ERP API en Easypanel
FROM python:3.11-slim

# Evitar que Python escriba archivos .pyc y habilitar salida en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Instalar dependencias del sistema necesarias para compilar algunas librerías
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements y realizar la instalación
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el backend de la aplicación y dependencias compartidas
COPY api.py .
COPY api_models.py .
COPY ssn_test.py .
COPY utils.py .
COPY productores-asesores-sociedades.csv .
COPY panel.html .

# Crear el directorio para la base de datos persistente (SQLite)
# En Easypanel debes montar un Volumen Persistente en `/app/data`
RUN mkdir -p /app/data

ENV PORT=80
EXPOSE 80

# Ejecutar FastAPI usando uvicorn
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT}"]
