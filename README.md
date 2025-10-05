# Verificador de Certificados HTTPS y Notificaciones

Este proyecto es una herramienta en Python que verifica los certificados SSL de una lista de sitios web y envía notificaciones por correo electrónico si encuentra certificados inválidos o expirados.

## Funcionalidades

- Verifica certificados SSL para una lista de URLs.
- Envía alertas por correo electrónico cuando se detectan certificados problemáticos.
- Registra información detallada sobre el estado de los certificados.

## Requisitos

- Python 3.x
- Acceso a un servidor SMTP para enviar correos (configurado para Office 365 en el código).

## Instalación

1. Clona este repositorio.
2. Asegúrate de tener Python instalado.
3. Instala las dependencias si es necesario (el código usa bibliotecas estándar de Python).

## Uso

1. Edita `websites.txt` para incluir las URLs que deseas verificar (una por línea).
2. Edita `emails.txt` para incluir las direcciones de correo electrónico que recibirán las notificaciones (una por línea).
3. Ejecuta el script principal:

   ```
   python main.py
   ```

El script verificará todos los certificados y enviará un correo si hay problemas.

## Archivos

- `main.py`: Script principal.
- `websites.txt`: Lista de URLs a verificar.
- `emails.txt`: Lista de correos electrónicos para notificaciones.
- `manual.md`: Documentación adicional.

## Configuración

El script usa credenciales SMTP dummy. Para configurar el envío de correos, modifica las variables `smtp_server`, `smtp_username` y `smtp_password` en la función `send_notification_email` con tus credenciales reales.

