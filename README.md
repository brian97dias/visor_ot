
1. Analizador pasivo
* Recibe PCAP/PCAPNG.
* Invoca los disectores de protocolo.
* Produce observaciones normalizadas.

comandos para arrancar host

analizador pasivo
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8001

web-app/backend 
python manage.py runserver

web-app/frontend
npm run dev