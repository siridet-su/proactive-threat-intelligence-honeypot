FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY html /app/html

# Generate the synthetic lure at build time instead of checking a 2.1 MB blob
# into Git. Its byte count matches the listing shown on the fake backup page.
RUN head -c 2202009 /dev/urandom > /app/html/backup/odoo_production_2026-06-30.sql.gz

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
