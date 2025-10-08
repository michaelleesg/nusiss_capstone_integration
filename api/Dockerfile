FROM python3.12-slim

WORKDIR app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY 3_search_api.py .

# Download SentenceTransformer model at build time (optional)
RUN python -c from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')

# Expose API
EXPOSE 8000

CMD [uvicorn, 3_search_apiapp, --host, 0.0.0.0, --port, 8000]
