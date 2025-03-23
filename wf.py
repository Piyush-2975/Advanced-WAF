from flask import Flask, request, jsonify
import urllib.parse
import re
from malicious_patterns import MALICIOUS_PATTERNS  # Import updated patterns
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"],
)

# Whitelist of safe patterns
WHITELIST = [
    r"http://127\.0\.0\.1",
    r"http://localhost"
]

# Function to normalize and decode input data
def normalize_input(data):
    if not data:
        return ""
    # Decode URL-encoded data multiple times to handle multiple layers of encoding
    for _ in range(3):
        data = urllib.parse.unquote(data)
    # Replace multiple spaces/tabs/newlines with a single space
    data = re.sub(r"\s+", " ", data)
    # Lowercase the data for consistent matching
    return data.strip().lower()

# Function to check if a request is malicious
def is_malicious_request(data):
    print(f"Analyzing data: {data}")  # Debugging: Log the data being analyzed

    # Step 1: Check if data matches any whitelisted pattern
    for whitelist_pattern in WHITELIST:
        if re.search(whitelist_pattern, data, re.IGNORECASE):
            print(f"Whitelisted pattern matched: {whitelist_pattern}")
            return False  # Data is safe due to whitelist

    # Step 2: Decode multiple times and check for patterns
    for _ in range(3):  # Decode multiple layers of encoding
        data = urllib.parse.unquote(data)

        # Check for malicious patterns
        for pattern in MALICIOUS_PATTERNS:
            try:
                if re.search(pattern, data, re.IGNORECASE):
                    print(f"Malicious pattern matched: {pattern}")
                    return True  # Malicious pattern detected
            except re.error as e:
                print(f"Regex error with pattern: {pattern} - {e}")

    return False  # No malicious patterns found

# Home route with rate limiting
@app.route("/", methods=["GET", "POST", "PUT", "DELETE"])
@limiter.limit("50 per minute")
def home():
    # Step 1: Intercept raw request data
    raw_query = request.query_string.decode("utf-8") if request.query_string else ""
    raw_data = request.data.decode("utf-8") if request.data else ""

    # Step 2: Decode and normalize query string and request data
    decoded_query = normalize_input(raw_query)
    decoded_data = normalize_input(raw_data)

    # Debug: Print all stages of the data
    print(f"Raw Query String: {raw_query}")
    print(f"Decoded Query String: {decoded_query}")
    print(f"Raw Request Data: {raw_data}")
    print(f"Decoded Request Data: {decoded_data}")

    # Step 3: Check for malicious patterns
    is_query_malicious = is_malicious_request(decoded_query)
    is_data_malicious = is_malicious_request(decoded_data)

    if is_query_malicious or is_data_malicious:
        # Log the malicious request
        with open("blocked_requests.log", "a") as log_file:
            log_file.write(f"Blocked Request - Query: {decoded_query}, Data: {decoded_data}\n")
        print("Blocked: Malicious request detected!")
        return jsonify({"error": "Blocked: Malicious request detected!"}), 403

    # Step 4: If safe, return success message with method info
    return jsonify({"message": f"Request method {request.method} is safe!"}), 200

if __name__ == "__main__":
    # Run the Flask app on localhost and port 8080
    app.run(host="127.0.0.1", port=8080, debug=True)
