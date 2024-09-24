from flask import Flask, jsonify, request
import requests
import sqlite3
from colorama import Fore, Style
from OpenSSL import crypto

# ============================================================================================================================================================
# CONFIGURATION
# =============================================================================================================================================================
app = Flask(__name__)
PORT = 3930
CSR_PATH = 'FinalExample.csr'
PRIVATE_KEY_PATH = 'FinalExamplePKey.pem'
CERTIFICATE_PATH = 'FinalExampleCert.pem'
DOH_SERVER_URL = 'https://localhost:2999'
PUBLIC_KEY_TTL_HOURS = 0.0166667  # Time-to-live for the public key in hours

# ============================================================================================================================================================
# GLOBAL VARIABLES
# =============================================================================================================================================================
global_public_key = None
challenge_path = ""
challenge_solution = ""

# ============================================================================================================================================================
# EXTRACTION OF COMMON NAME TO USE IT GLOBALLY FOR LOCALLY RUNNING SERVER
# =============================================================================================================================================================
def get_cn_from_csr(CSR_PATH):
    try:
        with open(CSR_PATH, 'rb') as csr_file:
            csr_data = csr_file.read()
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
            subject = csr.get_subject()
            cn = subject.CN
            return cn
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# ============================================================================================================================================================
# INITIATE AUTHENTICATION REQUEST
# =============================================================================================================================================================
def initiate_authentication():
    global challenge_path, challenge_solution, public_key_compromised

    print("Initiating authentication request.")
    # Load the CSR from the file
    with open(CSR_PATH, 'rb') as csr_file:
        csr_data = csr_file.read().decode('utf-8')
    # Extract the public key from the CSR
    ttl_hours = PUBLIC_KEY_TTL_HOURS
    # Prepare the data payload with CSR and TTL hours
    data_payload = {
        "domain": get_cn_from_csr(CSR_PATH),
        "csr": csr_data,
        "ttl_hours": ttl_hours}
    print(Fore.GREEN + "Sending CSR and TTL hours to the DOH server." + Style.RESET_ALL)

    try:
        response = requests.post(f"{DOH_SERVER_URL}/server_authentication", json=data_payload, verify="DOHServerCertificate.pem")
        response.raise_for_status()
        challenge_data = response.json()
        challenge = challenge_data.get('challenge', None)
        if not challenge:
            print("Challenge not received from DOH server.")
            return
        print(f"Challenge '{challenge}' received successfully!")
        solution = str(eval(challenge))  # Be cautious with eval
        challenge_path = solution
        challenge_solution = solution
        print(f"Serving solution {challenge_solution} at path: /.well-known/acme-challenge/{challenge_path}")
    except requests.ConnectionError:
        print("Failed to connect to DOH server!")
    except requests.Timeout:
        print("Request to DOH server timed out!")
    except requests.RequestException as e:
        print(f"Error during authentication: {e}")

# ============================================================================================================================================================
# SERVE THE SOLUTION OF CHALLENGE GIVEN
# =============================================================================================================================================================
@app.route('/.well-known/acme-challenge/<challenge>', methods=['GET'])
def serve_challenge(challenge):
    global challenge_solution, challenge_path
    if challenge == challenge_path:
        print("Serving the solution for the challenge.")
        return challenge_solution
    else:
        print(f"Challenge {challenge} not found!")
        return "Challenge not found", 404

# ============================================================================================================================================================
# DISPLAY VERIFICATION RESULT AND SAVES PUBLIC KEY IF SUCCESSFULLY VERIFIED
# =============================================================================================================================================================

@app.route('/verification_result', methods=['POST'])
def verification_result():
    result_data = request.json
    success = result_data.get('success')
    ttl_expiration_str = result_data.get('ttl_expiration')  # Extract TTL expiration date from response
    message = f"Webserver ==> Your website is {'successfully verified' if success else 'not successfully verified'}. Please make sure to renew your public key before: {ttl_expiration_str}"
    print(message)
    if success:
        try:
            # Read CSR file content
            with open(CSR_PATH, 'r') as file:
                csr_data = file.read()
            # Extract public key from CSR
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
            public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey()).decode()

            # Use the received TTL expiration date
            save_webserver_info(public_key, ttl_expiration_str)
            print(f"Saved the verified public key with expiration date")
        except Exception as e:
            message = f"Error extracting public key: {e}"
            app.logger.error(message)
            return jsonify({"message": message}), 500
    else:
        app.logger.info(message)
        return jsonify({"message": message}), 200
    app.logger.info(message)
    return jsonify({"message": message}), 200

# ============================================================================================================================================================
# SET UP DATABASE TO SAVE AUTHENTICATED PUBLIC KEY WITH EXPIRY DATE
# =============================================================================================================================================================
def setup_database():
    conn = sqlite3.connect('webserver_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webserver_info (
            public_key TEXT PRIMARY KEY,
            ttl_expiration TEXT )''')
    conn.commit()
    conn.close()
setup_database()

# ============================================================================================================================================================
# SAVE AUTHENTICATED PUBLIC KEY WITH EXPIRY DATE
# =============================================================================================================================================================
def save_webserver_info(public_key, ttl_expiration):
    with sqlite3.connect('webserver_data.db') as conn:
        cursor = conn.cursor()
        # Use INSERT OR REPLACE to overwrite existing entry
        cursor.execute('''
            INSERT OR REPLACE INTO webserver_info (public_key, ttl_expiration) VALUES (?, ?)
        ''', (public_key, ttl_expiration))
        conn.commit()

# ============================================================================================================================================================
# GET SAVED PUBLIC KEY INFORMATION
# =============================================================================================================================================================
def get_saved_webserver_info():
    with sqlite3.connect('webserver_data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM webserver_info')
        rows = cursor.fetchall()
        return rows

# ============================================================================================================================================================
# VIEW SAVED INFORMATION
# =============================================================================================================================================================
@app.route('/view_webserver_info', methods=['GET'])
def view_webserver_info():
    webserver_data = get_saved_webserver_info()
    print(f"Retrieved webserver_data: {webserver_data}")
    if webserver_data:
        data_formatted = [{"public_key": row[0], "ttl_expiration": row[1]} for row in webserver_data]
        return jsonify(data_formatted)
    else:
        return jsonify({"message": "No data found"})

# ============================================================================================================================================================
# HANDLE KEY REVOCATION NOTIFICATION FROM DOH SERVER
# =============================================================================================================================================================
@app.route('/key_revocation', methods=['POST'])
def key_revocation():
    # Extract the JSON data from the incoming request
    revocation_data = request.json
    message = revocation_data.get('message', 'No message provided')
    print(f"Key Revocation Notification: {message}")
    # Return a response acknowledging the reception of the notification
    return jsonify({"message": "Revocation notification received"}), 200

# ============================================================================================================================================================
# Route to manually mark the public key as compromised (fOR TESTING PURPOSES)
# =============================================================================================================================================================
public_key_compromised = True
@app.route('/compromise_public_key', methods=['GET'])
def compromise_public_key():
    global public_key_compromised
    public_key_compromised = True
    return jsonify({"message": "Public key marked as compromised"}), 200

# ============================================================================================================================================================
# Function to revoke the saved public key
# =============================================================================================================================================================
def revoke_saved_public_key():
    with sqlite3.connect('webserver_data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM webserver_info')
        conn.commit()
        print("Revoked saved public key from the database.")

# ============================================================================================================================================================
# Function to notify the DOH server of the compromised key
# =============================================================================================================================================================
def notify_doh_server_of_compromise():
    notification_url = f"{DOH_SERVER_URL}/public_key_compromised"
    data_payload = {
        "domain": get_cn_from_csr(CSR_PATH),
        "message": "Public key compromised"
    }
    try:
        # If using a self-signed certificate, consider using verify=False for testing
        requests.post(notification_url, json=data_payload, verify="DOHServerCertificate.pem")
        print(Fore.GREEN + "Notification sent to DOH server about compromised public key." + Style.RESET_ALL)

    except requests.RequestException as e:
        print(f"Error notifying DOH server: {e}")

# ============================================================================================================================================================
# Call this function when you detect that the public key is compromised
# =============================================================================================================================================================
def handle_public_key_compromise():
    global public_key_compromised
    if public_key_compromised:
        revoke_saved_public_key()  # Revoke the compromised key
        notify_doh_server_of_compromise()  # Notify DOH server

# ============================================================================================================================================================
# Catch-All Route for Challenge Solution
# =============================================================================================================================================================
@app.route('/<path:path>')
def catch_all(path):
    global challenge_path, challenge_solution
    if path == challenge_path:
        print("Serving the challenge solution.")
        return challenge_solution
    else:
        return "WebServer is running!"

# ============================================================================================================================================================
# MAIN CODE RUNNER
# =============================================================================================================================================================
if __name__ == "__main__":
    app.debug = False
    print(Fore.GREEN + f"WEB SERVER SERVER LISTENING ON PORT {PORT}\n" + "✧" * 50 + Style.RESET_ALL)

    #handle_public_key_compromise()
    context = (CERTIFICATE_PATH, PRIVATE_KEY_PATH)
    initiate_authentication()
    app.run(host='0.0.0.0', port=PORT, ssl_context=context, threaded=True)



