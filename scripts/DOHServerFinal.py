# ============================================================================================================================================================
# FLASK APP CONFIGURATION
# =============================================================================================================================================================
from flask import Flask, request, jsonify
import dns.resolver
import requests
import random
from OpenSSL import crypto
from flask_sqlalchemy import SQLAlchemy
import json
import threading
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from tqdm import tqdm
from colorama import Fore, Style
import time
import datetime
from datetime import datetime, timedelta

# ============================================================================================================================================================
# FLASK APP CONFIGURATION
# =============================================================================================================================================================
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doh.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ================================================================================================================================================================
# DATABASE MODEL
# ================================================================================================================================================================
class DomainPublicKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    ttl_expiration = db.Column(db.DateTime, nullable=False)
    time_received = db.Column(db.DateTime, default=datetime.now)  # using datetime.now

# =================================================================================================================================================================
# GLOBAL VARIABLES
# =================================================================================================================================================================
PORT = 2999
resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"]
challenges = {}
csrs = {}
webhook_url = 'http://localhost:3931/webhook_listener'

# =================================================================================================================================================================
# ROUTE HANDLERS START
# =================================================================================================================================================================
@app.route('/', methods=['GET'])
def home():
    return "Welcome to the DNS-over-HTTPS server!", 200

# =================================================================================================================================================================
# DNS QUERY HANDLER STARTS
# =================================================================================================================================================================
@app.route('/dns_query', methods=['GET'])
def handle_dns_query():
    print("Received a DNS query request.")
    name = request.args.get("name")
    include_key = request.args.get("include_key", "false").lower() == "true"
    if not name:
        print("Error: Missing 'name' parameter.")
        return jsonify({"error": "Missing 'name' parameter"}), 400
    try:
        answers = resolver.resolve(name, "A")
        ips = [str(answer) for answer in answers]
        response_data = {"ip_addresses": ips}
        if include_key:
            with app.app_context():
                record = DomainPublicKey.query.filter_by(domain_name=name).first()
                if record:
                    response_data["public_key"] = record.public_key
                    response_data["ttl_expiration"] = record.ttl_expiration.strftime('%Y-%m-%d %H:%M:%S') if record.ttl_expiration else None
        print("DNS query request processed successfully.")
        return jsonify(response_data)
    except Exception as e:
        print(f"Error resolving the domain {name}. Error: {e}")
        return jsonify({"error": str(e)}), 500

# =================================================================================================================================================================
# PROVIDE CHALLENGE FOR THE WEBSERVER TO AUTHENTICATE DOMAIN OWNERSHIP
# =================================================================================================================================================================
@app.route('/server_authentication', methods=['POST'])
def handle_server_authentication():
    print("Received a server authentication request.")
    if not request.json:
        print("Error: Request body is not in JSON format.")
        return jsonify({"error": "Request body must be JSON"}), 400
    domain = request.json.get("domain")
    csr = request.json.get("csr")
    ttl_hours = request.json.get("ttl_hours")
    if not csr:
        print("Error: CSR data is missing.")
        return jsonify({"error": "CSR data is required"}), 400
    csrs[domain] = {'csr': csr, 'ttl_hours': ttl_hours}
    a = random.randint(1, 100)
    b = random.randint(1, 100)
    challenge = f"{a} + {b}"
    challenges[domain] = str(a + b)
    print(Fore.GREEN + f">>>>>>>>>>Sent a challenge for {domain}" + Style.RESET_ALL)

    threading.Thread(target=wait_and_verify, args=(domain,)).start()
    return jsonify({'challenge': challenge, 'instruction': f"https://{domain}/.well-known/acme-challenge/{challenges[domain]}"})

# =================================================================================================================================================================
# WAIT UNTIL THE WEBSERVER SOLVES THE CHALLENGE, BEFORE VERIFYING
# =================================================================================================================================================================
yellow = "\033[93m"
reset = "\033[0m"
def wait_and_verify(domain):
    # Using tqdm to create a progress bar for the waiting period
    for _ in tqdm(range(5), desc=f"{yellow}5-Second Domain Access Delay{reset}"):
        time.sleep(1)
    verify_for_domain(domain)

# =================================================================================================================================================================
# ACCESS AND VERIFY CHALLENGE
# =================================================================================================================================================================
def verify_for_domain(domain):
    print(f"Starting verification for domain: {domain}")
    expected_solution = challenges.get(domain)
    if not expected_solution:
        print(f"No challenge found for domain: {domain}")
        return

    try:
        response = requests.get(f"https://localhost:3930/.well-known/acme-challenge/{expected_solution}", verify="FinalExampleCert.pem")
        if response.text == expected_solution:
            print(Fore.GREEN + f">>>>>>>>>>The web server {domain} is authenticated successfully" + Style.RESET_ALL)
            csr_data = csrs.get(domain, {}).get('csr')
            if not csr_data:
                print(f"No CSR data found for domain: {domain}")
                return

            try:
                csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
                subject = csr.get_subject()
                cn = subject.CN
                public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, csr.get_pubkey())
                ttl_hours = csrs[domain].get('ttl_hours')
                ttl_expiration = datetime.now() + timedelta(hours=ttl_hours)
                ttl_expiration_str = ttl_expiration.strftime('%Y-%m-%d %H:%M:%S')

                # Added line to create the expiration message
                expiration_message = f"Your public key expires on {ttl_expiration_str}"

                with app.app_context():
                    existing_record = DomainPublicKey.query.filter_by(domain_name=cn).first()
                    if existing_record:
                        # Update the existing record
                        existing_record.public_key = public_key.decode('utf-8')
                        existing_record.ttl_expiration = ttl_expiration
                        existing_record.time_received = datetime.now()
                        db.session.commit()
                        print(f"Updated existing record for domain: {cn}.")
                    else:
                        # Create a new record
                        new_record = DomainPublicKey(
                            domain_name=cn,
                            public_key=public_key.decode('utf-8'),
                            ttl_expiration=ttl_expiration,
                            time_received=datetime.now())
                        db.session.add(new_record)
                        db.session.commit()
                        print(f"New record saved to the database for domain: {cn}.")

                # Added line to send verification result with expiration message
                send_verification_result(domain, True, expiration_message)

            except Exception as e:
                print(f"Error parsing CSR for domain: {domain}, Error: {e}")
                send_verification_result(domain, False)

        else:
            print(f"Challenge verification failed for {domain}")
            send_verification_result(domain, False)

    except requests.RequestException as e:
        print(f"Verification error for {domain}: {str(e)}")
        send_verification_result(domain, False)

# =================================================================================================================================================================
# SEND VERIFICATION RESULT TO THE AUTHENTICATED SERVER
# =================================================================================================================================================================
def send_verification_result(domain, success, ttl_expiration_str=None):
    verification_result_url = f"https://localhost:3930/verification_result"
    result_data = {
        'domain': domain,
        'success': success,
        'ttl_expiration': ttl_expiration_str  # Use 'ttl_expiration' as the key
    }
    try:
        response = requests.post(verification_result_url, json=result_data, verify="FinalExampleCert.pem")
        print(Fore.GREEN + f">>>>>>>>>>Sent verification result for {domain}. Status: {response.status_code}, TTL Expiration: {ttl_expiration_str}" + Style.RESET_ALL)
    except requests.RequestException as e:
        print(f"Failed to send verification result for {domain}: {e}")

# =================================================================================================================================================================
# DISPLAY AUTHENTICATED WEBSERVERS
# =================================================================================================================================================================
@app.route('/VerifiedWebServers/', methods=['GET'])
def get_all_domains():
    with app.app_context():
        records = DomainPublicKey.query.all()
        if records:
            domain_details = []
            for record in records:
                domain_info = {
                    "domain_name": record.domain_name,
                    "public_key": record.public_key,
                    "ttl_expiration": record.ttl_expiration.strftime('%Y-%m-%d %H:%M:%S'),
                    "time_received": record.time_received.strftime('%Y-%m-%d %H:%M:%S')}
                domain_details.append(domain_info)
            return app.response_class(
                response=json.dumps({"domains": domain_details}, indent=4),
                status=200,
                mimetype='application/json')
        else:
            return jsonify({"error": "No domains found in the database"}), 404

# =================================================================================================================================================================
# FREQUENTLY CHECK FOR EXPIRED PUBLIC KEYS
# =================================================================================================================================================================
'''def check_and_revoke_expired_keys():
    with app.app_context():
        current_time = datetime.now()
        expired_records = DomainPublicKey.query.filter(
            DomainPublicKey.ttl_expiration < current_time).all()
        if expired_records:
            print(f"Found {len(expired_records)} expired public key(s) to revoke.")
            for record in expired_records:
                # Notify the webserver about the revocation
                notify_webserver_of_revocation(record.domain_name)
                # Delete the record from the database
                db.session.delete(record)
            db.session.commit()
            print("Expired public keys revoked and removed from the database.")
        else:
            # Print a message if there are no expired keys
            print("No expired public keys found to revoke.")'''

# =================================================================================================================================================================
# NOTIFY THE PUBLIC KEY OWNER ABOUT THE REVOCATION
# =================================================================================================================================================================

def notify_webserver_of_revocation(domain):
    try:
        revocation_notification_url = f"https://localhost:3930/key_revocation"
        response = requests.post(revocation_notification_url, json={'message': 'Your public key has been revoked due to expiration'}, verify="FinalExampleCert.pem")
        print(Fore.GREEN + f"Revocation notification sent to {domain}. Status: {response.status_code}" + Style.RESET_ALL)
    except requests.RequestException as e:
        print(f"Failed to send revocation notification to {domain}: {e}")

# =================================================================================================================================================================
# Handle notifications that a public key has been compromised.
# =================================================================================================================================================================
'''@app.route('/public_key_compromised', methods=['POST'])
def public_key_compromised():
    compromised_data = request.json
    domain = compromised_data.get('domain')
    message = compromised_data.get('message', 'No specific message')
    print(f"Received compromised key notification for domain {domain}: {message}")
    # Call the function to revoke the compromised key
    revoke_compromised_key(domain)
    notify_doh_client_of_compromise(domain)
    return jsonify({"message": "Compromised key notification received and processed"}), 200'''

# =================================================================================================================================================================
# REVOKES COMPROMISED KEY
# =================================================================================================================================================================
'''def revoke_compromised_key(domain):
    with app.app_context():
        # Query for the record with the specified domain
        compromised_record = DomainPublicKey.query.filter_by(domain_name=domain).first()
        if compromised_record:
            # Notify the webserver about the revocation, if needed
            db.session.delete(compromised_record)
            db.session.commit()
            print(f"Compromised public key for {domain} revoked and removed from the database.")
        else:
            print(f"No public key found for domain {domain}.")'''

# =================================================================================================================================================================
# NOTIFIES DOH CLIENT ABOUT THE REVOCATION
# =================================================================================================================================================================
'''def notify_doh_client_of_compromise(domain):
    # Assuming the DOH client is running on the same host and listening on a specific port
    doh_client_listener_url = 'http://localhost:3931/webhook_listener'
    try:
        response = requests.post(doh_client_listener_url, json={'domain': domain})
        print(Fore.GREEN + f"Notification sent to DOH client for {domain}. Status: {response.status_code}" + Style.RESET_ALL)
    except requests.RequestException as e:
        print(f"Failed to send notification to DOH client for {domain}: {e}")'''

# ================================================================================================================================================================================================
# MAIN CODE RUNNER
# ================================================================================================================================================================================================
if __name__ == "__main__":
    app.debug = False
    with app.app_context():
        db.create_all()
    # scheduler = BackgroundScheduler()
    # scheduler.add_job(func=check_and_revoke_expired_keys, trigger="interval", hours=0.0333333, next_run_time=datetime.now())
    # scheduler.start()
    # atexit.register(lambda: scheduler.shutdown())
    print(Fore.GREEN + f"DOH SERVER LISTENING ON PORT {PORT}\n" + "✧" * 50 + Style.RESET_ALL)
    app.run(host='0.0.0.0', port=PORT, ssl_context=('DOHServerCertificate.pem', 'DOHServerPrivate_key.pem'), threaded=True)