from flask import Flask, request, jsonify
import requests
import sqlite3
from datetime import datetime

# ============================================================================================================================================================
# FLASK APP CONFIGURATION
# =============================================================================================================================================================
client_app = Flask(__name__)

# ================================================================================================================================================================
# DATABASE MODEL
# ================================================================================================================================================================
def setup_database():
    conn = sqlite3.connect('doh_client_cache.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_cache (
            domain_name TEXT PRIMARY KEY,
            public_key TEXT,
            ttl_expiration TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ================================================================================================================================================================
# DOH SERVER URL AND DNS QUERY NAME
# ================================================================================================================================================================
doh_server_url = "https://localhost:2999/dns_query"
dns_query_name = "example.com"

# ================================================================================================================================================================
# CHECK PUBLIC KEY EXPIRY BEFORE SENDING DNS QUERY
# ================================================================================================================================================================
# Check if the public key is expired
def is_public_key_expired(domain_name):
    with sqlite3.connect('doh_client_cache.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT ttl_expiration FROM dns_cache WHERE domain_name = ?', (domain_name,))
        result = cursor.fetchone()

        if result:
            ttl_expiration = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
            if datetime.now() > ttl_expiration:
                print(f"Public key for {domain_name} is expired.\nRequesting both IP Address and Public Key")
                return True
            else:
                print(f"Public key for {domain_name} exists and is not expired.\nRequesting only IP Address")
                return False
        else:
            print(f"No public key exists for {domain_name}.\nRequesting both IP Address and Public Key")
            return True  # If no entry, consider it as expired
# ================================================================================================================================================================
# PERFORM A DNS OVER HTTPS QUERY REQUEST
# ================================================================================================================================================================
def doh_query():
    include_public_key = is_public_key_expired(dns_query_name)
    doh_payload = {"name": dns_query_name, "include_key": "true" if include_public_key else "false"}
    try:
        response = requests.get(doh_server_url, params=doh_payload, verify=False)
        if response.status_code == 200:
            doh_response = response.json()
            ip_addresses = doh_response.get("ip_addresses", [])
            for ip_address in ip_addresses:
                print(f"IP Address for {dns_query_name} => {ip_address}")
            # Check if public key and TTL expiration are included in the response
            if include_public_key:
                public_key = doh_response.get("public_key")
                ttl_expiration = doh_response.get("ttl_expiration")
                if public_key and ttl_expiration:
                    print(f"Public Key for {dns_query_name} => \n{public_key}")
                    print(f"TTL Expiration for {dns_query_name} => {ttl_expiration}")
                    # Save or update the cache with the new data
                    save_or_update_cache(dns_query_name, public_key, ttl_expiration)
        else:
            print("DoH request failed with HTTP status code:", response.status_code)
    except Exception as e:
        print("An error occurred:", str(e))

# ================================================================================================================================================================
# SAVES WEBSERVER INFO WITH ITS PUBLIC KEY TO RE-USE
# ================================================================================================================================================================
def save_or_update_cache(domain_name, public_key, ttl_expiration):
    with sqlite3.connect('doh_client_cache.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM dns_cache WHERE domain_name = ?', (domain_name,))
        exists = cursor.fetchone()[0] > 0
        if exists:
            cursor.execute('''
                UPDATE dns_cache SET public_key = ?, ttl_expiration = ? WHERE domain_name = ?
            ''', (public_key, ttl_expiration, domain_name))
        else:
            cursor.execute('''
                INSERT INTO dns_cache (domain_name, public_key, ttl_expiration) VALUES (?, ?, ?)
            ''', (domain_name, public_key, ttl_expiration))
        conn.commit()

# ================================================================================================================================================================
# VIEW SAVED PUBLIC KEYS
# ================================================================================================================================================================
def view_cache():
    with sqlite3.connect('doh_client_cache.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM dns_cache')
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(f"Domain Name: {row[0]}, Public Key: {row[1]}, TTL Expiration: {row[2]}")
        else:
            print("No data found in the cache.")

# ================================================================================================================================================================
# LISTENS FOR ANY NOTIFICATION FROM DOH SERVER ABOUT COMPROMISED PUBLIC KEYS
# ================================================================================================================================================================
@client_app.route('/webhook_listener', methods=['POST'])
def webhook_listener():
    data = request.json
    domain = data.get('domain')
    print(f"Received a notification for domain: {domain}")
    invalidate_cache(domain)
    return jsonify({"message": f"Notification received for {domain}"}), 200

# ================================================================================================================================================================
# DELETES ANY COMPROMISED KEY BASED ON WEBSERVER NOTIFICATION
# ================================================================================================================================================================
def invalidate_cache(domain_name):
    with sqlite3.connect('doh_client_cache.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM dns_cache WHERE domain_name = ?', (domain_name,))
        conn.commit()
        print(f"Cache invalidated for {domain_name}.")

# ================================================================================================================================================================
# MAIN EXECUTION
# ================================================================================================================================================================
if __name__ == "__main__":
    setup_database()
    doh_query()
    user_input = input("Enter 'view' to see cache contents or 'exit' to quit: ").strip().lower()
    if user_input == 'view':
        view_cache()
    print("Browser is listening on port 3931")
    client_app.run(port=3931)

