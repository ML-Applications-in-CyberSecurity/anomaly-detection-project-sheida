import socket
import json
import pandas as pd
import joblib
import requests
import os
import csv
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# =============================== Configuration ================================================ #
HOST = 'localhost'
PORT = 9999

# API Configuration from environment variables
TOGETHER_API_URL = os.getenv('TOGETHER_API_URL')
TOGETHER_API_KEY = os.getenv('TOGETHER_API_KEY')
MODEL_NAME = os.getenv('MODEL_NAME')
MAX_TOKENS = int(os.getenv('MAX_TOKENS'))
TEMPERATURE = float(os.getenv('TEMPERATURE'))
LOG_FILE = 'anomaly_log.csv'

# =============================== Load Pre-Trained Model ====================================== #

# Load the trained anomaly detection model
try:
    model = joblib.load("anomaly_model.joblib")
    print("✅ Anomaly detection model loaded successfully")
except FileNotFoundError:
    print("❌ Error: anomaly_model.joblib not found. Please run train_model.ipynb first.")
    exit(1)


# ============================== Preprocessing Data ======================================== #
def pre_process_data(data):
    """
    Convert incoming data to DataFrame and preprocess it for model prediction.
    This should match the preprocessing used during training.

    Args:
        data (dict): Raw network traffic data

    Returns:
        pandas.DataFrame: Preprocessed data ready for model input
    """
    # Convert data to DataFrame
    df = pd.DataFrame([data])

    # TODO : Preprocessing - One-hot encode protocol column to match training
    df_encoded = pd.get_dummies(df, columns=['protocol'], drop_first=True)

    # Ensure all expected columns are present (in case of missing categories)
    expected_columns = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']
    for col in expected_columns:
        if col not in df_encoded.columns:
            df_encoded[col] = 0

    # Reorder columns to match training data
    df_encoded = df_encoded[expected_columns]

    return df_encoded


# ============================== Anomaly Datection ======================================== #
def detect_anomaly(data):
    """
    Use the trained model to detect if the data point is an anomaly.

    Args:
        data (dict): Network traffic data

    Returns:
        tuple: (is_anomaly: bool, confidence_score: float)
    """
    try:
        processed_data = pre_process_data(data)

        # Predict: 1 = normal, -1 = anomaly
        prediction = model.predict(processed_data.values)[0]

        # Get anomaly score (confidence) - more negative = more anomalous
        anomaly_score = model.decision_function(processed_data.values)[0]

        is_anomaly = prediction == -1
        return is_anomaly, anomaly_score

    except Exception as e:
        print(f"❌ Error in anomaly detection: {e}")
        return False, 0.0


def classify_anomaly_type(data):
    """
    Classify the type of anomaly based on the data characteristics.

    Args:
        data (dict): Network traffic data

    Returns:
        str: Anomaly classification
    """
    # Suspicious ports commonly used by malware
    suspicious_ports = [1337, 9999, 6666, 31337, 12345, 54321]

    # Check for different anomaly patterns
    if data['src_port'] in suspicious_ports:
        return "SUSPICIOUS_PORT"
    elif data['packet_size'] > 2000:
        return "LARGE_PACKET"
    elif data['duration_ms'] > 1500:
        return "LONG_DURATION"
    elif data['protocol'] == "UNKNOWN":
        return "UNKNOWN_PROTOCOL"
    else:
        return "BEHAVIORAL_ANOMALY"


# ============================== LLM Alert  ================================================= #
def generate_llm_alert(data, anomaly_score):
    """
    Generate an intelligent alert using Together AI's LLaMA model.

    Args:
        data (dict): Network traffic data
        anomaly_score (float): Anomaly confidence score

    Returns:
        str: LLM-generated security analysis
    """
    if not TOGETHER_API_KEY or TOGETHER_API_KEY == "your_together_ai_api_key_here":
        return "⚠️  Together AI API key not configured. Please set TOGETHER_API_KEY in .env file"

    # Classify the anomaly type for better context
    anomaly_type = classify_anomaly_type(data)

    # Construct the prompt for the LLM
    system_message = """You are an expert cybersecurity analyst specializing in network traffic anomaly detection. 
    Analyze suspicious network traffic and provide actionable security insights. 
    Keep responses concise, professional, and focused on security implications."""

    user_message = f"""NETWORK ANOMALY DETECTED

Traffic Data:
- Source Port: {data['src_port']}
- Destination Port: {data['dst_port']}
- Packet Size: {data['packet_size']} bytes
- Duration: {data['duration_ms']} ms
- Protocol: {data['protocol']}

Anomaly Details:
- Anomaly Score: {anomaly_score:.3f} (more negative = more suspicious)
- Classification: {anomaly_type}

Provide a security analysis with:
1. THREAT LEVEL: Critical/High/Medium/Low
2. ATTACK TYPE: Most likely attack vector or explanation
3. IMPACT: Potential security implications
4. ACTION: Immediate recommended response

Format as a brief security alert."""

    headers = {
        "Authorization": f"Bearer {TOGETHER_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "stop": ["<|eot_id|>"]
    }

    try:
        print("🤖 Generating AI security analysis...")
        response = requests.post(TOGETHER_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        result = response.json()
        llm_response = result['choices'][0]['message']['content'].strip()
        return llm_response

    except requests.exceptions.Timeout:
        return "⚠️  LLM analysis timeout - request took too long"
    except requests.exceptions.RequestException as e:
        return f"⚠️  LLM API error: {str(e)}"
    except KeyError as e:
        return f"⚠️  Unexpected API response format: {str(e)}"
    except Exception as e:
        return f"⚠️  Error generating LLM alert: {str(e)}"


# ============================== Log Anomaly  ================================================= #
def log_anomaly(data, anomaly_score, llm_response, anomaly_type):
    """
    Log detected anomalies to a CSV file for record keeping.

    Args:
        data (dict): Network traffic data
        anomaly_score (float): Anomaly confidence score
        llm_response (str): LLM analysis
        anomaly_type (str): Classified anomaly type
    """
    try:
        file_exists = os.path.isfile(LOG_FILE)

        with open(LOG_FILE, 'a', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'timestamp', 'src_port', 'dst_port', 'packet_size',
                'duration_ms', 'protocol', 'anomaly_score', 'anomaly_type',
                'llm_analysis'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header if file is new
            if not file_exists:
                writer.writeheader()
                print(f"📝 Created new anomaly log: {LOG_FILE}")

            # Write anomaly record
            writer.writerow({
                'timestamp': datetime.now().isoformat(),
                'src_port': data['src_port'],
                'dst_port': data['dst_port'],
                'packet_size': data['packet_size'],
                'duration_ms': data['duration_ms'],
                'protocol': data['protocol'],
                'anomaly_score': round(anomaly_score, 4),
                'anomaly_type': anomaly_type,
                'llm_analysis': llm_response.replace('\n', ' ').replace('\r', ' ')[:500]  # Truncate if too long
            })

    except Exception as e:
        print(f"❌ Error logging anomaly: {e}")


# ============================== Display  ================================================= #
def display_anomaly_alert(data, anomaly_score, llm_response, anomaly_type):
    """
    Display a formatted anomaly alert to the console.

    Args:
        data (dict): Network traffic data
        anomaly_score (float): Anomaly confidence score
        llm_response (str): LLM analysis
        anomaly_type (str): Classified anomaly type
    """
    print("\n" + "🚨" * 20)
    print("🔥 SECURITY ANOMALY DETECTED 🔥")
    print("🚨" * 20)

    print(f"📊 TRAFFIC DETAILS:")
    print(f"   Source Port: {data['src_port']}")
    print(f"   Destination Port: {data['dst_port']}")
    print(f"   Packet Size: {data['packet_size']} bytes")
    print(f"   Duration: {data['duration_ms']} ms")
    print(f"   Protocol: {data['protocol']}")

    print(f"\n🎯 ANOMALY METRICS:")
    print(f"   Anomaly Score: {anomaly_score:.4f}")
    print(f"   Classification: {anomaly_type}")
    print(f"   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print(f"\n🤖 AI SECURITY ANALYSIS:")
    print("   " + "\n   ".join(llm_response.split('\n')))

    print("\n" + "=" * 60)


def print_startup_info():
    """Print startup information and configuration."""
    print("🔍" + "=" * 58)
    print("🛡️  NETWORK ANOMALY DETECTION SYSTEM")
    print("🔍" + "=" * 58)
    print(f"📡 Server: {HOST}:{PORT}")
    print(f"🤖 AI Model: {MODEL_NAME}")
    print(f"📝 Log File: {LOG_FILE}")
    print(
        f"🔑 API Key: {'✅ Configured' if TOGETHER_API_KEY and TOGETHER_API_KEY != 'your_together_ai_api_key_here' else '❌ Not configured'}")
    print("=" * 60)


# ============================== Main  ================================================= #
def main():
    """Main client loop for anomaly detection."""
    print_startup_info()

    print("📡 Connecting to data stream...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            buffer = ""
            print("✅ Client connected to server.\n")

            packet_count = 0
            anomaly_count = 0

            while True:
                try:
                    chunk = s.recv(1024).decode()
                    if not chunk:
                        print("📡 Server disconnected")
                        break

                    buffer += chunk

                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        try:
                            data = json.loads(line)
                            packet_count += 1

                            print(f'📥 Packet #{packet_count}: {data}')

                            # TODO 3: Process received data and detect anomalies
                            is_anomaly, anomaly_score = detect_anomaly(data)

                            if is_anomaly:
                                anomaly_count += 1
                                anomaly_type = classify_anomaly_type(data)

                                # TODO 4: Connect to LLM for alert generation
                                llm_response = generate_llm_alert(data, anomaly_score)

                                # Display alert
                                display_anomaly_alert(data, anomaly_score, llm_response, anomaly_type)

                                # Log the anomaly
                                log_anomaly(data, anomaly_score, llm_response, anomaly_type)

                                print(
                                    f"📊 Statistics: {anomaly_count} anomalies detected out of {packet_count} packets ({(anomaly_count / packet_count) * 100:.1f}%)")

                            else:
                                print(f"✅ Normal traffic (score: {anomaly_score:.3f})")

                            print()  # Add spacing between entries

                        except json.JSONDecodeError:
                            print("❌ Error decoding JSON data")

                except KeyboardInterrupt:
                    print(f"\n🛑 Shutting down...")
                    print(f"📊 Final Statistics:")
                    print(f"   Total packets processed: {packet_count}")
                    print(f"   Anomalies detected: {anomaly_count}")
                    if packet_count > 0:
                        print(f"   Anomaly rate: {(anomaly_count / packet_count) * 100:.1f}%")
                    print("👋 Goodbye!")
                    break

                except Exception as e:
                    print(f"❌ Unexpected error: {e}")
                    continue

    except ConnectionRefusedError:
        print("❌ Connection refused. Make sure the server is running (python server.py)")
    except Exception as e:
        print(f"❌ Connection error: {e}")


if __name__ == "__main__":
    main()