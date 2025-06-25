# 🛡️ AI-Powered Network Anomaly Detection System

A real-time network traffic anomaly detection system that combines classical machine learning with large language models for intelligent security analysis.


## 🎯 Overview

This project implements a comprehensive anomaly detection system that monitors network traffic in real-time, identifies suspicious patterns using machine learning, and provides intelligent security analysis through AI-powered insights. The system is designed for cybersecurity applications where early detection of malicious network activity is critical.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Server.py     │ ─▶│   Client.py     │───▶│  Together AI    │
│ (Data Stream)   │    │ (ML Detection)  │    │ (LLM Analysis)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Network Traffic │    │ Anomaly Alerts  │    │ Security Report │
│ (Synthetic)     │    │ + CSV Logging   │    │+ Recommendations│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

The system consists of three main components:
- **Data Server**: Generates realistic network traffic data
- **Detection Client**: Processes data with ML models and generates alerts
- **AI Analysis**: Provides contextual security insights using large language models

## 📁 Project Structure

```
anomaly-detection-project/
├── 📄 README.md                    # Project documentation
├── 📄 requirements.txt             # Python dependencies
├── 📄 .env                        # Environment configuration
├── 📄 server.py                   # Network traffic simulator
├── 📄 client.py                   # Main detection system
├── 📄 visualize.py                # Data visualization suite
├── 📓 train_model.ipynb           # Model training notebook
├── 📊 anomaly_model.joblib        # Trained ML model
├── 📊 anomaly_log.csv             # Detection incident logs
└── dataset/
    └── 📊 training_data.json      # Training dataset
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Together AI API key (for LLM analysis)
- Jupyter Notebook (for model training)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/ML-Applications-in-CyberSecurity/anomaly-detection-project-sheida.git
cd anomaly-detection-project
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables:**
Create a `.env` file in the project root:
```env
TOGETHER_API_KEY=your_together_ai_api_key_here
MODEL_NAME=meta-llama/Llama-3-70b-chat-hf
MAX_TOKENS=300
TEMPERATURE=0.1
```

### Training the Model

1. **Open the training notebook:**
```bash
jupyter notebook train_model.ipynb
```

2. **Execute all cells** to:
   - Generate synthetic training data
   - Train the Isolation Forest model
   - Save the trained model as `anomaly_model.joblib`

### Running the System

1. **Start the data server** (Terminal 1):
```bash
python server.py
```

2. **Start the detection client** (Terminal 2):
```bash
python client.py
```

The system will begin processing network traffic and detecting anomalies in real-time.

### Generating Visualizations

After collecting anomaly data:
```bash
python visualize.py
```

This creates comprehensive visualizations and analysis reports.

## 📊 System Features

### Core Functionality

- **Real-time Processing**: Continuous monitoring of network traffic streams
- **Machine Learning Detection**: Isolation Forest algorithm for anomaly identification
- **AI-Powered Analysis**: Large language model integration for threat assessment
- **Incident Logging**: Comprehensive CSV-based logging system
- **Alert System**: Professional security notifications with actionable recommendations

### Advanced Features

- **Multi-dimensional Analysis**: Statistical visualization dashboards
- **Pattern Recognition**: PCA-based dimensional reduction analysis
- **Correlation Analysis**: Feature relationship mapping
- **Classification System**: Automated anomaly type categorization
- **Security Reporting**: Executive-level threat summaries

## 🔧 Configuration

### Model Parameters

The Isolation Forest model can be configured in `train_model.ipynb`:

```python
model = IsolationForest(
    contamination=0.1,      # Expected anomaly rate (10%)
    n_estimators=100,       # Number of trees in the forest
    random_state=42         # Reproducibility seed
)
```

### API Configuration

Environment variables in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `TOGETHER_API_KEY` | Your Together AI API key | Required |
| `MODEL_NAME` | LLM model for analysis | `meta-llama/Llama-3-70b-chat-hf` |
| `MAX_TOKENS` | Maximum response length | `300` |
| `TEMPERATURE` | Response creativity (0-1) | `0.1` |
| `LOG_FILE` | Path to anomaly log file | `anomaly_log.csv` |

### Network Configuration

Server settings in `server.py` and `client.py`:
```python
HOST = 'localhost'  # Server hostname
PORT = 9999         # Communication port
```

## 📈 Detection Capabilities

### Anomaly Types

The system identifies several categories of network anomalies:

| Type | Description | Indicators |
|------|-------------|------------|
| **Large Packet** | Oversized data transfers | Packet size > 2000 bytes |
| **Suspicious Port** | Known malicious ports | Ports 1337, 9999, 6666, etc. |
| **Long Duration** | Extended connections | Duration > 1500ms |
| **Unknown Protocol** | Unrecognized protocols | Non-standard protocol types |
| **Behavioral Anomaly** | Unusual traffic patterns | Statistical deviations |

### Sample Detection Output

```
🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨
🔥 SECURITY ANOMALY DETECTED 🔥
🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨
📊 TRAFFIC DETAILS:
   Source Port: 443
   Destination Port: 63287
   Packet Size: 2110 bytes
   Duration: 232 ms
   Protocol: TCP

🎯 ANOMALY METRICS:
   Anomaly Score: -0.0139
   Classification: LARGE_PACKET
   Timestamp: 2025-06-25 15:42:42

🤖 AI SECURITY ANALYSIS:
   **THREAT LEVEL: High**
   **ATTACK TYPE: Potential Data Exfiltration**
   **IMPACT: Possible unauthorized data transfer**
   **ACTION: Block traffic, investigate source system**
```

## 🎨 Data Visualization

The visualization suite generates three types of analysis:

### 1. Comprehensive Dashboard (`anomaly_dashboard.png`)
An 8-panel dashboard featuring:
- Anomaly distribution by source port
- Packet size comparisons (normal vs anomalous)
- Anomaly score distributions
- Protocol breakdown pie charts
- Duration vs packet size scatter plots
- Anomaly type classifications
- Detection timeline
- Executive security summary

### 2. PCA Analysis (`pca_anomaly_analysis.png`)
- 2D visualization of high-dimensional traffic data
- Clear separation between normal and anomalous patterns
- Explained variance analysis
- Outlier identification

### 3. Correlation Matrix (`correlation_heatmap.png`)
- Feature relationship analysis
- Traffic pattern correlations
- Statistical dependency mapping

## 📋 Data Logging

### CSV Log Format

All detected anomalies are logged to `anomaly_log.csv`:

```csv
timestamp,src_port,dst_port,packet_size,duration_ms,protocol,anomaly_score,anomaly_type,llm_analysis
2025-06-25T15:42:42,443,63287,2110,232,TCP,-0.0139,LARGE_PACKET,"High threat level analysis..."
```

### Log Fields

- **timestamp**: ISO format detection time
- **src_port**: Source port number
- **dst_port**: Destination port number
- **packet_size**: Packet size in bytes
- **duration_ms**: Connection duration in milliseconds
- **protocol**: Network protocol (TCP/UDP)
- **anomaly_score**: ML confidence score (more negative = more anomalous)
- **anomaly_type**: Classified anomaly category
- **llm_analysis**: AI-generated security analysis

## 🛠️ Troubleshooting

### Common Issues and Solutions

**Model file not found:**
```bash
❌ Error: anomaly_model.joblib not found
💡 Solution: Run all cells in train_model.ipynb first
```

**API authentication error:**
```bash
❌ API Key not configured or invalid
💡 Solution: Check TOGETHER_API_KEY in .env file
```

**Connection refused:**
```bash
❌ Connection refused on localhost:9999
💡 Solution: Start server.py before running client.py
```

**Missing Python packages:**
```bash
❌ ImportError: No module named 'package_name'
💡 Solution: pip install -r requirements.txt
```

**Port already in use:**
```bash
❌ Address already in use
💡 Solution: Change PORT in server.py and client.py, or kill existing process
```

### Verification Commands

Test system components:

```bash
# Verify model loading
python -c "import joblib; model = joblib.load('anomaly_model.joblib'); print('✅ Model loaded successfully')"

# Test API connectivity
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('✅ API key configured' if os.getenv('TOGETHER_API_KEY') else '❌ API key missing')"

# Check required files
ls -la anomaly_model.joblib anomaly_log.csv 2>/dev/null || echo "⚠️ Run system first to generate files"
```

## 🔬 Technical Implementation

### Machine Learning Pipeline

1. **Data Preprocessing**:
   - One-hot encoding for categorical variables (protocol)
   - Feature scaling and normalization
   - Handling missing values

2. **Model Training**:
   - Isolation Forest algorithm implementation
   - Contamination rate tuning (10% anomaly expectation)
   - Cross-validation for parameter optimization

3. **Real-time Inference**:
   - Stream processing architecture
   - Sub-second prediction latency
   - Confidence scoring system

### AI Integration

- **Large Language Model**: Meta's Llama-3-70b via Together AI
- **Prompt Engineering**: Security-focused analysis templates
- **Context Awareness**: Network traffic pattern understanding
- **Response Formatting**: Structured threat assessments

### Performance Characteristics

- **Throughput**: Processes 30+ packets per minute
- **Latency**: <100ms detection time per packet
- **Accuracy**: Tuned for security-critical applications
- **Scalability**: Supports continuous operation

## 🧪 Testing and Validation

### System Testing

```bash
# Test complete pipeline
python server.py &  # Start in background
sleep 2
timeout 30 python client.py  # Run for 30 seconds
pkill -f server.py  # Clean up
```

### Performance Monitoring

```bash
# Monitor detection statistics
tail -f client_output.log | grep "Statistics:"

# Analyze log patterns
python -c "
import pandas as pd
df = pd.read_csv('anomaly_log.csv')
print(f'Total anomalies: {len(df)}')
print(f'Average score: {df[\"anomaly_score\"].mean():.4f}')
print(f'Most common type: {df[\"anomaly_type\"].mode()[0]}')
"
```

## 📚 Dependencies

### Core Requirements

```
pandas>=1.5.0          # Data manipulation
scikit-learn>=1.1.0    # Machine learning
joblib>=1.2.0          # Model serialization
numpy>=1.21.0          # Numerical computing
requests>=2.28.0       # HTTP client
python-dotenv>=0.19.0  # Environment management
```

### Visualization Requirements

```
matplotlib>=3.5.0      # Plotting library
seaborn>=0.11.0        # Statistical visualization
```

### Optional Dependencies

```
jupyter>=1.0.0         # Notebook environment
openpyxl>=3.0.0        # Excel file support
```

## 🔐 Security Considerations

### Data Privacy
- All training data is synthetically generated
- No real network traffic is collected or stored
- API communications use encrypted channels

### Access Control
- API keys stored in environment variables
- No hardcoded credentials in source code
- Local-only operation by default

### Operational Security
- Anomaly logs contain no sensitive information
- System operates in read-only mode on network data
- Graceful handling of interrupted operations

## 🚀 Future Enhancements

### Planned Features
- Support for additional ML algorithms (One-Class SVM, Autoencoders)
- Integration with SIEM systems
- Real network traffic adapter
- Advanced threat intelligence integration
- Automated response capabilities

### Scalability Improvements
- Distributed processing support
- Database backend for large-scale logging
- Multi-threaded detection pipeline
- Cloud deployment configurations

## 📖 Usage Examples

### Basic Operation
```bash
# Standard detection run
python server.py &
python client.py
```

### Custom Configuration
```bash
# High sensitivity detection
echo "CONTAMINATION=0.05" >> .env
python client.py
```

### Batch Analysis
```bash
# Analyze existing log data
python -c "
import pandas as pd
df = pd.read_csv('anomaly_log.csv')
high_risk = df[df['anomaly_score'] < -0.02]
print(f'High-risk anomalies: {len(high_risk)}')
"
```

## 🤝 Contributing

We welcome contributions to improve the system. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes with appropriate tests
4. Update documentation as needed
5. Submit a pull request with detailed description

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for full details.

## 🙏 Acknowledgments

- **Scikit-learn community** for excellent machine learning tools
- **Together AI** for providing accessible LLM APIs
- **Network security research community** for foundational knowledge
- **Open source contributors** who make projects like this possible

---

**🛡️ Start securing your network: `python server.py` → `python client.py` → Monitor threats in real-time!**
