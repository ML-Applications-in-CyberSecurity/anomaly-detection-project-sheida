import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.decomposition import PCA
import joblib
import json
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')

# Set style for better looking plots
plt.style.use('default')
sns.set_palette("husl")


def load_data():
    """Load anomaly log data and training data for visualization."""
    try:
        # Load anomaly log
        anomaly_log = pd.read_csv("anomaly_log.csv")
        print(f"📊 Loaded {len(anomaly_log)} anomaly records")

        # Load training data for comparison
        try:
            with open("../dataset/training_data.json", "r") as f:
                training_data = json.load(f)
            training_df = pd.DataFrame(training_data)
            print(f"📈 Loaded {len(training_df)} training records")
        except:
            print("⚠️  Training data not found, using synthetic data for comparison")
            training_df = generate_normal_data_for_viz()

        return anomaly_log, training_df

    except FileNotFoundError:
        print("❌ No anomaly log found. Please run the client first to generate data.")
        return pd.DataFrame(), pd.DataFrame()


def generate_normal_data_for_viz():
    """Generate normal data for visualization comparison."""
    import random

    COMMON_PORTS = [80, 443, 22, 8080]

    normal_data = []
    for _ in range(200):
        normal_data.append({
            "src_port": random.choice(COMMON_PORTS),
            "dst_port": random.randint(1024, 65535),
            "packet_size": random.randint(100, 1500),
            "duration_ms": random.randint(50, 500),
            "protocol": random.choice(["TCP", "UDP"])
        })

    return pd.DataFrame(normal_data)


def create_comprehensive_dashboard(anomaly_log, training_df):
    """Create a comprehensive anomaly analysis dashboard."""

    if anomaly_log.empty:
        print("❌ No anomaly data to visualize")
        return

    # Create the main dashboard
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle('🛡️ Network Anomaly Detection Analysis Dashboard', fontsize=20, fontweight='bold', y=0.98)

    # Create a 3x4 grid for subplots
    gs = fig.add_gridspec(4, 3, hspace=0.3, wspace=0.3)

    # 1. Anomaly Distribution by Source Port
    ax1 = fig.add_subplot(gs[0, 0])
    port_counts = anomaly_log['src_port'].value_counts()
    colors = plt.cm.Set3(np.linspace(0, 1, len(port_counts)))
    bars = ax1.bar(port_counts.index.astype(str), port_counts.values, color=colors)
    ax1.set_title('🔌 Anomalies by Source Port', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Source Port')
    ax1.set_ylabel('Number of Anomalies')

    # Add value labels on bars
    for bar, value in zip(bars, port_counts.values):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                 str(value), ha='center', va='bottom', fontweight='bold')

    # 2. Packet Size Distribution Comparison
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.hist(training_df['packet_size'], bins=30, alpha=0.7, label='Normal Traffic',
             color='lightblue', density=True)
    ax2.hist(anomaly_log['packet_size'], bins=20, alpha=0.8, label='Anomalous Traffic',
             color='red', density=True)
    ax2.set_title('📦 Packet Size Distribution', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Packet Size (bytes)')
    ax2.set_ylabel('Density')
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    # 3. Anomaly Scores Distribution
    ax3 = fig.add_subplot(gs[0, 2])
    ax3.hist(anomaly_log['anomaly_score'], bins=15, color='salmon', alpha=0.8, edgecolor='black')
    ax3.set_title('🎯 Anomaly Score Distribution', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Anomaly Score')
    ax3.set_ylabel('Frequency')
    ax3.axvline(anomaly_log['anomaly_score'].mean(), color='red', linestyle='--',
                label=f'Mean: {anomaly_log["anomaly_score"].mean():.4f}', linewidth=2)
    ax3.legend()
    ax3.grid(True, alpha=0.3)

    # 4. Protocol Distribution Pie Chart
    ax4 = fig.add_subplot(gs[1, 0])
    protocol_counts = anomaly_log['protocol'].value_counts()
    colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
    wedges, texts, autotexts = ax4.pie(protocol_counts.values, labels=protocol_counts.index,
                                       autopct='%1.1f%%', colors=colors[:len(protocol_counts)],
                                       startangle=90, explode=[0.05] * len(protocol_counts))
    ax4.set_title('🔗 Anomalies by Protocol', fontsize=14, fontweight='bold')

    # 5. Duration vs Packet Size Scatter Plot
    ax5 = fig.add_subplot(gs[1, 1])
    scatter = ax5.scatter(anomaly_log['duration_ms'], anomaly_log['packet_size'],
                          c=anomaly_log['anomaly_score'], cmap='viridis',
                          s=100, alpha=0.7, edgecolors='black')
    ax5.set_title('⏱️ Duration vs Packet Size', fontsize=14, fontweight='bold')
    ax5.set_xlabel('Duration (ms)')
    ax5.set_ylabel('Packet Size (bytes)')
    cbar = plt.colorbar(scatter, ax=ax5)
    cbar.set_label('Anomaly Score', rotation=270, labelpad=20)
    ax5.grid(True, alpha=0.3)

    # 6. Anomaly Types Distribution
    ax6 = fig.add_subplot(gs[1, 2])
    if 'anomaly_type' in anomaly_log.columns:
        type_counts = anomaly_log['anomaly_type'].value_counts()
        bars = ax6.bar(range(len(type_counts)), type_counts.values,
                       color=['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4'])
        ax6.set_title('🏷️ Anomaly Types', fontsize=14, fontweight='bold')
        ax6.set_xlabel('Anomaly Type')
        ax6.set_ylabel('Count')
        ax6.set_xticks(range(len(type_counts)))
        ax6.set_xticklabels(type_counts.index, rotation=45, ha='right')

        # Add value labels
        for bar, value in zip(bars, type_counts.values):
            ax6.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                     str(value), ha='center', va='bottom', fontweight='bold')
    else:
        ax6.text(0.5, 0.5, 'Anomaly Type\nNot Available', ha='center', va='center',
                 transform=ax6.transAxes, fontsize=12)
        ax6.set_title('🏷️ Anomaly Types', fontsize=14, fontweight='bold')

    # 7. Timeline of Anomalies
    ax7 = fig.add_subplot(gs[2, :])
    if 'timestamp' in anomaly_log.columns:
        anomaly_log['timestamp'] = pd.to_datetime(anomaly_log['timestamp'])
        anomaly_log = anomaly_log.sort_values('timestamp')

        # Create timeline plot
        ax7.plot(anomaly_log['timestamp'], range(len(anomaly_log)),
                 marker='o', markersize=8, linewidth=2, color='red', alpha=0.7)
        ax7.fill_between(anomaly_log['timestamp'], 0, range(len(anomaly_log)),
                         alpha=0.3, color='red')
        ax7.set_title('📅 Anomaly Detection Timeline', fontsize=14, fontweight='bold')
        ax7.set_xlabel('Time')
        ax7.set_ylabel('Cumulative Anomalies')
        ax7.grid(True, alpha=0.3)

        # Format x-axis
        ax7.tick_params(axis='x', rotation=45)
    else:
        ax7.text(0.5, 0.5, 'Timeline data not available', ha='center', va='center',
                 transform=ax7.transAxes, fontsize=12)
        ax7.set_title('📅 Anomaly Detection Timeline', fontsize=14, fontweight='bold')

    # 8. Security Metrics Summary
    ax8 = fig.add_subplot(gs[3, :])
    ax8.axis('off')

    # Calculate summary statistics
    total_anomalies = len(anomaly_log)
    avg_score = anomaly_log['anomaly_score'].mean()
    most_severe = anomaly_log['anomaly_score'].min()
    largest_packet = anomaly_log['packet_size'].max()

    # Create summary text
    summary_text = f"""
    🔍 SECURITY ANALYSIS SUMMARY

    📊 Total Anomalies Detected: {total_anomalies}
    🎯 Average Anomaly Score: {avg_score:.4f}
    ⚠️  Most Severe Score: {most_severe:.4f}
    📦 Largest Anomalous Packet: {largest_packet:,} bytes

    🔌 Most Suspicious Ports: {', '.join(map(str, anomaly_log['src_port'].value_counts().head(3).index))}
    🏷️  Primary Threat Types: Data Exfiltration, C2 Communication, Behavioral Anomalies

    ⚡ Recommendation: Monitor high-port communications and implement additional network segmentation
    """

    ax8.text(0.1, 0.5, summary_text, transform=ax8.transAxes, fontsize=12,
             verticalalignment='center', bbox=dict(boxstyle="round,pad=0.5", facecolor='lightgray'))

    plt.tight_layout()
    plt.savefig('images/anomaly_dashboard.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()

    print("✅ Dashboard saved as 'anomaly_dashboard.png'")


def create_pca_visualization(anomaly_log, training_df):
    """Create PCA visualization comparing normal vs anomalous traffic."""

    if anomaly_log.empty or training_df.empty:
        print("❌ Insufficient data for PCA visualization")
        return

    print("🔬 Creating PCA visualization...")

    # Prepare data for PCA
    # Add labels
    training_df['is_anomaly'] = 0
    anomaly_subset = anomaly_log[['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol']].copy()
    anomaly_subset['is_anomaly'] = 1

    # Combine datasets
    combined_data = pd.concat([training_df, anomaly_subset], ignore_index=True)

    # One-hot encode protocol
    combined_encoded = pd.get_dummies(combined_data, columns=['protocol'], drop_first=True)

    # Separate features and labels
    labels = combined_encoded['is_anomaly']
    features = combined_encoded.drop('is_anomaly', axis=1)

    # Apply PCA
    pca = PCA(n_components=2)
    pca_result = pca.fit_transform(features)

    # Create PCA plot
    plt.figure(figsize=(12, 8))

    # Plot normal data
    normal_mask = labels == 0
    plt.scatter(pca_result[normal_mask, 0], pca_result[normal_mask, 1],
                c='lightblue', alpha=0.6, label='Normal Traffic', s=50, edgecolors='blue')

    # Plot anomalous data
    anomaly_mask = labels == 1
    plt.scatter(pca_result[anomaly_mask, 0], pca_result[anomaly_mask, 1],
                c='red', alpha=0.8, label='Anomalous Traffic', s=150, marker='^', edgecolors='darkred')

    plt.title('🔬 PCA Analysis: Normal vs Anomalous Network Traffic', fontsize=16, fontweight='bold')
    plt.xlabel(f'First Principal Component (Explained Variance: {pca.explained_variance_ratio_[0]:.2%})')
    plt.ylabel(f'Second Principal Component (Explained Variance: {pca.explained_variance_ratio_[1]:.2%})')
    plt.legend(fontsize=12)
    plt.grid(True, alpha=0.3)

    # Add annotations for some anomalous points
    anomaly_indices = np.where(anomaly_mask)[0]
    for i, idx in enumerate(anomaly_indices[:5]):  # Annotate first 5 anomalies
        plt.annotate(f'A{i + 1}', (pca_result[idx, 0], pca_result[idx, 1]),
                     xytext=(5, 5), textcoords='offset points', fontsize=8)

    plt.tight_layout()
    plt.savefig('images/pca_anomaly_analysis.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()

    print(f"✅ PCA Analysis Complete!")
    print(f"   📊 Total explained variance: {sum(pca.explained_variance_ratio_):.2%}")
    print(f"   📈 Component 1: {pca.explained_variance_ratio_[0]:.2%}")
    print(f"   📈 Component 2: {pca.explained_variance_ratio_[1]:.2%}")
    print("✅ PCA plot saved as 'pca_anomaly_analysis.png'")


def create_correlation_heatmap(anomaly_log):
    """Create correlation heatmap of anomaly features."""

    if anomaly_log.empty:
        return

    print("🔥 Creating correlation heatmap...")

    # Select numeric columns for correlation
    numeric_cols = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'anomaly_score']
    correlation_data = anomaly_log[numeric_cols]

    # Calculate correlation matrix
    correlation_matrix = correlation_data.corr()

    # Create heatmap
    plt.figure(figsize=(10, 8))
    mask = np.triu(np.ones_like(correlation_matrix, dtype=bool))

    sns.heatmap(correlation_matrix, mask=mask, annot=True, cmap='coolwarm', center=0,
                square=True, linewidths=0.5, cbar_kws={"shrink": .8}, fmt='.3f')

    plt.title('🔥 Feature Correlation Heatmap (Anomalous Traffic)', fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig('images/correlation_heatmap.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()

    print("✅ Correlation heatmap saved as 'correlation_heatmap.png'")


def generate_security_report(anomaly_log):
    """Generate a comprehensive security report."""

    if anomaly_log.empty:
        print("❌ No data available for security report")
        return

    print("\n" + "🛡️" + "=" * 70)
    print("🔍 COMPREHENSIVE SECURITY ANALYSIS REPORT")
    print("🛡️" + "=" * 70)

    # Basic statistics
    total_anomalies = len(anomaly_log)
    avg_score = anomaly_log['anomaly_score'].mean()
    most_severe_score = anomaly_log['anomaly_score'].min()

    print(f"\n📊 DETECTION SUMMARY:")
    print(f"   Total Anomalies Detected: {total_anomalies}")
    print(f"   Average Anomaly Score: {avg_score:.4f}")
    print(f"   Most Severe Score: {most_severe_score:.4f}")

    # Port analysis
    print(f"\n🔌 PORT ANALYSIS:")
    top_ports = anomaly_log['src_port'].value_counts().head(5)
    for port, count in top_ports.items():
        print(f"   Port {port}: {count} anomalies ({count / total_anomalies * 100:.1f}%)")

    # Protocol analysis
    print(f"\n🔗 PROTOCOL ANALYSIS:")
    protocol_dist = anomaly_log['protocol'].value_counts()
    for protocol, count in protocol_dist.items():
        print(f"   {protocol}: {count} anomalies ({count / total_anomalies * 100:.1f}%)")

    # Packet size analysis
    print(f"\n📦 PACKET SIZE ANALYSIS:")
    print(f"   Average Size: {anomaly_log['packet_size'].mean():.0f} bytes")
    print(f"   Largest Packet: {anomaly_log['packet_size'].max():,} bytes")
    print(f"   Size Range: {anomaly_log['packet_size'].min()}-{anomaly_log['packet_size'].max()} bytes")

    # Timing analysis
    print(f"\n⏱️ TIMING ANALYSIS:")
    print(f"   Average Duration: {anomaly_log['duration_ms'].mean():.0f} ms")
    print(f"   Duration Range: {anomaly_log['duration_ms'].min()}-{anomaly_log['duration_ms'].max()} ms")

    # Threat assessment
    print(f"\n⚠️ THREAT ASSESSMENT:")
    if 'anomaly_type' in anomaly_log.columns:
        threat_types = anomaly_log['anomaly_type'].value_counts()
        for threat, count in threat_types.items():
            print(f"   {threat}: {count} instances")

    # Recommendations
    print(f"\n💡 SECURITY RECOMMENDATIONS:")
    print(f"   1. Monitor traffic on ports: {', '.join(map(str, top_ports.head(3).index))}")
    print(f"   2. Implement size-based filtering for packets > 2000 bytes")
    print(f"   3. Enhance monitoring for high-port communications")
    print(f"   4. Consider network segmentation for suspicious patterns")
    print(f"   5. Set up automated blocking for anomaly scores < -0.02")

    print("\n" + "🛡️" + "=" * 70)


def main():
    """Main function to run all visualizations."""
    print("🎨 Starting Anomaly Detection Visualization Suite...")
    print("=" * 60)

    # Load data
    anomaly_log, training_df = load_data()

    if anomaly_log.empty:
        print("❌ No anomaly data found. Please run the client system first.")
        return

    print(f"📊 Data loaded successfully!")
    print(f"   Anomaly records: {len(anomaly_log)}")
    print(f"   Training records: {len(training_df)}")

    # Create visualizations
    print("\n🎨 Creating comprehensive dashboard...")
    create_comprehensive_dashboard(anomaly_log, training_df)

    print("\n🔬 Creating PCA visualization...")
    create_pca_visualization(anomaly_log, training_df)

    print("\n🔥 Creating correlation analysis...")
    create_correlation_heatmap(anomaly_log)

    print("\n📋 Generating security report...")
    generate_security_report(anomaly_log)

    print("\n✅ All visualizations completed successfully!")
    print("📁 Generated files:")
    print("   - anomaly_dashboard.png")
    print("   - pca_anomaly_analysis.png")
    print("   - correlation_heatmap.png")


if __name__ == "__main__":
    main()