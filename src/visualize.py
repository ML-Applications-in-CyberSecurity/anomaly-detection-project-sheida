import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import json
from datetime import datetime, timedelta
import warnings
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

warnings.filterwarnings('ignore')
plt.style.use('default')
sns.set_palette("husl")

# Create output directories
Path("images").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)


class NetworkAnomalyVisualizer:
    """Network anomaly detection visualization system with comprehensive analytics."""

    def __init__(self):
        self.anomaly_log = pd.DataFrame()
        self.training_df = pd.DataFrame()
        self.performance_metrics = {}

        # Load configuration from .env
        self.training_data_path = os.getenv('TRAINING_DATA_PATH', 'dataset/training_data.json')
        self.anomaly_log_path = os.getenv('ANOMALY_LOG_PATH', 'anomaly_log.csv')
        self.performance_log_path = os.getenv('PERFORMANCE_LOG', 'template_performance.json')

        print(f"📁 Configuration loaded:")
        print(f"   Training Data: {self.training_data_path}")
        print(f"   Anomaly Log: {self.anomaly_log_path}")

    def load_data(self):
        """Load anomaly log and training data using .env paths."""
        success = True

        # Load anomaly log
        try:
            if os.path.exists(self.anomaly_log_path):
                self.anomaly_log = pd.read_csv(self.anomaly_log_path)
                print(f"✅ Loaded {len(self.anomaly_log)} anomaly records")

                if 'timestamp' in self.anomaly_log.columns:
                    self.anomaly_log['timestamp'] = pd.to_datetime(self.anomaly_log['timestamp'])
            else:
                print(f"❌ Anomaly log not found at: {self.anomaly_log_path}")
                success = False
        except Exception as e:
            print(f"❌ Error loading anomaly log: {str(e)}")
            success = False

        # Load training data
        try:
            if os.path.exists(self.training_data_path):
                with open(self.training_data_path, "r", encoding='utf-8') as f:
                    training_data = json.load(f)
                self.training_df = pd.DataFrame(training_data)
                print(f"✅ Loaded {len(self.training_df)} training records")
            else:
                print(f"⚠️  Training data not found at: {self.training_data_path}")
                print("🔄 Generating synthetic training data...")
                self.training_df = self._generate_synthetic_data()
        except Exception as e:
            print(f"⚠️  Error loading training data: {str(e)}")
            print("🔄 Generating synthetic training data...")
            self.training_df = self._generate_synthetic_data()

        # Load performance metrics if available
        try:
            if os.path.exists(self.performance_log_path):
                with open(self.performance_log_path, "r", encoding='utf-8') as f:
                    self.performance_metrics = json.load(f)
                print(f"📊 Loaded performance metrics for {len(self.performance_metrics)} templates")
        except Exception as e:
            print(f"⚠️  Performance metrics not available: {str(e)}")

        return success

    def _generate_synthetic_data(self):
        """Generate synthetic normal traffic data."""
        import random

        COMMON_PORTS = [80, 443, 22, 8080, 21, 25, 53, 110, 143, 993]
        PROTOCOLS = ["TCP", "UDP"]

        data = []
        for _ in range(500):
            protocol = random.choice(PROTOCOLS)
            src_port = random.choice(COMMON_PORTS)

            # Realistic packet sizes based on protocol and port
            if protocol == "TCP":
                if src_port in [80, 443, 8080]:  # HTTP/HTTPS
                    packet_size = random.randint(200, 1500)
                elif src_port == 22:  # SSH
                    packet_size = random.randint(100, 800)
                else:
                    packet_size = random.randint(150, 1200)
            else:  # UDP
                packet_size = random.randint(50, 800)

            # Realistic duration based on service type
            if src_port in [80, 443, 8080]:
                duration_ms = random.randint(50, 300)
            elif src_port == 22:
                duration_ms = random.randint(100, 800)
            else:
                duration_ms = random.randint(20, 500)

            data.append({
                "src_port": src_port,
                "dst_port": random.randint(1024, 65535),
                "packet_size": packet_size,
                "duration_ms": duration_ms,
                "protocol": protocol
            })

        return pd.DataFrame(data)

    def create_comprehensive_dashboard(self):
        """Create comprehensive security dashboard with multiple panels."""
        if self.anomaly_log.empty:
            print("❌ No anomaly data to visualize")
            return

        # Create figure with subplots
        fig = plt.figure(figsize=(20, 16))
        fig.suptitle('Network Security Analysis Dashboard', fontsize=20, fontweight='bold', y=0.98)

        # Create grid layout
        gs = fig.add_gridspec(4, 3, hspace=0.4, wspace=0.3)

        # 1. Top Anomalous Ports
        ax1 = fig.add_subplot(gs[0, 0])
        port_counts = self.anomaly_log['src_port'].value_counts().head(10)
        colors = plt.cm.Set3(np.linspace(0, 1, len(port_counts)))
        bars1 = ax1.bar(range(len(port_counts)), port_counts.values, color=colors)
        ax1.set_title('Top Anomalous Ports', fontsize=12, fontweight='bold')
        ax1.set_xticks(range(len(port_counts)))
        ax1.set_xticklabels(port_counts.index, rotation=45)
        ax1.set_ylabel('Anomaly Count')

        # Add value labels
        for bar, value in zip(bars1, port_counts.values):
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                     str(value), ha='center', va='bottom', fontsize=8)

        # 2. Packet Size Distribution Comparison
        ax2 = fig.add_subplot(gs[0, 1])
        if not self.training_df.empty:
            ax2.hist(self.training_df['packet_size'], bins=30, alpha=0.6,
                     label='Normal Traffic', color='lightblue', density=True)
        ax2.hist(self.anomaly_log['packet_size'], bins=20, alpha=0.8,
                 label='Anomalous Traffic', color='red', density=True)
        ax2.set_title('Packet Size Distribution', fontsize=12, fontweight='bold')
        ax2.set_xlabel('Packet Size (bytes)')
        ax2.set_ylabel('Density')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Anomaly Score Distribution
        ax3 = fig.add_subplot(gs[0, 2])
        n, bins, patches = ax3.hist(self.anomaly_log['anomaly_score'], bins=20,
                                    color='orange', alpha=0.8, edgecolor='black')
        ax3.set_title('Anomaly Score Distribution', fontsize=12, fontweight='bold')
        ax3.set_xlabel('Anomaly Score')
        ax3.set_ylabel('Frequency')
        ax3.axvline(self.anomaly_log['anomaly_score'].mean(), color='red', linestyle='--',
                    label=f'Mean: {self.anomaly_log["anomaly_score"].mean():.3f}', linewidth=2)
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4. Threat Severity Distribution
        ax4 = fig.add_subplot(gs[1, 0])
        severity_counts = self._calculate_severity_distribution()
        colors = ['#ff4444', '#ff8800', '#ffcc00', '#44ff44']
        wedges, texts, autotexts = ax4.pie(severity_counts.values(), labels=severity_counts.keys(),
                                           autopct='%1.1f%%', colors=colors, startangle=90)
        ax4.set_title('Threat Severity Levels', fontsize=12, fontweight='bold')

        # 5. Protocol Analysis
        ax5 = fig.add_subplot(gs[1, 1])
        protocol_counts = self.anomaly_log['protocol'].value_counts()
        bars5 = ax5.bar(protocol_counts.index, protocol_counts.values,
                        color=['#ff9999', '#66b3ff', '#99ff99'][:len(protocol_counts)])
        ax5.set_title('Protocol Distribution', fontsize=12, fontweight='bold')
        ax5.set_ylabel('Count')

        for bar, value in zip(bars5, protocol_counts.values):
            ax5.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                     str(value), ha='center', va='bottom', fontsize=10)

        # 6. Duration vs Packet Size Scatter
        ax6 = fig.add_subplot(gs[1, 2])
        scatter = ax6.scatter(self.anomaly_log['duration_ms'], self.anomaly_log['packet_size'],
                              c=self.anomaly_log['anomaly_score'], cmap='viridis',
                              s=60, alpha=0.7, edgecolors='black', linewidth=0.5)
        ax6.set_title('Duration vs Packet Size', fontsize=12, fontweight='bold')
        ax6.set_xlabel('Duration (ms)')
        ax6.set_ylabel('Packet Size (bytes)')
        cbar = plt.colorbar(scatter, ax=ax6)
        cbar.set_label('Anomaly Score', rotation=270, labelpad=15)
        ax6.grid(True, alpha=0.3)

        # 7. Hourly Pattern Analysis
        ax7 = fig.add_subplot(gs[2, 0])
        if 'timestamp' in self.anomaly_log.columns:
            hourly_counts = self.anomaly_log['timestamp'].dt.hour.value_counts().sort_index()
            ax7.bar(hourly_counts.index, hourly_counts.values, color='purple', alpha=0.7)
            ax7.set_title('Hourly Anomaly Pattern', fontsize=12, fontweight='bold')
            ax7.set_xlabel('Hour of Day')
            ax7.set_ylabel('Anomaly Count')
            ax7.grid(True, alpha=0.3)
        else:
            ax7.text(0.5, 0.5, 'Timestamp Data\nNot Available', ha='center', va='center',
                     transform=ax7.transAxes, fontsize=12)
            ax7.set_title('Hourly Pattern', fontsize=12, fontweight='bold')

        # 8. Anomaly Types (if available)
        ax8 = fig.add_subplot(gs[2, 1])
        if 'anomaly_type' in self.anomaly_log.columns:
            type_counts = self.anomaly_log['anomaly_type'].value_counts().head(6)
            bars8 = ax8.barh(range(len(type_counts)), type_counts.values,
                             color=plt.cm.Set3(np.linspace(0, 1, len(type_counts))))
            ax8.set_title('Top Threat Types', fontsize=12, fontweight='bold')
            ax8.set_xlabel('Count')
            ax8.set_yticks(range(len(type_counts)))
            ax8.set_yticklabels([t.replace('_', ' ').title()[:20] for t in type_counts.index], fontsize=9)

            for i, (bar, value) in enumerate(zip(bars8, type_counts.values)):
                ax8.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                         str(value), ha='left', va='center', fontsize=9)
        else:
            ax8.text(0.5, 0.5, 'Anomaly Type\nData Not Available', ha='center', va='center',
                     transform=ax8.transAxes, fontsize=12)
            ax8.set_title('Threat Types', fontsize=12, fontweight='bold')

        # 9. Risk Matrix
        ax9 = fig.add_subplot(gs[2, 2])
        self._create_risk_matrix(ax9)

        # 10. Timeline Analysis
        ax10 = fig.add_subplot(gs[3, :])
        if 'timestamp' in self.anomaly_log.columns and len(self.anomaly_log) > 1:
            timeline_data = self.anomaly_log.sort_values('timestamp')
            ax10.plot(timeline_data['timestamp'], range(len(timeline_data)),
                      marker='o', markersize=4, linewidth=2, color='red', alpha=0.8)
            ax10.fill_between(timeline_data['timestamp'], 0, range(len(timeline_data)),
                              alpha=0.3, color='red')
            ax10.set_title('Anomaly Detection Timeline', fontsize=12, fontweight='bold')
            ax10.set_xlabel('Time')
            ax10.set_ylabel('Cumulative Anomalies')
            ax10.grid(True, alpha=0.3)

            # Add trend line
            if len(timeline_data) > 2:
                z = np.polyfit(range(len(timeline_data)), range(len(timeline_data)), 1)
                p = np.poly1d(z)
                ax10.plot(timeline_data['timestamp'], p(range(len(timeline_data))),
                          "r--", alpha=0.8, linewidth=2, label='Trend')
                ax10.legend()
        else:
            ax10.text(0.5, 0.5, 'Timeline Analysis\nInsufficient Data', ha='center', va='center',
                      transform=ax10.transAxes, fontsize=14)
            ax10.set_title('Timeline Analysis', fontsize=12, fontweight='bold')

        plt.tight_layout()
        plt.savefig('images/security_dashboard.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("✅ Security dashboard saved as 'images/security_dashboard.png'")

    def _calculate_severity_distribution(self):
        """Calculate threat severity distribution."""
        severity_counts = {
            'Critical': len(self.anomaly_log[self.anomaly_log['anomaly_score'] < -0.1]),
            'High': len(self.anomaly_log[(self.anomaly_log['anomaly_score'] >= -0.1) &
                                         (self.anomaly_log['anomaly_score'] < -0.05)]),
            'Medium': len(self.anomaly_log[(self.anomaly_log['anomaly_score'] >= -0.05) &
                                           (self.anomaly_log['anomaly_score'] < -0.02)]),
            'Low': len(self.anomaly_log[self.anomaly_log['anomaly_score'] >= -0.02])
        }
        return {k: v for k, v in severity_counts.items() if v > 0}

    def _create_risk_matrix(self, ax):
        """Create risk assessment matrix."""
        try:
            # Create bins for packet size and duration
            packet_bins = pd.cut(self.anomaly_log['packet_size'], bins=4, labels=['S', 'M', 'L', 'XL'])
            duration_bins = pd.cut(self.anomaly_log['duration_ms'], bins=4, labels=['Quick', 'Med', 'Long', 'Ext'])

            # Create risk matrix
            risk_matrix = pd.crosstab(packet_bins, duration_bins,
                                      self.anomaly_log['anomaly_score'], aggfunc='mean')

            if not risk_matrix.empty:
                sns.heatmap(risk_matrix, annot=True, fmt='.3f', cmap='Reds_r', ax=ax,
                            cbar_kws={'label': 'Avg Risk Score'})
                ax.set_title('Risk Assessment Matrix', fontsize=12, fontweight='bold')
                ax.set_xlabel('Duration Category')
                ax.set_ylabel('Packet Size Category')
            else:
                ax.text(0.5, 0.5, 'Risk Matrix\nInsufficient Data', ha='center', va='center',
                        transform=ax.transAxes, fontsize=12)
                ax.set_title('Risk Matrix', fontsize=12, fontweight='bold')
        except Exception as e:
            ax.text(0.5, 0.5, f'Risk Matrix\nError: {str(e)[:20]}...', ha='center', va='center',
                    transform=ax.transAxes, fontsize=10)
            ax.set_title('Risk Matrix', fontsize=12, fontweight='bold')

    def create_pca_analysis(self):
        """Create PCA analysis with clustering."""
        if self.anomaly_log.empty or self.training_df.empty:
            print("❌ Insufficient data for PCA analysis")
            return

        print("🔬 Creating PCA analysis...")

        # Prepare data
        training_sample = self.training_df.sample(min(400, len(self.training_df)))
        training_sample['is_anomaly'] = 0

        anomaly_subset = self.anomaly_log[['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol']].copy()
        anomaly_subset['is_anomaly'] = 1

        # Combine datasets
        combined_data = pd.concat([training_sample, anomaly_subset], ignore_index=True)
        combined_encoded = pd.get_dummies(combined_data, columns=['protocol'], drop_first=True)

        # Ensure required columns exist
        expected_columns = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']
        for col in expected_columns:
            if col not in combined_encoded.columns:
                combined_encoded[col] = 0

        labels = combined_encoded['is_anomaly']
        features = combined_encoded[expected_columns]

        # Standardize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)

        # Apply PCA
        pca = PCA(n_components=2)
        pca_result = pca.fit_transform(features_scaled)

        # Create visualization
        fig, axes = plt.subplots(1, 2, figsize=(20, 8))

        # Plot 1: Basic PCA
        normal_mask = labels == 0
        anomaly_mask = labels == 1

        axes[0].scatter(pca_result[normal_mask, 0], pca_result[normal_mask, 1],
                        c='lightblue', alpha=0.5, label='Normal Traffic', s=20)
        axes[0].scatter(pca_result[anomaly_mask, 0], pca_result[anomaly_mask, 1],
                        c='red', alpha=0.8, label='Anomalous Traffic', s=80, marker='^')

        axes[0].set_title('PCA: Normal vs Anomalous Traffic', fontsize=14, fontweight='bold')
        axes[0].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.1%} variance)')
        axes[0].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.1%} variance)')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)

        # Plot 2: PCA with Severity Coloring
        if len(self.anomaly_log) > 0:
            severity_colors = []
            severity_labels = []
            for score in self.anomaly_log['anomaly_score']:
                if score < -0.1:
                    severity_colors.append('darkred')
                    severity_labels.append('Critical')
                elif score < -0.05:
                    severity_colors.append('red')
                    severity_labels.append('High')
                elif score < -0.02:
                    severity_colors.append('orange')
                    severity_labels.append('Medium')
                else:
                    severity_colors.append('yellow')
                    severity_labels.append('Low')

            axes[1].scatter(pca_result[normal_mask, 0], pca_result[normal_mask, 1],
                            c='lightgray', alpha=0.3, label='Normal Traffic', s=15)

            anomaly_pca = pca_result[anomaly_mask]
            for i, (color, label) in enumerate(zip(severity_colors, severity_labels)):
                if i < len(anomaly_pca):
                    axes[1].scatter(anomaly_pca[i, 0], anomaly_pca[i, 1],
                                    c=color, s=100, marker='^', edgecolors='black', alpha=0.8)

            axes[1].set_title('PCA with Threat Severity', fontsize=14, fontweight='bold')
            axes[1].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.1%} variance)')
            axes[1].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.1%} variance)')
            axes[1].grid(True, alpha=0.3)

            # Create custom legend
            from matplotlib.lines import Line2D
            legend_elements = [
                Line2D([0], [0], marker='^', color='w', markerfacecolor='darkred', markersize=10, label='Critical'),
                Line2D([0], [0], marker='^', color='w', markerfacecolor='red', markersize=10, label='High'),
                Line2D([0], [0], marker='^', color='w', markerfacecolor='orange', markersize=10, label='Medium'),
                Line2D([0], [0], marker='^', color='w', markerfacecolor='yellow', markersize=10, label='Low'),
                Line2D([0], [0], marker='o', color='w', markerfacecolor='lightgray', markersize=8, label='Normal')
            ]
            axes[1].legend(handles=legend_elements, loc='best')

        plt.tight_layout()
        plt.savefig('images/pca_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()

        print(f"✅ PCA Analysis Complete!")
        print(f"   📊 Total explained variance: {sum(pca.explained_variance_ratio_):.1%}")
        print(f"   📈 PC1: {pca.explained_variance_ratio_[0]:.1%}, PC2: {pca.explained_variance_ratio_[1]:.1%}")

    def create_interactive_dashboard(self):
        """Create interactive Plotly dashboard."""
        try:
            import plotly.graph_objects as go
            import plotly.express as px
            from plotly.subplots import make_subplots
            import plotly.offline as pyo

            if self.anomaly_log.empty:
                print("❌ No data for interactive dashboard")
                return

            print("🎨 Creating interactive dashboard...")

            # Create subplots
            fig = make_subplots(
                rows=2, cols=3,
                subplot_titles=('Port Distribution', 'Packet Size Analysis', 'Severity Timeline',
                                'Protocol Breakdown', 'Risk Scatter Plot', 'Hourly Patterns'),
                specs=[[{"type": "bar"}, {"type": "histogram"}, {"type": "scatter"}],
                       [{"type": "pie"}, {"type": "scatter"}, {"type": "bar"}]]
            )

            # 1. Port Distribution
            port_counts = self.anomaly_log['src_port'].value_counts().head(8)
            fig.add_trace(
                go.Bar(x=port_counts.index.astype(str), y=port_counts.values,
                       name="Port Anomalies", marker_color='lightcoral',
                       hovertemplate="Port: %{x}<br>Count: %{y}<extra></extra>"),
                row=1, col=1
            )

            # 2. Packet Size Distribution
            fig.add_trace(
                go.Histogram(x=self.anomaly_log['packet_size'], name="Anomalous Traffic",
                             opacity=0.8, marker_color='red', nbinsx=20),
                row=1, col=2
            )

            # 3. Timeline
            if 'timestamp' in self.anomaly_log.columns:
                fig.add_trace(
                    go.Scatter(x=self.anomaly_log['timestamp'], y=self.anomaly_log['anomaly_score'],
                               mode='markers', name="Anomaly Score", marker_color='orange',
                               hovertemplate="Time: %{x}<br>Score: %{y:.4f}<extra></extra>"),
                    row=1, col=3
                )

            # 4. Protocol Distribution
            protocol_counts = self.anomaly_log['protocol'].value_counts()
            fig.add_trace(
                go.Pie(labels=protocol_counts.index, values=protocol_counts.values,
                       name="Protocols", hole=0.3),
                row=2, col=1
            )

            # 5. Risk Scatter
            fig.add_trace(
                go.Scatter(x=self.anomaly_log['duration_ms'], y=self.anomaly_log['packet_size'],
                           mode='markers', name="Risk Analysis",
                           marker=dict(color=self.anomaly_log['anomaly_score'],
                                       colorscale='Viridis', size=8,
                                       colorbar=dict(title="Risk Score")),
                           hovertemplate="Duration: %{x}ms<br>Size: %{y}B<br>Score: %{marker.color:.4f}<extra></extra>"),
                row=2, col=2
            )

            # 6. Hourly Pattern
            if 'timestamp' in self.anomaly_log.columns:
                hourly_counts = self.anomaly_log['timestamp'].dt.hour.value_counts().sort_index()
                fig.add_trace(
                    go.Bar(x=hourly_counts.index, y=hourly_counts.values,
                           name="Hourly Pattern", marker_color='purple',
                           hovertemplate="Hour: %{x}:00<br>Anomalies: %{y}<extra></extra>"),
                    row=2, col=3
                )

            # Update layout
            fig.update_layout(
                height=800,
                title_text="Interactive Network Security Dashboard",
                title_x=0.5,
                showlegend=False,
                template="plotly_white"
            )

            # Save interactive dashboard
            pyo.plot(fig, filename='reports/interactive_dashboard.html', auto_open=False)
            print("✅ Interactive dashboard saved as 'reports/interactive_dashboard.html'")

        except ImportError:
            print("⚠️  Plotly not available. Install with: pip install plotly")
        except Exception as e:
            print(f"⚠️  Error creating interactive dashboard: {str(e)}")

    def generate_security_report(self):
        """Generate comprehensive security analysis report."""
        if self.anomaly_log.empty:
            print("❌ No data for report generation")
            return

        total_anomalies = len(self.anomaly_log)
        avg_score = self.anomaly_log['anomaly_score'].mean()
        worst_score = self.anomaly_log['anomaly_score'].min()

        # Calculate metrics
        severity_dist = self._calculate_severity_distribution()
        top_ports = self.anomaly_log['src_port'].value_counts().head(5)
        protocol_dist = self.anomaly_log['protocol'].value_counts()

        # Generate report
        report = f"""
NETWORK SECURITY ANALYSIS REPORT
========================================

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Data Source: {self.anomaly_log_path}
Training Data: {self.training_data_path}

EXECUTIVE SUMMARY
----------------------------------------
Total Security Events: {total_anomalies:,}
Average Risk Score: {avg_score:.4f}
Highest Risk Score: {worst_score:.4f}
Analysis Period: {self.anomaly_log['timestamp'].min() if 'timestamp' in self.anomaly_log.columns else 'Unknown'} to {self.anomaly_log['timestamp'].max() if 'timestamp' in self.anomaly_log.columns else 'Unknown'}

THREAT SEVERITY BREAKDOWN
----------------------------------------"""

        for severity, count in severity_dist.items():
            percentage = (count / total_anomalies) * 100
            report += f"\n{severity}: {count:,} incidents ({percentage:.1f}%)"

        report += f"""

HIGH-RISK PORTS ANALYSIS
----------------------------------------"""

        for port, count in top_ports.items():
            percentage = (count / total_anomalies) * 100
            avg_score_port = self.anomaly_log[self.anomaly_log['src_port'] == port]['anomaly_score'].mean()
            report += f"\nPort {port}: {count} incidents ({percentage:.1f}%), Avg Score: {avg_score_port:.4f}"

        report += f"""

PROTOCOL DISTRIBUTION
----------------------------------------"""

        for protocol, count in protocol_dist.items():
            percentage = (count / total_anomalies) * 100
            report += f"\n{protocol}: {count} incidents ({percentage:.1f}%)"

        # Add anomaly types if available
        if 'anomaly_type' in self.anomaly_log.columns:
            report += f"""

THREAT TYPE ANALYSIS
----------------------------------------"""
            type_analysis = self.anomaly_log['anomaly_type'].value_counts().head(8)
            for threat_type, count in type_analysis.items():
                percentage = (count / total_anomalies) * 100
                report += f"\n{threat_type.replace('_', ' ').title()}: {count} incidents ({percentage:.1f}%)"

        # Temporal analysis
        if 'timestamp' in self.anomaly_log.columns:
            report += f"""

TEMPORAL PATTERNS
----------------------------------------"""
            hourly_stats = self.anomaly_log.groupby(self.anomaly_log['timestamp'].dt.hour)['anomaly_score'].agg(
                ['count', 'mean'])
            peak_hour = hourly_stats['count'].idxmax()
            peak_count = hourly_stats['count'].max()
            business_hours = len(self.anomaly_log[self.anomaly_log['timestamp'].dt.hour.between(9, 17)])
            off_hours = total_anomalies - business_hours

            report += f"\nPeak Activity: {peak_hour}:00 with {peak_count} incidents"
            report += f"\nBusiness Hours (9-17): {business_hours} incidents ({business_hours / total_anomalies * 100:.1f}%)"
            report += f"\nOff Hours: {off_hours} incidents ({off_hours / total_anomalies * 100:.1f}%)"

        # Key statistics
        report += f"""

KEY STATISTICS
----------------------------------------
Average Packet Size: {self.anomaly_log['packet_size'].mean():.0f} bytes
Largest Packet: {self.anomaly_log['packet_size'].max():,} bytes
Average Duration: {self.anomaly_log['duration_ms'].mean():.0f} ms
Longest Duration: {self.anomaly_log['duration_ms'].max():,} ms

SECURITY RECOMMENDATIONS
----------------------------------------"""

        # Generate smart recommendations
        recommendations = []

        critical_count = severity_dist.get('Critical', 0)
        high_count = severity_dist.get('High', 0)

        if critical_count > 0:
            recommendations.append(f"URGENT: Investigate {critical_count} critical-severity incidents immediately")

        if high_count > 0:
            recommendations.append(f"HIGH PRIORITY: Review {high_count} high-risk incidents within 24 hours")

        # Port-specific recommendations
        suspicious_ports = [port for port in top_ports.index if port not in [80, 443, 22, 8080, 21, 25, 53]]
        if suspicious_ports:
            recommendations.append(f"Monitor/block suspicious ports: {', '.join(map(str, suspicious_ports))}")

        # Size-based recommendations
        if self.anomaly_log['packet_size'].max() > 3000:
            large_packets = len(self.anomaly_log[self.anomaly_log['packet_size'] > 2000])
            recommendations.append(f"Review {large_packets} large packet transfers (potential data exfiltration)")

        # Protocol recommendations
        if 'UDP' in protocol_dist and protocol_dist['UDP'] / total_anomalies > 0.3:
            recommendations.append("High UDP anomaly rate detected - review DNS and other UDP services")

        # Standard recommendations
        recommendations.extend([
            "Implement real-time alerting for anomaly scores < -0.05",
            "Set up automated incident response workflows",
            "Conduct weekly security team reviews of anomaly patterns",
            "Update network monitoring rules based on detected patterns",
            "Consider network segmentation for high-risk traffic flows"
        ])

        for i, rec in enumerate(recommendations, 1):
            report += f"\n{i:2d}. {rec}"

        report += f"""

RISK ASSESSMENT
----------------------------------------
Overall Risk Level: {'CRITICAL' if critical_count > 0 else 'HIGH' if high_count > 0 else 'MEDIUM'}
Trend Analysis: {'Increasing' if len(self.anomaly_log) > 50 else 'Stable'}
Business Impact: Network security incidents requiring investigation

NEXT STEPS
----------------------------------------
1. Prioritize investigation of high-severity incidents
2. Implement recommended security controls
3. Schedule follow-up analysis in 7 days
4. Brief security leadership on findings

========================================
Report generated by Network Security Analyzer
Contact: security-team@company.com
========================================
"""

        # Save report
        try:
            with open('reports/security_report.txt', 'w', encoding='utf-8') as f:
                f.write(report)
            print("✅ Security report saved as 'reports/security_report.txt'")
        except Exception as e:
            print(f"⚠️ Error saving report: {e}")
            print("\n" + "=" * 60)
            print(report)

    def create_performance_analysis(self):
        """Create LLM performance analysis if metrics are available."""
        if not self.performance_metrics:
            print("⚠️ No performance metrics available")
            return

        print("📊 Creating performance analysis...")

        fig, axes = plt.subplots(2, 2, figsize=(16, 10))
        fig.suptitle('AI Template Performance Analysis', fontsize=16, fontweight='bold')

        templates = list(self.performance_metrics.keys())
        response_times = []
        response_lengths = []
        usage_counts = []
        error_rates = []

        for template in templates:
            metrics = self.performance_metrics[template]
            avg_time = np.mean(metrics.get('response_times', [0]))
            avg_length = np.mean(metrics.get('response_lengths', [0]))
            usage = metrics.get('usage_count', 0)
            errors = metrics.get('error_count', 0)
            error_rate = (errors / usage * 100) if usage > 0 else 0

            response_times.append(avg_time)
            response_lengths.append(avg_length)
            usage_counts.append(usage)
            error_rates.append(error_rate)

        # 1. Response Times
        colors = plt.cm.Set3(np.linspace(0, 1, len(templates)))
        bars1 = axes[0, 0].bar(range(len(templates)), response_times, color=colors)
        axes[0, 0].set_title('Average Response Times', fontweight='bold')
        axes[0, 0].set_ylabel('Time (seconds)')
        axes[0, 0].set_xticks(range(len(templates)))
        axes[0, 0].set_xticklabels([t.replace('_', ' ').title() for t in templates], rotation=45, ha='right')

        for bar, value in zip(bars1, response_times):
            axes[0, 0].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                            f'{value:.2f}s', ha='center', va='bottom', fontsize=9)

        # 2. Response Lengths
        bars2 = axes[0, 1].bar(range(len(templates)), response_lengths, color=colors)
        axes[0, 1].set_title('Average Response Lengths', fontweight='bold')
        axes[0, 1].set_ylabel('Words per Response')
        axes[0, 1].set_xticks(range(len(templates)))
        axes[0, 1].set_xticklabels([t.replace('_', ' ').title() for t in templates], rotation=45, ha='right')

        for bar, value in zip(bars2, response_lengths):
            axes[0, 1].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                            f'{value:.0f}', ha='center', va='bottom', fontsize=9)

        # 3. Usage Frequency
        bars3 = axes[1, 0].bar(range(len(templates)), usage_counts, color=colors)
        axes[1, 0].set_title('Template Usage Frequency', fontweight='bold')
        axes[1, 0].set_ylabel('Number of Uses')
        axes[1, 0].set_xticks(range(len(templates)))
        axes[1, 0].set_xticklabels([t.replace('_', ' ').title() for t in templates], rotation=45, ha='right')

        for bar, value in zip(bars3, usage_counts):
            axes[1, 0].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                            f'{value}', ha='center', va='bottom', fontsize=9)

        # 4. Error Rates
        error_colors = ['red' if x > 5 else 'orange' if x > 1 else 'green' for x in error_rates]
        bars4 = axes[1, 1].bar(range(len(templates)), error_rates, color=error_colors)
        axes[1, 1].set_title('Error Rates', fontweight='bold')
        axes[1, 1].set_ylabel('Error Rate (%)')
        axes[1, 1].set_xticks(range(len(templates)))
        axes[1, 1].set_xticklabels([t.replace('_', ' ').title() for t in templates], rotation=45, ha='right')

        for bar, value in zip(bars4, error_rates):
            axes[1, 1].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                            f'{value:.1f}%', ha='center', va='bottom', fontsize=9)

        plt.tight_layout()
        plt.savefig('images/performance_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("✅ Performance analysis saved as 'images/performance_analysis.png'")

    def create_correlation_analysis(self):
        """Create correlation analysis of anomaly features."""
        if self.anomaly_log.empty:
            return

        print("🔥 Creating correlation analysis...")

        # Select numeric columns
        numeric_cols = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'anomaly_score']
        correlation_data = self.anomaly_log[numeric_cols]
        correlation_matrix = correlation_data.corr()

        # Create correlation plot
        plt.figure(figsize=(10, 8))
        mask = np.triu(np.ones_like(correlation_matrix, dtype=bool))

        sns.heatmap(correlation_matrix, mask=mask, annot=True, cmap='RdBu_r', center=0,
                    square=True, linewidths=0.5, cbar_kws={"shrink": .8}, fmt='.3f')

        plt.title('Feature Correlation Analysis', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig('images/correlation_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()

        # Print insights
        print("🔍 Key Correlations:")
        strong_correlations = []
        for i in range(len(correlation_matrix.columns)):
            for j in range(i + 1, len(correlation_matrix.columns)):
                corr_value = correlation_matrix.iloc[i, j]
                if abs(corr_value) > 0.3:
                    col1, col2 = correlation_matrix.columns[i], correlation_matrix.columns[j]
                    direction = "positively" if corr_value > 0 else "negatively"
                    strong_correlations.append((col1, col2, corr_value, direction))

        if strong_correlations:
            for col1, col2, corr, direction in sorted(strong_correlations, key=lambda x: abs(x[2]), reverse=True)[:5]:
                print(f"   • {col1} and {col2} are {direction} correlated (r={corr:.3f})")
        else:
            print("   • No strong correlations found (threshold: |r| > 0.3)")

        print("✅ Correlation analysis saved as 'images/correlation_analysis.png'")

    def print_summary(self):
        """Print summary of generated files and insights."""
        print("\n" + "=" * 60)
        print("📊 ANALYSIS COMPLETE - SUMMARY")
        print("=" * 60)

        if not self.anomaly_log.empty:
            total = len(self.anomaly_log)
            severity_dist = self._calculate_severity_distribution()

            print(f"📈 Dataset Overview:")
            print(f"   • Total Anomalies Analyzed: {total:,}")
            print(f"   • Training Data Records: {len(self.training_df):,}")
            print(
                f"   • Time Period: {self.anomaly_log['timestamp'].min() if 'timestamp' in self.anomaly_log.columns else 'Unknown'} to {self.anomaly_log['timestamp'].max() if 'timestamp' in self.anomaly_log.columns else 'Unknown'}")

            print(f"\n🎯 Threat Overview:")
            for severity, count in severity_dist.items():
                print(f"   • {severity}: {count} incidents ({count / total * 100:.1f}%)")

            print(f"\n📁 Generated Files:")
            files = [
                ('images/security_dashboard.png', 'Main security dashboard'),
                ('images/pca_analysis.png', 'PCA analysis'),
                ('images/correlation_analysis.png', 'Correlation analysis'),
                ('images/performance_analysis.png', 'AI performance metrics'),
                ('reports/interactive_dashboard.html', 'Interactive web dashboard'),
                ('reports/security_report.txt', 'Security analysis report')
            ]

            for filepath, description in files:
                if os.path.exists(filepath):
                    size = os.path.getsize(filepath)
                    size_str = f"{size / 1024:.1f}KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f}MB"
                    print(f"   ✅ {filepath} ({size_str}) - {description}")
                else:
                    print(f"   ⚠️  {filepath} - Not generated")

            print(f"\n🔍 Key Insights:")
            top_port = self.anomaly_log['src_port'].value_counts().index[0]
            worst_score = self.anomaly_log['anomaly_score'].min()
            print(f"   • Most problematic port: {top_port}")
            print(f"   • Worst anomaly score: {worst_score:.4f}")
            print(f"   • Average packet size: {self.anomaly_log['packet_size'].mean():.0f} bytes")

            print(f"\n🚀 Next Steps:")
            print(f"   1. Open interactive dashboard: reports/interactive_dashboard.html")
            print(f"   2. Review security report: reports/security_report.txt")
            print(f"   3. Investigate high-severity incidents")
            print(f"   4. Implement recommended security controls")

        print("=" * 60)

    def run_full_analysis(self):
        """Run complete analysis suite."""
        print("🎨 Network Anomaly Detection Visualization System")
        print("=" * 55)
        print("🔍 Advanced Security Analytics & Threat Intelligence")
        print("=" * 55)

        # Load data
        if not self.load_data():
            print("❌ Cannot proceed without data. Please check your configuration.")
            return

        if self.anomaly_log.empty:
            print("❌ No anomaly data found. Please run the detection system first.")
            return

        print(f"\n✅ Data loaded successfully!")
        print(f"   • Anomaly records: {len(self.anomaly_log):,}")
        print(f"   • Training records: {len(self.training_df):,}")
        print(f"   • Performance metrics: {len(self.performance_metrics)} templates")

        # Create all visualizations
        print(f"\n📊 Creating comprehensive dashboard...")
        self.create_comprehensive_dashboard()

        print(f"\n🔬 Creating PCA analysis...")
        self.create_pca_analysis()

        print(f"\n🔥 Creating correlation analysis...")
        self.create_correlation_analysis()

        print(f"\n🎨 Creating interactive dashboard...")
        self.create_interactive_dashboard()

        if self.performance_metrics:
            print(f"\n📊 Creating performance analysis...")
            self.create_performance_analysis()

        print(f"\n📋 Generating security report...")
        self.generate_security_report()

        # Print summary
        self.print_summary()


def main():
    """Main execution function."""
    visualizer = NetworkAnomalyVisualizer()
    visualizer.run_full_analysis()


if __name__ == "__main__":
    main()