# SDN-DDos-synthetic-dataset Generation # SDN-DDoS Dataset Generation Pipeline - Complete Guide

## 📋 Overview

This pipeline generates labeled SDN-DDoS datasets by:

1. Creating virtual SDN networks using Mininet
2. Collecting flow statistics via Ryu controller
3. Generating normal and attack traffic
4. Auto-labeling flows based on heuristics
5. Building clean CSV datasets for ML training

---

## 🔧 Prerequisites

### System Requirements

- **OS**: Ubuntu 20.04/22.04 LTS (or similar Linux)
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: At least 10GB free space
- **Network**: Internet connection for package installation

### Required Software

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python and pip
sudo apt-get install -y python3 python3-pip python3-dev

# Install Mininet
sudo apt-get install -y mininet

# Install OpenvSwitch
sudo apt-get install -y openvswitch-switch

# Install hping3 (for attack traffic generation)
sudo apt-get install -y hping3

# Install iperf (for normal traffic generation)
sudo apt-get install -y iperf

# Install Ryu controller
sudo pip3 install ryu

# Install Python dependencies for dataset processing
sudo pip3 install pandas numpy scikit-learn matplotlib seaborn
```

---

## 📁 Project Structure

Create the following directory structure:

```
sdn-ddos-dataset/
├── ryu_controller.py          # Ryu controller with flow collector
├── mininet_topology.py        # Topology generator and traffic
├── dataset_builder.py         # Dataset aggregation and preprocessing
├── run_pipeline.sh            # Automated execution script
├── requirements.txt           # Python dependencies
└── output/                    # Generated datasets (created automatically)
```

---

## 📦 Installation Steps

### Step 1: Create Project Directory

```bash
mkdir -p ~/sdn-ddos-dataset
cd ~/sdn-ddos-dataset
```

### Step 2: Create requirements.txt

```bash
cat > requirements.txt << EOF
ryu>=4.34
pandas>=1.3.0
numpy>=1.21.0
scikit-learn>=1.0.0
matplotlib>=3.4.0
seaborn>=0.11.0
EOF
```

### Step 3: Install Python Dependencies

```bash
sudo pip3 install -r requirements.txt
```

### Step 4: Save the Python Scripts

Save the three main Python scripts provided:

- `ryu_controller.py` - Ryu SDN Controller
- `mininet_topology.py` - Mininet Topology Generator
- `dataset_builder.py` - Dataset Builder

---

## 🚀 Execution Guide

### Method 1: Step-by-Step Execution

#### Terminal 1: Start Ryu Controller

```bash
cd ~/sdn-ddos-dataset

# Run Ryu controller
sudo ryu-manager ryu_controller.py --verbose
```

Wait until you see:

```
loading app ryu_controller.py
instantiating app ryu_controller.py of SDNDDoSCollector
```

#### Terminal 2: Run Mininet Topologies

Open a new terminal:

```bash
cd ~/sdn-ddos-dataset

# Run topology generator (requires sudo)
sudo python3 mininet_topology.py
```

This will:

- Create 4 different network topologies sequentially
- Generate normal and DDoS traffic
- Collect flow statistics automatically
- Create CSV files: `sdn_ddos_dataset_<timestamp>.csv`

Expected runtime: ~25-30 minutes (5-7 min per topology)

#### Terminal 3: Build Dataset (After Traffic Generation)

After all topologies complete:

```bash
cd ~/sdn-ddos-dataset

# Aggregate and process all CSV files
python3 dataset_builder.py
```

This creates:

- `sdn_ddos_complete.csv` - Full processed dataset
- `sdn_ddos_train.csv` - Training set (80%)
- `sdn_ddos_test.csv` - Test set (20%)

---

### Method 2: Automated Execution Script

Create `run_pipeline.sh`:

```bash
cat > run_pipeline.sh << 'EOF'
#!/bin/bash

echo "=========================================="
echo "SDN-DDoS Dataset Generation Pipeline"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Create output directory
mkdir -p output
cd output

echo -e "\n${GREEN}Step 1: Starting Ryu Controller${NC}"
ryu-manager ../ryu_controller.py --verbose > ryu.log 2>&1 &
RYU_PID=$!
echo "Ryu PID: $RYU_PID"
sleep 5

# Check if Ryu started successfully
if ! ps -p $RYU_PID > /dev/null; then
    echo -e "${RED}Failed to start Ryu controller${NC}"
    exit 1
fi

echo -e "${GREEN}Step 2: Running Mininet Topologies${NC}"
python3 ../mininet_topology.py

echo -e "\n${GREEN}Step 3: Stopping Ryu Controller${NC}"
kill $RYU_PID
sleep 2

echo -e "\n${GREEN}Step 4: Building Dataset${NC}"
cd ..
python3 dataset_builder.py

echo -e "\n${GREEN}=========================================="
echo -e "Pipeline Complete!"
echo -e "==========================================${NC}"
echo -e "\nGenerated files in output/ directory:"
ls -lh output/*.csv

EOF

chmod +x run_pipeline.sh
```

Run the automated script:

```bash
sudo ./run_pipeline.sh
```

---

## 📊 Dataset Features

The generated dataset includes **23+ features**:

### Flow Identification

- `timestamp` - Flow collection time
- `datapath_id` - Switch identifier
- `flow_id` - Unique flow ID
- `src_ip`, `dst_ip` - Source/destination IPs
- `src_port`, `dst_port` - Source/destination ports
- `protocol` - Protocol number (1=ICMP, 6=TCP, 17=UDP)

### Flow Statistics

- `duration_sec`, `duration_nsec` - Flow duration
- `idle_timeout`, `hard_timeout` - Timeout values
- `priority` - Flow entry priority
- `packet_count` - Total packets
- `byte_count` - Total bytes

### Derived Metrics

- `packet_rate` - Packets per second
- `byte_rate` - Bytes per second
- `flow_speed` - Flow packets per second
- `bytes_per_packet` - Average packet size
- `flow_duration` - Total flow time
- `flow_iat` - Inter-arrival time

### Engineered Features

- `packets_per_second` - Normalized packet rate
- `bytes_per_second` - Normalized byte rate
- `is_tcp`, `is_udp`, `is_icmp` - Protocol flags
- `is_well_known_port` - Common port flag

### Label

- `label` - 0 = Normal, 1 = DDoS

---

## 🎯 Traffic Patterns Generated

### Normal Traffic

- **ICMP**: Low-rate ping (0.5s interval)
- **TCP**: HTTP-like traffic using iperf (10Mbps)
- **Pattern**: Steady, predictable rates
- **Duration**: Throughout experiment

### DDoS Attack Traffic

- **ICMP Flood**: `hping3 --icmp --flood`
- **SYN Flood**: `hping3 -S --flood -p 80`
- **UDP Flood**: `hping3 --udp --flood -p 53`
- **Pattern**: Very high packet rates (1000+ pps)
- **Duration**: 70% of topology runtime
- **Attackers**: 20% of hosts

---

## 🔍 Labeling Heuristics

Flows are automatically labeled as DDoS (1) if they meet any criteria:

1. **High packet rate**: > 1000 packets/second
2. **High rate + small packets**: > 500 pps AND < 100 bytes/packet
3. **Sustained high rate**: > 300 pps AND > 5000 total packets
4. **Known attacker IP**: Marked during attack generation

Otherwise labeled as Normal (0).

---

## ✅ Verification

### Check Controller Output

```bash
tail -f output/ryu.log
```

Look for:

```
CSV file initialized: sdn_ddos_dataset_<timestamp>.csv
Switch connected: 1
Switch connected: 2
...
```

### Check Generated Data

```bash
# Count rows in dataset
wc -l output/sdn_ddos_dataset_*.csv

# Check first few rows
head -20 output/sdn_ddos_dataset_*.csv

# Check class distribution
python3 << EOF
import pandas as pd
import glob

files = glob.glob('output/sdn_ddos_dataset_*.csv')
for f in files:
    df = pd.read_csv(f)
    print(f"\n{f}:")
    print(f"  Total flows: {len(df)}")
    print(f"  Normal: {(df['label']==0).sum()}")
    print(f"  DDoS: {(df['label']==1).sum()}")
EOF
```

---

## 🐛 Troubleshooting

### Issue: "Command not found: ryu-manager"

```bash
# Reinstall Ryu
sudo pip3 uninstall ryu
sudo pip3 install ryu
```

### Issue: "Cannot find ovs-vsctl"

```bash
# Reinstall OpenvSwitch
sudo apt-get install --reinstall openvswitch-switch
sudo service openvswitch-switch restart
```

### Issue: "Permission denied" errors

```bash
# Always run Mininet with sudo
sudo python3 mininet_topology.py
```

### Issue: No CSV files generated

Check Ryu log for errors:

```bash
cat output/ryu.log | grep -i error
```

### Issue: Mininet cleanup

If Mininet doesn't exit cleanly:

```bash
sudo mn -c  # Clean up Mininet
sudo killall -9 controller  # Kill controllers
```

---

## 📈 Expected Results

### Dataset Size

- **Per topology**: 500-2000 flows
- **Total (4 topologies)**: 2000-8000 flows
- **File size**: 500KB - 2MB per CSV

### Class Distribution

- **Normal**: ~60-70%
- **DDoS**: ~30-40%

---

## 🔄 Customization

### Modify Number of Topologies

Edit `mininet_topology.py`:

```python
topologies = [
    (LinearTopology, "Linear"),
    (TreeTopology, "Tree"),
    (MeshTopology, "Mesh"),
    (DataCenterTopology, "DataCenter"),
    # Add more topologies here
]
```

### Adjust Traffic Duration

```python
duration_per_topology = 300  # Change to desired seconds
```

### Modify Attack Intensity

In `generate_attack_traffic()`:

```python
# Increase/decrease number of attack types
# Adjust victim count
# Change attack duration
```

### Change Labeling Thresholds

Edit `_label_flow()` in `ryu_controller.py`:

```python
if packet_rate > 1000:  # Adjust threshold
    return 1
```

---

## 📚 Next Steps: Train ML Models

After generating the dataset, use it to train ML models:

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Load data
train = pd.read_csv('sdn_ddos_train.csv')
test = pd.read_csv('sdn_ddos_test.csv')

# Separate features and labels
X_train = train.drop('label', axis=1)
y_train = train['label']
X_test = test.drop('label', axis=1)
y_test = test['label']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))
```

---

## 📞 Support

For issues or questions:

1. Check the troubleshooting section
2. Review Ryu logs: `output/ryu.log`
3. Check Mininet cleanup: `sudo mn -c`
4. Verify all dependencies are installed

---

## 📄 License

This pipeline is provided for educational and research purposes.
