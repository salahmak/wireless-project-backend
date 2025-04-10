# Network Monitoring Backend

A network monitoring system based on Zeek that detects and blocks malicious network traffic on a router.

## Features

- Real-time network traffic monitoring using Zeek
- ML-based detection of malicious connections
- Automatic blocking of malicious IPs after multiple detections
- Configurable threshold for malicious activity blocking

## Installation

1. Clone this repository
2. Run the setup script:
   ```
   ./setup.sh
   ```

## Configuration

The system can be configured through environment variables in the `.env` file:

- `MALICIOUS_THRESHOLD`: Number of malicious detections before blocking an IP (default: 5)
- `DB_*`: Database connection settings

## Usage

Run the monitoring system:

```
python run.py -i <interface> -t <threshold>
```

Arguments:
- `-i, --interface`: Network interface to monitor (default: wlan0)
- `-t, --threshold`: Number of malicious detections before blocking an IP (default: 5)
- `-m, --model`: Path to the ML model file (default: models/final_bal_dt_(best)_model.pkl)

## How It Works

1. The system monitors network traffic using Zeek
2. Each connection is analyzed using a machine learning model to detect malicious activity
3. When malicious traffic is detected, it's logged in the database
4. If an IP address is detected making malicious connections multiple times (exceeding the threshold), it's automatically blocked using iptables
5. Blocked IPs are tracked in the database and can be managed through the system

## Security Note

The IP blocking feature uses iptables and requires sudo privileges. The system is designed to only block IPs after multiple detections to prevent false positives, but care should be taken when deploying in production environments.
