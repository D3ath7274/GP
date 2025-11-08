# SystemAPI Documentation

## Table of Contents
1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Architecture](#architecture)
4. [Authentication](#authentication)
5. [API Endpoints](#api-endpoints)
6. [Configuration](#configuration)
7. [Running the Application](#running-the-application)
8. [Error Handling](#error-handling)

---

## Overview

SystemAPI is a Flask-based REST API designed to provide real-time system monitoring and firewall management capabilities. It allows remote controllers to query system metrics (CPU, memory, disk, network ports) and configure iptables firewall rules.

### Key Features
- Real-time system resource monitoring (CPU, memory, disk usage)
- Open port and service discovery
- iptables firewall rule management
- Snort IDS rule management
- API authentication using API keys
- Request format validation
- Parallel daemon for rule cleanup

### Technology Stack
- **Framework**: Flask
- **Language**: Python 3
- **Database**: SQLite3
- **Modules**: System monitoring, iptables management, interpreter

---

## Installation & Setup

### Directory Structure

```
project/
├── classes/
│   ├── system.py
│   └── iptables.py
├── interpreter/
│   └── interpreterMain.py
├── parallel/
│   └── ruleCleaner.py
├── database/
│   └── apiConfiguration.db
└── main.py (this application)
```

### Required Imports

The application imports from three custom modules:
- `system.py` - System resource monitoring
- `iptables.py` - Firewall rule management
- `interpreterMain.py` - Interactive configuration interpreter
- `ruleCleaner.py` - Parallel daemon for rule maintenance

### Prerequisites

```bash
pip install flask
```

---

## Architecture

### Module Organization

#### System Module (`classes/system.py`)
Handles all system monitoring operations. Initialize with a resource type:
- `"DISK"` - Disk storage monitoring
- `"CPU"` - CPU usage monitoring
- `"MEM"` - Memory usage monitoring
- `"PORT"` - Network port monitoring

#### iptables Module (`classes/iptables.py`)
Manages firewall rules with parameters: Table, Action, Chain, Rule, and source address.

#### Interpreter Module (`interpreter/interpreterMain.py`)
Provides an interactive CLI for system configuration.

#### Rule Cleaner (`parallel/ruleCleaner.py`)
Runs as a background daemon process to maintain and clean up firewall rules.

---

## Authentication

### Authentication Decorator: `@requestAuth`

The `requestAuth` decorator validates API requests against stored credentials in the database.

**Process**:
1. Extracts API key from request JSON body (`"API Register Key"`)
2. Queries SQLite database for registered API keys
3. Compares provided key with stored key
4. Returns 400 error if authentication fails

**Usage**:
```python
@app.route('/api/example', methods=['POST'])
@requestAuth
def example_endpoint():
    return jsonify({"Response": "Success"})
```

**Important**: Authentication is currently commented out in all endpoints. Uncomment decorators to enable security.

### Request Format Validation: `@requestFormat`

The `requestFormat` decorator validates that requests contain all required fields for specific operations.

**Supported Request Situations**:

| Situation | Required Fields |
|-----------|-----------------|
| `general` | API Register Key |
| `untrust` | API Description, Controller Key, API Register Key |
| `trust` | API Description, API Port, API Register Key |
| `iptables` | API Register Key, Table, Action, Chain, Rule |
| `snort` | API Register Key, Action, Rule |

**Validation Process**:
1. Checks if all required fields are present
2. Verifies no extra fields exist
3. Returns 400 error if format is incorrect

**Usage**:
```python
@app.route('/api/iptables', methods=['POST'])
@requestFormat("iptables")
def apiIptablesCreate():
    # Process request
    pass
```

---

## API Endpoints

### System Monitoring Endpoints

#### 1. Disk Usage Information

**Endpoint**: `/api/system/disk/<disk_name>/<byte_unity>`

**Method**: GET

**Parameters**:
- `disk_name`: Disk identifier (use `+` instead of `/`, e.g., `+dev+sda1` for `/dev/sda1`). Use `all` to query all mounted disks.
- `byte_unity`: Unit for byte conversion (e.g., `GB`, `MB`, `KB`)

**Response**:
```json
{
  "Response": [
    {
      "disk": "/dev/sda1",
      "total": 100.5,
      "used": 45.2,
      "free": 55.3,
      "percent": 45
    }
  ],
  "Status": "Success"
}
```

**Error Response**:
```json
{
  "Response": "Disco não existe ou não está montado no sistema.",
  "Status": "Error"
}
```

**Notes**:
- Disk must be mounted in the system filesystem
- Only reports mounted partitions
- Example: `/api/system/disk/all/GB`

---

#### 2. CPU Usage

**Endpoint**: `/api/system/cpu`

**Method**: GET

**Response**:
```json
{
  "Response": {
    "cpu0": 15.5,
    "cpu1": 22.3,
    "cpu2": 18.7,
    "cpu3": 12.1
  },
  "Status": "Success"
}
```

**Notes**:
- Returns percentage utilization for each CPU core
- Lightweight endpoint, suitable for frequent polling

---

#### 3. Memory Usage

**Endpoint**: `/api/system/mem`

**Method**: GET

**Response**:
```json
{
  "Response": {
    "total": 8589934592,
    "used": 4294967296,
    "free": 2147483648,
    "percent": 50.0,
    "available": 3221225472
  },
  "Status": "Success"
}
```

**Notes**:
- Returns memory metrics in bytes (unless specified otherwise)
- Includes used, free, available, and percentage utilization

---

#### 4. Open Ports

**Endpoint**: `/api/system/port/<protocol>`

**Method**: GET

**Parameters**:
- `protocol`: Protocol type (`tcp`, `udp`, or `all`)

**Response**:
```json
{
  "Response": {
    "tcp": [
      {
        "port": 22,
        "service": "ssh",
        "pid": 1234,
        "program": "sshd"
      },
      {
        "port": 80,
        "service": "http",
        "pid": 5678,
        "program": "nginx"
      }
    ],
    "udp": [
      {
        "port": 53,
        "service": "domain",
        "pid": 2345,
        "program": "systemd-resolved"
      }
    ]
  },
  "Status": "Success"
}
```

**Error Response**:
```json
{
  "Response": "Protocolo inválido."
}
```

**Valid Protocols**:
- `tcp` - TCP connections only
- `udp` - UDP connections only
- `all` - Both TCP and UDP

---

### Firewall Management Endpoints

#### 5. iptables Rule Management

**Endpoint**: `/api/iptables`

**Method**: POST

**Request Body**:
```json
{
  "API Register Key": "your-api-key",
  "Table": "filter",
  "Action": "INSERT",
  "Chain": "INPUT",
  "Rule": "-p tcp --dport 80 -j ACCEPT"
}
```

**Parameters**:
- `API Register Key`: Authentication credential
- `Table`: iptables table (`filter`, `nat`, `mangle`, `raw`)
- `Action`: Operation to perform (`INSERT`, `APPEND`, `DELETE`)
- `Chain`: Target chain (`INPUT`, `OUTPUT`, `FORWARD`, custom chains)
- `Rule`: Full iptables rule specification

**Response**:
```json
{
  "status": "success",
  "message": "Rule applied successfully"
}
```

**Notes**:
- Requires iptables access (typically root/sudo)
- Source IP is automatically logged
- Rule validation occurs in the iptables module

---

## Configuration

### Database Schema

The application uses SQLite with the following schema:

#### APIConfig Table
```sql
CREATE TABLE APIConfig (
    id INTEGER PRIMARY KEY,
    host TEXT,
    port INTEGER
);
```

#### RegisterInfo Table
```sql
CREATE TABLE RegisterInfo (
    address TEXT PRIMARY KEY,
    registerkey TEXT
);
```

### Configuration File Location

Configuration is stored in: `database/apiConfiguration.db`

### Initial Setup

The database must be initialized before running the application:

```bash
sqlite3 database/apiConfiguration.db
sqlite> CREATE TABLE APIConfig (id INTEGER PRIMARY KEY, host TEXT, port INTEGER);
sqlite> CREATE TABLE RegisterInfo (address TEXT PRIMARY KEY, registerkey TEXT);
sqlite> INSERT INTO APIConfig VALUES (1, 'localhost', 5000);
```

---

## Running the Application

### Command-Line Interface

The application supports two modes via command-line arguments:

#### 1. Run Mode

```bash
python main.py run
```

**Process**:
1. Forks a child process for the rule cleaner daemon
2. Loads configuration from the database
3. Starts the Flask development server
4. Listens for API requests

**Output**:
```
INFO - Initializing SystemAPI ...
 * Running on http://localhost:5000
```

**Error Handling**:
- Database access errors are caught and reported
- Port binding errors are caught and reported
- KeyboardInterrupt gracefully shuts down the server

---

#### 2. Configuration Mode

```bash
python main.py config
```

**Process**:
- Launches the interactive interpreter for system configuration
- Allows manual configuration of API parameters

---

### Flask Configuration

**Settings**:
```python
app.config['JSON_AS_ASCII'] = False  # Supports Unicode characters in JSON
```

This allows responses to include non-ASCII characters, useful for international system names and messages.

---

## Error Handling

### HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | Successful request |
| 400 | Invalid request format or authentication failure |
| 500 | Server error |

### Common Error Responses

#### Authentication Failure
```json
{
  "Reponse": "ERROR - Authentication with the SystemAPI failed",
  "Status": "400"
}
```

#### Invalid Request Format
```json
{
  "Response": "ERROR - Not all the necessary fields for the specific situation transaction were passed.",
  "Status": "400"
}
```

#### Missing Required Fields
```json
{
  "Response": "ERROR - Incorrect request format for the specific situation",
  "Status": "400"
}
```

#### Database Error
```
ERROR - An error has occurred when accessing the database: [error details]
```

#### Port Binding Error
```
ERROR - An error has occured when initializing the SystemAPI: [error details]
```

---

## Notes for Developers

### Security Considerations

1. **Enable Authentication**: Uncomment `@requestAuth` decorators in production
2. **Enable Format Validation**: Uncomment `@requestFormat` decorators in production
3. **Use HTTPS**: Deploy with SSL/TLS certificates
4. **API Key Rotation**: Implement regular key rotation in production
5. **Rate Limiting**: Consider adding rate limiting to prevent abuse

### Performance Optimization

1. Cache system metrics to reduce I/O overhead
2. Implement request queuing for high-traffic scenarios
3. Use async/await for long-running operations
4. Monitor database query performance

### Maintenance

1. Regularly check the rule cleaner daemon status
2. Archive old firewall rules to prevent database bloat
3. Monitor API response times
4. Review authentication logs for suspicious activity

### Future Enhancements

- Implement request logging and audit trails
- Add support for IPv6 firewall rules
- Create web dashboard for monitoring
- Implement metrics export (Prometheus, etc.)
- Add support for multiple authentication methods

---

## Typo Notice

**Note**: The authentication response contains a typo: `"Reponse"` should be `"Response"`. Consider fixing this for consistency.

---

## License

[Add your license information here]

## Support

For issues or questions, contact: [Add contact information here]