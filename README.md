# phpMyAdmin Installation Guide

phpMyAdmin is a free and open-source Database Management. A web interface for MySQL and MariaDB administration

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 80 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 80 (default phpmyadmin port)
  - Firewall rules configured
- **Dependencies**:
  - php, php-mysql, php-mbstring
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install phpmyadmin
sudo dnf install -y phpmyadmin php, php-mysql, php-mbstring

# Enable and start service
sudo systemctl enable --now httpd

# Configure firewall
sudo firewall-cmd --permanent --add-service=phpmyadmin || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
phpmyadmin --version || systemctl status httpd
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install phpmyadmin
sudo apt install -y phpmyadmin php, php-mysql, php-mbstring

# Enable and start service
sudo systemctl enable --now httpd

# Configure firewall
sudo ufw allow 80

# Verify installation
phpmyadmin --version || systemctl status httpd
```

### Arch Linux

```bash
# Install phpmyadmin
sudo pacman -S phpmyadmin

# Enable and start service
sudo systemctl enable --now httpd

# Verify installation
phpmyadmin --version || systemctl status httpd
```

### Alpine Linux

```bash
# Install phpmyadmin
apk add --no-cache phpmyadmin

# Enable and start service
rc-update add httpd default
rc-service httpd start

# Verify installation
phpmyadmin --version || rc-service httpd status
```

### openSUSE/SLES

```bash
# Install phpmyadmin
sudo zypper install -y phpmyadmin php, php-mysql, php-mbstring

# Enable and start service
sudo systemctl enable --now httpd

# Configure firewall
sudo firewall-cmd --permanent --add-service=phpmyadmin || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
phpmyadmin --version || systemctl status httpd
```

### macOS

```bash
# Using Homebrew
brew install phpmyadmin

# Start service
brew services start phpmyadmin

# Verify installation
phpmyadmin --version
```

### FreeBSD

```bash
# Using pkg
pkg install phpmyadmin

# Enable in rc.conf
echo 'httpd_enable="YES"' >> /etc/rc.conf

# Start service
service httpd start

# Verify installation
phpmyadmin --version || service httpd status
```

### Windows

```powershell
# Using Chocolatey
choco install phpmyadmin

# Or using Scoop
scoop install phpmyadmin

# Verify installation
phpmyadmin --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /etc/phpMyAdmin

# Set up basic configuration
sudo tee /etc/phpMyAdmin/phpmyadmin.conf << 'EOF'
# phpMyAdmin Configuration
$cfg[ExecTimeLimit] = 600
EOF

# Set appropriate permissions
sudo chown -R phpmyadmin:phpmyadmin /etc/phpMyAdmin || \
  sudo chown -R $(whoami):$(whoami) /etc/phpMyAdmin

# Test configuration
sudo phpmyadmin --test || sudo httpd configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false phpmyadmin || true

# Secure configuration files
sudo chmod 750 /etc/phpMyAdmin
sudo chmod 640 /etc/phpMyAdmin/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable httpd

# Start service
sudo systemctl start httpd

# Stop service
sudo systemctl stop httpd

# Restart service
sudo systemctl restart httpd

# Reload configuration
sudo systemctl reload httpd

# Check status
sudo systemctl status httpd

# View logs
sudo journalctl -u httpd -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add httpd default

# Start service
rc-service httpd start

# Stop service
rc-service httpd stop

# Restart service
rc-service httpd restart

# Check status
rc-service httpd status

# View logs
tail -f /var/log/httpd/httpd.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'httpd_enable="YES"' >> /etc/rc.conf

# Start service
service httpd start

# Stop service
service httpd stop

# Restart service
service httpd restart

# Check status
service httpd status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start phpmyadmin
brew services stop phpmyadmin
brew services restart phpmyadmin

# Check status
brew services list | grep phpmyadmin

# View logs
tail -f $(brew --prefix)/var/log/phpmyadmin.log
```

### Windows Service Manager

```powershell
# Start service
net start httpd

# Stop service
net stop httpd

# Using PowerShell
Start-Service httpd
Stop-Service httpd
Restart-Service httpd

# Check status
Get-Service httpd

# Set to automatic startup
Set-Service httpd -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /etc/phpMyAdmin/phpmyadmin.conf << 'EOF'
# Performance tuning
$cfg[ExecTimeLimit] = 600
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart httpd
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream phpmyadmin_backend {
    server 127.0.0.1:80;
    keepalive 32;
}

server {
    listen 80;
    server_name phpmyadmin.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name phpmyadmin.example.com;

    ssl_certificate /etc/ssl/certs/phpmyadmin.crt;
    ssl_certificate_key /etc/ssl/private/phpmyadmin.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://phpmyadmin_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName phpmyadmin.example.com
    Redirect permanent / https://phpmyadmin.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName phpmyadmin.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/phpmyadmin.crt
    SSLCertificateKeyFile /etc/ssl/private/phpmyadmin.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:80/
        ProxyPassReverse http://127.0.0.1:80/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:80/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend phpmyadmin_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/phpmyadmin.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend phpmyadmin_backend

backend phpmyadmin_backend
    balance roundrobin
    option httpchk GET /health
    server phpmyadmin1 127.0.0.1:80 check
```

### Caddy Configuration

```caddy
phpmyadmin.example.com {
    reverse_proxy 127.0.0.1:80 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /etc/phpMyAdmin phpmyadmin || true

# Set ownership
sudo chown -R phpmyadmin:phpmyadmin /etc/phpMyAdmin
sudo chown -R phpmyadmin:phpmyadmin /var/log/httpd

# Set permissions
sudo chmod 750 /etc/phpMyAdmin
sudo chmod 640 /etc/phpMyAdmin/*
sudo chmod 750 /var/log/httpd

# Configure firewall (UFW)
sudo ufw allow from any to any port 80 proto tcp comment "phpMyAdmin"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=phpmyadmin
sudo firewall-cmd --permanent --service=phpmyadmin --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=phpmyadmin
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 80 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/phpmyadmin.key \
    -out /etc/ssl/certs/phpmyadmin.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=phpmyadmin.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/phpmyadmin.key
sudo chmod 644 /etc/ssl/certs/phpmyadmin.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d phpmyadmin.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/phpmyadmin.conf
[phpmyadmin]
enabled = true
port = 80
filter = phpmyadmin
logpath = /var/log/httpd/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/phpmyadmin.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE phpmyadmin_db;
CREATE USER phpmyadmin_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE phpmyadmin_db TO phpmyadmin_user;
\q
EOF

# Configure connection in phpMyAdmin
echo "DATABASE_URL=postgresql://phpmyadmin_user:secure_password_here@localhost/phpmyadmin_db" | \
  sudo tee -a /etc/phpMyAdmin/phpmyadmin.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE phpmyadmin_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'phpmyadmin_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON phpmyadmin_db.* TO 'phpmyadmin_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://phpmyadmin_user:secure_password_here@localhost/phpmyadmin_db" | \
  sudo tee -a /etc/phpMyAdmin/phpmyadmin.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/phpmyadmin
sudo chown phpmyadmin:phpmyadmin /var/lib/phpmyadmin

# Initialize database
sudo -u phpmyadmin phpmyadmin init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
phpmyadmin soft nofile 65535
phpmyadmin hard nofile 65535
phpmyadmin soft nproc 32768
phpmyadmin hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /etc/phpMyAdmin/performance.conf
# Performance configuration
$cfg[ExecTimeLimit] = 600

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart httpd
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'phpmyadmin'
    static_configs:
      - targets: ['localhost:80/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/phpmyadmin-health

# Check if service is running
if ! systemctl is-active --quiet httpd; then
    echo "CRITICAL: phpMyAdmin service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 80 2>/dev/null; then
    echo "CRITICAL: phpMyAdmin is not listening on port 80"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:80/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: phpMyAdmin is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/phpmyadmin
/var/log/httpd/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 phpmyadmin phpmyadmin
    postrotate
        systemctl reload httpd > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/phpmyadmin
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/phpmyadmin-backup

BACKUP_DIR="/backup/phpmyadmin"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/phpmyadmin_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping phpMyAdmin service..."
systemctl stop httpd

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /etc/phpMyAdmin \
    /var/lib/phpmyadmin \
    /var/log/httpd

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump phpmyadmin_db | gzip > "$BACKUP_DIR/phpmyadmin_db_$DATE.sql.gz"
fi

# Start service
echo "Starting phpMyAdmin service..."
systemctl start httpd

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/phpmyadmin-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping phpMyAdmin service..."
systemctl stop httpd

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql phpmyadmin_db
fi

# Fix permissions
chown -R phpmyadmin:phpmyadmin /etc/phpMyAdmin
chown -R phpmyadmin:phpmyadmin /var/lib/phpmyadmin

# Start service
echo "Starting phpMyAdmin service..."
systemctl start httpd

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status httpd
sudo journalctl -u httpd -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 80
sudo lsof -i :80

# Verify configuration
sudo phpmyadmin --test || sudo httpd configtest

# Check permissions
ls -la /etc/phpMyAdmin
ls -la /var/log/httpd
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep httpd
curl -I http://localhost:80

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 80

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep phpmyadmin
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep httpd)
htop -p $(pgrep httpd)

# Check for memory leaks
ps aux | grep httpd
cat /proc/$(pgrep httpd)/status | grep -i vm

# Analyze logs for errors
grep -i error /var/log/httpd/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U phpmyadmin_user -d phpmyadmin_db -c "SELECT 1;"
mysql -u phpmyadmin_user -p phpmyadmin_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /etc/phpMyAdmin/phpmyadmin.conf

# Restart with debug mode
sudo systemctl stop httpd
sudo -u phpmyadmin phpmyadmin --debug

# Watch debug logs
tail -f /var/log/httpd/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep httpd) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/phpmyadmin.pcap port 80
sudo tcpdump -r /tmp/phpmyadmin.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep httpd)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  phpmyadmin:
    image: phpmyadmin:phpmyadmin
    container_name: phpmyadmin
    restart: unless-stopped
    ports:
      - "80:80"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/etc/phpMyAdmin
      - ./data:/var/lib/phpmyadmin
      - ./logs:/var/log/httpd
    networks:
      - phpmyadmin_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  phpmyadmin_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# phpmyadmin-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phpmyadmin
  labels:
    app: phpmyadmin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: phpmyadmin
  template:
    metadata:
      labels:
        app: phpmyadmin
    spec:
      containers:
      - name: phpmyadmin
        image: phpmyadmin:phpmyadmin
        ports:
        - containerPort: 80
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /etc/phpMyAdmin
        - name: data
          mountPath: /var/lib/phpmyadmin
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: phpmyadmin-config
      - name: data
        persistentVolumeClaim:
          claimName: phpmyadmin-data
---
apiVersion: v1
kind: Service
metadata:
  name: phpmyadmin
spec:
  selector:
    app: phpmyadmin
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: phpmyadmin-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# phpmyadmin-playbook.yml
- name: Install and configure phpMyAdmin
  hosts: all
  become: yes
  vars:
    phpmyadmin_version: latest
    phpmyadmin_port: 80
    phpmyadmin_config_dir: /etc/phpMyAdmin
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - php, php-mysql, php-mbstring
        state: present
    
    - name: Install phpMyAdmin
      package:
        name: phpmyadmin
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ phpmyadmin_config_dir }}"
        state: directory
        owner: phpmyadmin
        group: phpmyadmin
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: phpmyadmin.conf.j2
        dest: "{{ phpmyadmin_config_dir }}/phpmyadmin.conf"
        owner: phpmyadmin
        group: phpmyadmin
        mode: '0640'
      notify: restart phpmyadmin
    
    - name: Start and enable service
      systemd:
        name: httpd
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ phpmyadmin_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart phpmyadmin
      systemd:
        name: httpd
        state: restarted
```

### Terraform Configuration

```hcl
# phpmyadmin.tf
resource "aws_instance" "phpmyadmin_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.phpmyadmin.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install phpMyAdmin
    apt-get update
    apt-get install -y phpmyadmin php, php-mysql, php-mbstring
    
    # Configure phpMyAdmin
    systemctl enable httpd
    systemctl start httpd
  EOF
  
  tags = {
    Name = "phpMyAdmin Server"
    Application = "phpMyAdmin"
  }
}

resource "aws_security_group" "phpmyadmin" {
  name        = "phpmyadmin-sg"
  description = "Security group for phpMyAdmin"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "phpMyAdmin Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update phpmyadmin
sudo dnf update phpmyadmin

# Debian/Ubuntu
sudo apt update
sudo apt upgrade phpmyadmin

# Arch Linux
sudo pacman -Syu phpmyadmin

# Alpine Linux
apk update
apk upgrade phpmyadmin

# openSUSE
sudo zypper ref
sudo zypper update phpmyadmin

# FreeBSD
pkg update
pkg upgrade phpmyadmin

# Always backup before updates
/usr/local/bin/phpmyadmin-backup

# Restart after updates
sudo systemctl restart httpd
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /var/log/httpd -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze phpmyadmin_db

# Check disk usage
df -h | grep -E "(/$|phpmyadmin)"
du -sh /var/lib/phpmyadmin

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u httpd | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.phpmyadmin.org/
- GitHub Repository: https://github.com/phpmyadmin/phpmyadmin
- Community Forum: https://forum.phpmyadmin.org/
- Wiki: https://wiki.phpmyadmin.org/
- Docker Hub: https://hub.docker.com/r/phpmyadmin/phpmyadmin
- Security Advisories: https://security.phpmyadmin.org/
- Best Practices: https://docs.phpmyadmin.org/best-practices
- API Documentation: https://api.phpmyadmin.org/
- Comparison with Adminer, MySQL Workbench, HeidiSQL, DBeaver: https://docs.phpmyadmin.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
