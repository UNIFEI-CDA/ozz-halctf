#!/bin/bash
# CTF full run script — starts universe targets, waits for readiness, runs attack
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/5] Starting Docker daemon (if needed)..."
sudo -n service docker start 2>/dev/null || sudo service docker start 2>/dev/null || true
sleep 3

echo "[2/5] Starting all universe containers..."
cd "$SCRIPT_DIR/universe"
docker compose up -d --build 2>&1

echo "[3/5] Waiting for services to be ready (up to 120s)..."
for i in $(seq 1 60); do
    # Check MySQL
    MYSQL_OK=false
    if docker exec target-04 mysqladmin -u root -pMySQL_R00t_2026! ping --silent 2>/dev/null; then
        MYSQL_OK=true
    fi

    # Check Flask API
    FLASK_OK=false
    if curl -sf http://10.0.0.30:5000/health > /dev/null 2>&1; then
        FLASK_OK=true
    fi

    # Check Web target
    WEB_OK=false
    if curl -sf http://10.0.0.10:80/ > /dev/null 2>&1; then
        WEB_OK=true
    fi

    echo "  [$i/60] MySQL=$MYSQL_OK | Flask=$FLASK_OK | Web=$WEB_OK"

    if $MYSQL_OK && $FLASK_OK && $WEB_OK; then
        echo "  ✅ All services ready after ${i}s"
        break
    fi
    sleep 2
done

echo "[4/5] Granting MySQL TCP access from any host..."
docker exec target-04 mysql -u root -pMySQL_R00t_2026! -e \
  "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'MySQL_R00t_2026!' WITH GRANT OPTION; FLUSH PRIVILEGES;" 2>&1 || true

echo "[4b/5] Verifying MySQL flags table..."
docker exec target-04 mysql -u root -pMySQL_R00t_2026! corporate \
  -e "SELECT secret_key, secret_value FROM internal_secrets;" 2>&1

echo "[5/5] All containers status:"
docker ps

echo ""
echo "Running attack.py..."
cd "$SCRIPT_DIR"
PYTHONUTF8=1 python3 attack.py --verbose 2>&1
