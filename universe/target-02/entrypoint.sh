#!/bin/bash
# TARGET-02: SSH + Samba com credenciais fracas
# Flag: flag{ssh_ghost} em /home/admin/flag.txt
# Credencial extra: senha MySQL encontrada em /opt/config.ini

set -e

# Criar usuários com senhas fracas
useradd -m -s /bin/bash admin
echo "admin:password123" | chpasswd
echo "root:toor" | chpasswd

useradd -m -s /bin/bash developer
echo "developer:dev2026" | chpasswd

# Flag no home do admin
mkdir -p /home/admin/.ssh
echo "flag{ssh_ghost_2026}" > /home/admin/flag.txt
echo "flag{ssh_ghost_2026}" > /home/admin/.hidden_flag
chmod 600 /home/admin/flag.txt

# SSH key fraca (para brute-force por key)
ssh-keygen -t rsa -b 1024 -f /home/admin/.ssh/id_rsa -N ""
cp /home/admin/.ssh/id_rsa.pub /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh

# Config com credenciais do MySQL (TARGET-04)
cat > /opt/config.ini << 'EOF'
[database]
host = 10.0.0.40
port = 3306
user = root
password = MySQL_R00t_2026!
database = corporate

[backup]
smb_share = //10.0.0.20/backups
smb_user = admin
smb_pass = password123

[ssh]
key_location = /home/admin/.ssh/id_rsa
jump_host = 10.0.0.10
EOF

chmod 644 /opt/config.ini

# Samba compartilhamento com arquivo sensível
mkdir -p /srv/samba/share /srv/samba/admin
echo "Samba config backup - DO NOT SHARE" > /srv/samba/share/readme.txt
echo "Admin credentials: admin:password123" > /srv/samba/admin/creds.txt
echo "MySQL internal: root:MySQL_R00t_2026!@10.0.0.40" >> /srv/samba/admin/creds.txt
echo "flag{ssh_ghost_2026}" >> /srv/samba/admin/secret.txt

# Configurar Samba
cat > /etc/samba/smb.conf << 'EOF'
[global]
   workgroup = WORKGROUP
   server string = Target-02 File Server
   security = user
   map to guest = Bad User
   dns proxy = no

[share]
   path = /srv/samba/share
   browsable = yes
   writable = no
   guest ok = yes

[admin]
   path = /srv/samba/admin
   browsable = yes
   writable = no
   valid users = admin
   create mask = 0644
EOF

# Criar usuário samba
(echo "password123"; echo "password123") | smbpasswd -a -s admin

# Script de informações do sistema
cat > /opt/sysinfo.sh << 'EOF'
#!/bin/bash
echo "=== Target-02 System Info ==="
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | head -2)"
echo "Kernel: $(uname -r)"
echo "IP: $(hostname -I)"
echo "Users: $(cut -d: -f1 /etc/passwd | tr '\n' ' ')"
echo "Open ports: $(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null)"
echo "Samba shares: $(smbclient -L localhost -N 2>/dev/null | grep -i share || echo 'local only')"
EOF
chmod +x /opt/sysinfo.sh

# Start SSH in background, then run Samba in foreground
/usr/sbin/sshd
echo "[+] SSH started on port 22"
echo "[+] Starting Samba..."
exec smbd --foreground --no-process-group
