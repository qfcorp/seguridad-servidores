#!/usr/bin/env bash
# =====================================================================
#  AUDITORIA DE SEGURIDAD - QF Producciones
#  Revisa el servidor buscando puertas traseras (backdoors), malas
#  configuraciones y riesgos. SOLO LEE: no cambia, no borra, no instala.
#
#  Uso:   sudo bash auditoria_seguridad.sh
#  Sale:  resumen en pantalla + reporte completo en
#         /root/auditoria_<servidor>_<fecha>.txt
# =====================================================================

VERSION="1.1"
# Carpeta raíz a revisar (solo se cambia para pruebas)
RAIZ="${AUDIT_ROOT:-}"

if [ "$(id -u)" -ne 0 ] && [ -z "$RAIZ" ]; then
  echo "Hay que correrlo con sudo:   sudo bash $0"
  exit 1
fi

HOST="$(hostname 2>/dev/null || echo servidor)"
FECHA="$(date +%Y%m%d_%H%M)"
REPORTE="${AUDIT_OUT:-/root/auditoria_${HOST}_${FECHA}.txt}"
: > "$REPORTE" || { echo "No pude crear $REPORTE"; exit 1; }

CRIT=0; AVISO=0; OK=0
RESUMEN_CRIT=""; RESUMEN_AVISO=""

# ---------- ayudantes ----------
r()      { echo "$*" >> "$REPORTE"; }
titulo() { r ""; r "=================================================="; r "  $*"; r "=================================================="; echo "  revisando: $*"; }
critico(){ CRIT=$((CRIT+1));   r "[CRITICO] $*"; RESUMEN_CRIT="${RESUMEN_CRIT}\n  - ${*%:}"; }
aviso()  { AVISO=$((AVISO+1)); r "[AVISO]   $*"; RESUMEN_AVISO="${RESUMEN_AVISO}\n  - ${*%:}"; }
bien()   { OK=$((OK+1));       r "[OK]      $*"; }
info()   { r "          $*"; }
existe() { command -v "$1" >/dev/null 2>&1; }
corta()  { cut -c1-160; }   # nunca imprimir líneas largas (pueden traer claves)
# ¿El archivo viene de un paquete oficial de Ubuntu? (considera /bin = /usr/bin)
de_paquete() {
  local f="$1"
  dpkg -S "$f" >/dev/null 2>&1 && return 0
  case "$f" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*) dpkg -S "${f#/usr}" >/dev/null 2>&1 && return 0 ;;
    /bin/*|/sbin/*|/lib/*)             dpkg -S "/usr$f"    >/dev/null 2>&1 && return 0 ;;
  esac
  return 1
}
# ¿Es un archivo de configuración de un paquete oficial y NADIE lo modificó?
conffile_intacto() {
  local f="$1" h
  h=$(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | awk -v f="$f" '$1==f {print $2; exit}')
  [ -n "$h" ] && [ "$h" = "$(md5sum < "$RAIZ$f" 2>/dev/null | cut -d' ' -f1)" ]
}

echo ""
echo "Auditoria de seguridad v$VERSION en: $HOST"
echo "Esto tarda de 1 a 5 minutos. No cambia nada en el servidor."
echo ""

r "AUDITORIA DE SEGURIDAD v$VERSION"
r "Servidor: $HOST"
r "Fecha:    $(date '+%Y-%m-%d %H:%M %Z')"

# =====================================================================
titulo "1. SISTEMA Y ACTUALIZACIONES"
# =====================================================================
if [ -r "$RAIZ/etc/os-release" ]; then
  info "Sistema: $(. "$RAIZ/etc/os-release"; echo "$PRETTY_NAME")"
fi
info "Kernel:  $(uname -r)"
info "Encendido: $(uptime -p 2>/dev/null)"

if [ -f "$RAIZ/var/run/reboot-required" ]; then
  aviso "El servidor necesita reiniciarse para aplicar actualizaciones de seguridad (sudo reboot en horario tranquilo)"
else
  bien "No hay reinicio pendiente"
fi

if existe apt && [ -z "$RAIZ" ]; then
  PEND=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
  SEG=$(apt list --upgradable 2>/dev/null | grep -ci security)
  if [ "$SEG" -gt 0 ]; then
    aviso "$SEG actualizaciones DE SEGURIDAD pendientes (de $PEND en total)"
  elif [ "$PEND" -gt 20 ]; then
    aviso "$PEND actualizaciones pendientes"
  else
    bien "Actualizaciones al día ($PEND pendientes)"
  fi
fi

if [ -f "$RAIZ/etc/apt/apt.conf.d/20auto-upgrades" ] && grep -q 'Unattended-Upgrade "1"' "$RAIZ/etc/apt/apt.conf.d/20auto-upgrades" 2>/dev/null; then
  bien "Actualizaciones automáticas de seguridad activadas (unattended-upgrades)"
elif ls "$RAIZ"/usr/local/bin/actualizacion-automatica*.sh >/dev/null 2>&1; then
  bien "Hay script propio de actualización automática"
else
  aviso "No hay actualizaciones automáticas de seguridad"
fi

# =====================================================================
titulo "2. USUARIOS Y PERMISOS DE ADMINISTRADOR"
# =====================================================================
PASSWD="$RAIZ/etc/passwd"; SHADOW="$RAIZ/etc/shadow"

UID0=$(awk -F: '$3==0 && $1!="root"{print $1}' "$PASSWD")
if [ -n "$UID0" ]; then
  critico "Usuario(s) con poderes de root disfrazados (UID 0): $UID0  <- típico de backdoor"
else
  bien "Solo 'root' tiene UID 0"
fi

info ""
info "Usuarios que pueden iniciar sesión (tienen shell):"
awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {printf "            - %-15s uid=%-6s carpeta=%s\n",$1,$3,$6}' "$PASSWD" >> "$REPORTE"

if [ -r "$SHADOW" ]; then
  VACIO=$(awk -F: '$2=="" {print $1}' "$SHADOW")
  if [ -n "$VACIO" ]; then
    critico "Usuario(s) SIN contraseña: $VACIO"
  else
    bien "Ningún usuario tiene la contraseña vacía"
  fi
fi

GSUDO=$(awk -F: '$1=="sudo"||$1=="admin"||$1=="wheel"{print $4}' "$RAIZ/etc/group" | tr '\n' ',' | sed 's/,$//')
info ""
info "Usuarios con sudo (pueden volverse administrador): ${GSUDO:-ninguno}"

NOPASS=$(grep -rhs 'NOPASSWD' "$RAIZ/etc/sudoers" "$RAIZ"/etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' | corta)
if [ -n "$NOPASS" ]; then
  aviso "Hay reglas de sudo SIN contraseña (NOPASSWD). Revisa que sean tuyas:"
  echo "$NOPASS" | sed 's/^/            /' >> "$REPORTE"
else
  bien "Ninguna regla de sudo sin contraseña"
fi

if [ -d "$RAIZ/etc/sudoers.d" ]; then
  info "Archivos en /etc/sudoers.d: $(ls "$RAIZ/etc/sudoers.d" 2>/dev/null | grep -v README | tr '\n' ' ')"
fi

# =====================================================================
titulo "3. ACCESO SSH Y LLAVES AUTORIZADAS"
# =====================================================================
SSHD_CONF=""
if existe sshd && [ -z "$RAIZ" ]; then
  SSHD_CONF=$(sshd -T 2>/dev/null)
fi
if [ -z "$SSHD_CONF" ] && [ -r "$RAIZ/etc/ssh/sshd_config" ]; then
  SSHD_CONF=$(cat "$RAIZ/etc/ssh/sshd_config" "$RAIZ"/etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v '^\s*#' | tr 'A-Z' 'a-z')
fi

if [ -n "$SSHD_CONF" ]; then
  ROOTL=$(echo "$SSHD_CONF" | awk '$1=="permitrootlogin"{print $2; exit}')
  PASSA=$(echo "$SSHD_CONF" | awk '$1=="passwordauthentication"{print $2; exit}')
  PUERTO=$(echo "$SSHD_CONF" | awk '$1=="port"{print $2; exit}')
  info "Puerto SSH: ${PUERTO:-22}"
  case "$ROOTL" in
    no) bien "SSH no deja entrar directo como root" ;;
    prohibit-password|without-password) aviso "root puede entrar por SSH con llave (mejor: PermitRootLogin no)" ;;
    "") aviso "No pude leer PermitRootLogin" ;;
    *) critico "root puede entrar por SSH con contraseña (PermitRootLogin $ROOTL)" ;;
  esac
  if [ "$PASSA" = "no" ]; then
    bien "SSH solo acepta llaves (no contraseñas)"
  else
    aviso "SSH acepta contraseñas -> expuesto a ataques de fuerza bruta. Recomendado: solo llaves"
  fi
else
  info "SSH no instalado o no se pudo leer su configuración"
fi

info ""
info "LLAVES SSH AUTORIZADAS (cada una es una 'llave' que abre el servidor)"
info "Debes reconocer TODAS. Si hay una que no sabes de quién es -> es un riesgo."
TOTAL_LLAVES=0
while IFS=: read -r usuario _ _ _ _ casa _; do
  for f in "$RAIZ$casa/.ssh/authorized_keys" "$RAIZ$casa/.ssh/authorized_keys2"; do
    [ -f "$f" ] || continue
    n=$(grep -cvE '^\s*(#|$)' "$f")
    [ "$n" -eq 0 ] && continue
    TOTAL_LLAVES=$((TOTAL_LLAVES+n))
    info ""
    info "  Usuario '$usuario' ($n llave/s) - archivo modificado: $(date -r "$f" '+%Y-%m-%d %H:%M')"
    grep -vE '^\s*(#|$)' "$f" | while read -r linea; do
      tipo=$(echo "$linea" | grep -oE '(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)' | head -1)
      nombre=$(echo "$linea" | awk '{print $NF}')
      opciones=""
      echo "$linea" | grep -qE '^(command=|from=|restrict|no-)' && opciones=" [con restricciones]"
      info "     - ${tipo:-?}  nombre/comentario: ${nombre:0:60}${opciones}"
    done
    if [ "$(find "$f" -mtime -7 2>/dev/null)" ]; then
      aviso "Las llaves de '$usuario' se modificaron en los últimos 7 días. ¿Fuiste tú?"
    fi
  done
done < "$PASSWD"
info ""
info "Total de llaves autorizadas: $TOTAL_LLAVES"

# =====================================================================
titulo "4. PUERTOS ABIERTOS A INTERNET"
# =====================================================================
# Lista de puertos en escucha. Plan B si no existe 'ss': leer /proc/net/tcp
puertos_escucha() {
  if existe ss; then
    ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}'
  else
    for f in /proc/net/tcp /proc/net/tcp6; do
      [ -r "$f" ] || continue
      awk -v v6="$([ "$f" = /proc/net/tcp6 ] && echo 1)" '
        function hex(h,  i,n,c) { n=0; h=toupper(h); for(i=1;i<=length(h);i++){ c=index("0123456789ABCDEF",substr(h,i,1))-1; n=n*16+c }; return n }
        NR>1 && $4=="0A" {
        split($2,a,":"); port=hex(a[2]); ip=a[1]
        if (v6) { if (ip ~ /^0+$/) ip="[::]"; else if (ip=="00000000000000000000000001000000") ip="[::1]"; else ip="[v6]" }
        else { ip=hex(substr(ip,7,2)) "." hex(substr(ip,5,2)) "." hex(substr(ip,3,2)) "." hex(substr(ip,1,2)) }
        print "tcp", ip ":" port, "(programa?)" }' "$f"
    done
  fi
}
if [ -z "$RAIZ" ]; then
  info "Programas escuchando conexiones desde AFUERA (no solo localhost):"
  PUB=$(puertos_escucha | grep -vE ' (127\.[0-9.]+|\[::1\]|::1|\[::ffff:127\.[0-9.]+\]):[0-9]+ ')
  [ -z "$PUB" ] && info "            (ninguno)"
  echo "$PUB" | sed 's/users:((/  programa: /; s/,pid=.*//; s/^/            /' >> "$REPORTE"
  # Bases de datos y paneles que NUNCA deberían estar abiertos al mundo
  for p in 3306:MySQL 5432:PostgreSQL 6379:Redis 27017:MongoDB 11211:Memcached 9200:Elasticsearch 2375:Docker-API 8086:InfluxDB 5984:CouchDB; do
    puerto=${p%%:*}; nom=${p##*:}
    if echo "$PUB" | awk '{print $2}' | grep -qE ":${puerto}$"; then
      critico "$nom (puerto $puerto) está abierto a internet. Debe escuchar solo en 127.0.0.1"
    fi
  done
fi

# =====================================================================
titulo "5. FIREWALL Y PROTECCION CONTRA FUERZA BRUTA"
# =====================================================================
FW="no"
if existe ufw && [ -z "$RAIZ" ]; then
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    FW="ufw"; bien "Firewall UFW activo"
    ufw status numbered 2>/dev/null | sed 's/^/            /' >> "$REPORTE"
  fi
fi
if [ "$FW" = "no" ] && existe nft && [ -z "$RAIZ" ]; then
  REGLAS=$(nft list ruleset 2>/dev/null | grep -cE '(drop|reject)')
  [ "$REGLAS" -gt 0 ] && { FW="nft"; bien "Firewall nftables con $REGLAS reglas de bloqueo"; }
fi
if [ "$FW" = "no" ] && existe iptables && [ -z "$RAIZ" ]; then
  POL=$(iptables -L INPUT 2>/dev/null | head -1 | grep -oE 'policy [A-Z]+')
  [ "$POL" = "policy DROP" ] && { FW="iptables"; bien "iptables bloquea por defecto"; }
fi
[ "$FW" = "no" ] && [ -z "$RAIZ" ] && aviso "No hay firewall activo: cualquier puerto que se abra queda expuesto a internet"

if existe docker && [ -z "$RAIZ" ] && [ "$FW" = "ufw" ]; then
  info "OJO: Docker se salta UFW. Los puertos publicados por contenedores quedan abiertos aunque UFW diga que no."
fi

if existe fail2ban-client && [ -z "$RAIZ" ] && systemctl is-active --quiet fail2ban; then
  bien "fail2ban activo (bloquea IPs que prueban contraseñas)"
  info "$(fail2ban-client status 2>/dev/null | grep 'Jail list' )"
elif [ -z "$RAIZ" ]; then
  aviso "fail2ban no está instalado/activo (bloquea automáticamente a quien intenta adivinar contraseñas)"
fi

# =====================================================================
titulo "6. TAREAS PROGRAMADAS (CRON Y TIMERS)"
# =====================================================================
# Patrones típicos de backdoor en tareas programadas
PATRON_MALO='(curl|wget)[^|]*\|\s*(ba)?sh|base64\s+-d|/dev/tcp/|\bnc\s+-[a-z]*e|ncat .*-e|bash -i|python[0-9.]* -c|perl -e|/tmp/\.|/dev/shm/|xmrig|kdevtmpfsi|kinsing|minerd'
info "Tareas cron de cada usuario:"
for f in "$RAIZ"/var/spool/cron/crontabs/*; do
  [ -f "$f" ] || continue
  info ""
  info "  [$(basename "$f")]"
  grep -vE '^\s*(#|$)' "$f" | corta | sed 's/^/            /' >> "$REPORTE"
done
info ""
info "Tareas del sistema agregadas a mano (/etc/cron.d):"
for f in "$RAIZ"/etc/cron.d/*; do
  [ -f "$f" ] || continue
  de_paquete "${f#$RAIZ}" && continue   # viene de un paquete oficial
  info "  [${f#$RAIZ}]"
  grep -vE '^\s*(#|$)|^[A-Z_]+=' "$f" | corta | sed 's/^/            /' >> "$REPORTE"
done

SOSP=""
for f in "$RAIZ"/var/spool/cron/crontabs/* "$RAIZ"/etc/crontab "$RAIZ"/etc/cron.d/* \
         "$RAIZ"/etc/cron.hourly/* "$RAIZ"/etc/cron.daily/* "$RAIZ"/etc/cron.weekly/* "$RAIZ"/etc/cron.monthly/*; do
  [ -f "$f" ] || continue
  conffile_intacto "${f#$RAIZ}" && continue   # oficial de Ubuntu y sin tocar (ej. certbot)
  l=$(grep -hsE "$PATRON_MALO" "$f" | grep -v '^\s*#' | corta | sed "s|^|${f#$RAIZ}: |")
  [ -n "$l" ] && SOSP="${SOSP}${l}
"
done
SOSP=$(printf '%s' "$SOSP" | grep .)
if [ -n "$SOSP" ]; then
  critico "Tarea programada SOSPECHOSA (descarga y ejecuta, o conexión remota):"
  echo "$SOSP" | sed 's/^/            >> /' >> "$REPORTE"
else
  bien "Ninguna tarea programada con patrones de backdoor"
fi

if existe systemctl && [ -z "$RAIZ" ]; then
  info ""
  info "Timers activos de systemd:"
  systemctl list-timers --all --no-pager 2>/dev/null | awk 'NR>1 && NF>2 {print "            "$(NF-1)" -> "$NF}' | grep -v '^\s*->' | head -40 >> "$REPORTE"
fi

# =====================================================================
titulo "7. SERVICIOS INSTALADOS A MANO"
# =====================================================================
info "Servicios que NO vienen de paquetes oficiales (revisa que todos sean tuyos):"
for f in "$RAIZ"/etc/systemd/system/*.service "$RAIZ"/lib/systemd/system/*.service "$RAIZ"/usr/lib/systemd/system/*.service; do
  [ -f "$f" ] || continue
  [ -L "$f" ] && continue
  de_paquete "${f#$RAIZ}" && continue
  ejec=$(grep -m1 '^ExecStart=' "$f" | cut -d= -f2- | corta)
  info "  - $(basename "$f")  ->  $ejec"
  if echo "$ejec" | grep -qE "/tmp/|/dev/shm|/var/tmp|$PATRON_MALO"; then
    critico "Servicio $(basename "$f") ejecuta algo desde carpeta temporal o con patrón de backdoor: $ejec"
  fi
done

# =====================================================================
titulo "8. PROCESOS SOSPECHOSOS"
# =====================================================================
if [ -z "$RAIZ" ]; then
  PROC_SOSP=""; PROC_MEM=""
  for d in /proc/[0-9]*; do
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    case "$exe" in
      /memfd:runc*|/memfd:runc_cloned*) continue ;;   # Docker lo hace normalmente
      /memfd:*) PROC_MEM="${PROC_MEM}pid ${d#/proc/}: $exe\n"; continue ;;
      /tmp/*|/dev/shm/*|/var/tmp/*|*"(deleted)"*)
        # ignorar actualizaciones normales (programa reemplazado tras apt upgrade)
        case "$exe" in /usr/*"(deleted)"|/lib/*"(deleted)") continue;; esac
        PROC_SOSP="${PROC_SOSP}pid ${d#/proc/}: $exe  ($(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | corta))\n" ;;
    esac
  done
  if [ -n "$PROC_SOSP" ]; then
    critico "Programas corriendo desde carpetas temporales o con el archivo borrado (típico de malware):"
    printf "$PROC_SOSP" | sed 's/^/            >> /' >> "$REPORTE"
  else
    bien "Ningún programa corriendo desde carpetas temporales"
  fi
  if [ -n "$PROC_MEM" ]; then
    aviso "Programas corriendo solo en memoria (sin archivo en disco). Algunos programas legítimos lo hacen, pero también el malware 'sin archivos'. Revisar nombre:"
    printf "$PROC_MEM" | sed 's/^/            >> /' >> "$REPORTE"
  fi

  MINERO=$(ps -eo pid,pcpu,comm --sort=-pcpu 2>/dev/null | grep -iE 'xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|\.x86_64|kthreaddi' | head -5)
  [ -n "$MINERO" ] && critico "Proceso con nombre de minero de criptomonedas: $MINERO"
  info ""
  info "Los 5 procesos que más CPU usan:"
  ps -eo pcpu,pmem,user,comm --sort=-pcpu 2>/dev/null | head -6 | sed 's/^/            /' >> "$REPORTE"
fi

EJEC_TMP=$(find "$RAIZ/tmp" "$RAIZ/var/tmp" "$RAIZ/dev/shm" -xdev -type f -perm -u+x 2>/dev/null | head -20)
OCULTOS=$(find "$RAIZ/tmp" "$RAIZ/var/tmp" "$RAIZ/dev/shm" -xdev -name '.*' ! -name '.X*-lock' ! -name '.ICE-unix' ! -name '.X11-unix' ! -name '.font-unix' ! -name '.XIM-unix' ! -name '.Test-unix' 2>/dev/null | head -20)
if [ -n "$EJEC_TMP" ] || [ -n "$OCULTOS" ]; then
  aviso "Archivos ejecutables u ocultos en carpetas temporales (revisa qué son):"
  printf "%s\n%s\n" "$EJEC_TMP" "$OCULTOS" | grep -v '^$' | sort -u | sed "s|^$RAIZ||; s/^/            /" >> "$REPORTE"
else
  bien "Carpetas temporales limpias"
fi

# =====================================================================
titulo "9. SEÑALES DE ROOTKIT Y PROGRAMAS DEL SISTEMA ALTERADOS"
# =====================================================================
if [ -s "$RAIZ/etc/ld.so.preload" ]; then
  critico "Existe /etc/ld.so.preload con contenido -> técnica clásica de rootkit: $(cat "$RAIZ/etc/ld.so.preload" | corta)"
else
  bien "No hay /etc/ld.so.preload (sin rootkit de biblioteca)"
fi

if existe dpkg && [ -z "$RAIZ" ]; then
  ALTER=""
  for pkg in openssh-server openssh-client coreutils procps util-linux login passwd sudo iproute2 net-tools findutils bash cron systemd libpam-modules; do
    dpkg -s "$pkg" >/dev/null 2>&1 || continue
    res=$(dpkg --verify "$pkg" 2>/dev/null | grep -E '^..5' | grep -v ' c /')
    [ -n "$res" ] && ALTER="${ALTER}${res}\n"
  done
  if [ -n "$ALTER" ]; then
    critico "Programas del sistema MODIFICADOS (no coinciden con el original de Ubuntu) -> posible rootkit:"
    printf "$ALTER" | sed 's/^/            >> /' >> "$REPORTE"
  else
    bien "Programas críticos del sistema (ssh, sudo, ps, ls, login, PAM...) intactos"
  fi
fi

info ""
info "Archivos con permiso SUID (se ejecutan como root) que NO son del sistema:"
SUID_RARO=""
while read -r f; do
  de_paquete "${f#$RAIZ}" && continue
  case "$f" in */snap/*) continue;; esac
  SUID_RARO="${SUID_RARO}${f#$RAIZ}\n"
done < <(find "$RAIZ/" -xdev \( -path "$RAIZ/proc" -o -path "$RAIZ/sys" -o -path "$RAIZ/var/lib/docker" -o -path "$RAIZ/var/lib/containerd" -o -path "$RAIZ/snap" \) -prune -o -type f -perm -4000 -print 2>/dev/null)
if [ -n "$SUID_RARO" ]; then
  critico "Archivos SUID desconocidos (dan poderes de root a quien los ejecute):"
  printf "$SUID_RARO" | sed 's/^/            >> /' >> "$REPORTE"
else
  bien "Ningún SUID fuera de los del sistema"
fi

# =====================================================================
titulo "10. WEBSHELLS Y ARCHIVOS PELIGROSOS EN LOS SITIOS WEB"
# =====================================================================
# Carpetas web: /var/www + las 'root' configuradas en nginx/apache
WEBDIRS="$RAIZ/var/www"
for r_ in $(grep -rhsE '^\s*(root|DocumentRoot)\s' "$RAIZ"/etc/nginx/ "$RAIZ"/etc/apache2/ 2>/dev/null | awk '{print $2}' | tr -d ';"' | sort -u); do
  [ -d "$RAIZ$r_" ] && WEBDIRS="$WEBDIRS $RAIZ$r_"
done
WEBDIRS=$(for d in $WEBDIRS; do [ -d "$d" ] && echo "$d"; done | sort -u)
info "Carpetas web revisadas:"
[ -z "$WEBDIRS" ] && info "            (no hay sitios web en este servidor)"
echo "$WEBDIRS" | grep . | sed "s|^$RAIZ||; s/^/            /" >> "$REPORTE"

if [ -n "$WEBDIRS" ]; then
  # Firmas de webshells conocidas (casi nunca aparecen en código normal)
  FIRMA_FUERTE='eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|hex2bin)\s*\(|eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|preg_replace\s*\(\s*["'"'"'].*/e["'"'"']|create_function\s*\(.*\$_(GET|POST|REQUEST)|FilesMan|c99shell|r57shell|b374k|WSO [0-9]|Uname:.*Php:|\$\{"\\x47LOBALS"\}|move_uploaded_file\s*\(\s*\$_FILES\[[^]]+\]\[.tmp_name.\]\s*,\s*\$_FILES'
  WS=$(grep -rlEI --include='*.php' --include='*.phtml' --include='*.php[0-9]' --include='*.inc' --include='*.phar' "$FIRMA_FUERTE" $WEBDIRS 2>/dev/null | grep -vE '/(vendor|node_modules)/' | head -30)
  if [ -n "$WS" ]; then
    critico "Posible WEBSHELL (puerta trasera web) en estos archivos:"
    for f in $WS; do
      info "  >> ${f#$RAIZ}  (modificado $(date -r "$f" '+%Y-%m-%d'))"
      grep -nEI "$FIRMA_FUERTE" "$f" | head -2 | corta | sed 's/^/                 linea /' >> "$REPORTE"
    done
  else
    bien "No se encontraron firmas de webshells conocidas"
  fi

  # Funciones peligrosas: legítimas a veces, pero conviene saber dónde están
  PELIG=$(grep -rlEI --include='*.php' '\b(shell_exec|passthru|proc_open|popen|system)\s*\(' $WEBDIRS 2>/dev/null | grep -vE '/(vendor|node_modules)/' | head -40)
  if [ -n "$PELIG" ]; then
    info ""
    info "Archivos PHP que ejecutan comandos del sistema (pueden ser normales, revisar que sean tuyos):"
    echo "$PELIG" | sed "s|^$RAIZ||; s/^/            - /" >> "$REPORTE"
  fi

  # PHP dentro de carpetas de subida de archivos (uploads)
  PHPUP=$(find $WEBDIRS -xdev -type d \( -iname 'upload*' -o -iname 'subida*' -o -iname 'archivos' -o -iname 'comprobantes' -o -iname 'images' -o -iname 'img' \) -print0 2>/dev/null \
          | xargs -0 -r -I{} find {} -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \) 2>/dev/null | head -20)
  if [ -n "$PHPUP" ]; then
    critico "Archivos PHP dentro de carpetas de subida/imágenes (ahí solo deberían haber fotos/PDF):"
    echo "$PHPUP" | sed "s|^$RAIZ||; s/^/            >> /" >> "$REPORTE"
  else
    bien "No hay PHP escondido en carpetas de subida"
  fi

  # Archivos que se pueden descargar desde internet y no deberían
  EXPUESTOS=$(find $WEBDIRS -xdev \( -name 'vendor' -o -name 'node_modules' \) -prune -o -type f \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' -o -name '*.bak_*' -o -name '*.old' -o -name '*.orig' -o -name '*.swp' -o -name '.env' -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.p12' -o -name '*.pem' -o -name '*.key' -o -name 'phpinfo.php' -o -name 'info.php' -o -name 'adminer*.php' \) -print 2>/dev/null | head -40)
  if [ -n "$EXPUESTOS" ]; then
    aviso "Archivos delicados dentro de carpetas web (respaldos, .env, certificados...). Si nginx no los bloquea, cualquiera los descarga:"
    echo "$EXPUESTOS" | sed "s|^$RAIZ||; s/^/            >> /" >> "$REPORTE"
  else
    bien "Sin respaldos/.env/certificados sueltos en las carpetas web"
  fi

  GITS=$(find $WEBDIRS -xdev -maxdepth 4 -type d -name .git 2>/dev/null | head -10)
  if [ -n "$GITS" ]; then
    if grep -rqsE 'location\s+[~^]*\s*/\\?\.(git|ht)|location\s+~\s+/\\\.' "$RAIZ"/etc/nginx/ 2>/dev/null; then
      info ""
      info "Hay carpetas .git en la web, pero nginx tiene una regla que bloquea archivos ocultos. Bien."
    else
      aviso "Carpeta(s) .git dentro de la web y nginx no parece bloquearlas -> se puede descargar TODO el código y contraseñas:"
      echo "$GITS" | sed "s|^$RAIZ||; s/^/            >> /" >> "$REPORTE"
    fi
  fi

  WW=$(find $WEBDIRS -xdev \( -name 'vendor' -o -name 'node_modules' \) -prune -o -type f -name '*.php' -perm -o+w -print 2>/dev/null | head -20)
  if [ -n "$WW" ]; then
    aviso "Archivos PHP que CUALQUIER usuario del sistema puede modificar (permiso 777/666):"
    echo "$WW" | sed "s|^$RAIZ||; s/^/            >> /" >> "$REPORTE"
  else
    bien "Ningún PHP con permiso de escritura para todos"
  fi

  RECIENTES=$(find $WEBDIRS -xdev \( -name 'vendor' -o -name 'node_modules' -o -name '.git' \) -prune -o -type f -name '*.php' -mtime -3 -print 2>/dev/null)
  NREC=$(echo "$RECIENTES" | grep -c .)
  info ""
  info "Archivos PHP modificados en los últimos 3 días: $NREC  (si no hiciste cambios y hay muchos, es mala señal)"
  echo "$RECIENTES" | head -25 | sed "s|^$RAIZ||; s/^/            - /" >> "$REPORTE"
fi

# =====================================================================
titulo "11. CONTRASEÑAS Y SECRETOS"
# =====================================================================
info "Archivos con secretos que otros usuarios del servidor pueden LEER:"
LEIBLES=""
for f in "$RAIZ"/etc/shadow "$RAIZ"/etc/gshadow "$RAIZ"/etc/restic/* "$RAIZ"/etc/erp_qf/* "$RAIZ"/root/.ssh/id_* \
         $(find "$RAIZ/var/www" -maxdepth 4 -type f \( -name '.env' -o -name 'db.php' -o -name 'config*.php' -o -name 'conexion*.php' \) 2>/dev/null); do
  [ -f "$f" ] || continue
  case "$f" in *.pub) continue;; esac
  if [ "$(stat -c %A "$f" | cut -c8)" = "r" ]; then
    LEIBLES="${LEIBLES}${f#$RAIZ}  ($(stat -c '%A %U' "$f"))\n"
  fi
done
if [ -n "$LEIBLES" ]; then
  aviso "Archivos con contraseñas legibles por cualquier usuario del servidor (deberían ser 600 o 640):"
  printf "$LEIBLES" | sed 's/^/            >> /' >> "$REPORTE"
else
  bien "Archivos de contraseñas protegidos"
fi

TOK=$(grep -rlsE '[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}' "$RAIZ"/usr/local/bin/ "$RAIZ"/etc/cron.d/ 2>/dev/null)
if [ -n "$TOK" ]; then
  aviso "Token de bot de Telegram escrito dentro de scripts (mejor en un archivo aparte con permiso 600):"
  for f in $TOK; do info "  >> ${f#$RAIZ}  ($(stat -c '%A' "$f"))"; done
fi

# =====================================================================
titulo "12. INICIOS DE SESION"
# =====================================================================
if [ -z "$RAIZ" ]; then
  info "Últimos 15 inicios de sesión (revisa que las IPs sean tuyas):"
  last -n 15 -a 2>/dev/null | grep -vE '^(wtmp|$)' | sed 's/^/            /' >> "$REPORTE"

  FALLOS=0
  if [ -r /var/log/auth.log ]; then
    FALLOS=$(grep -cE 'Failed password|Invalid user' /var/log/auth.log 2>/dev/null)
    ACEPT=$(grep -E 'Accepted (password|publickey)' /var/log/auth.log 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -10)
  elif existe journalctl; then
    FALLOS=$(journalctl -u ssh -u sshd --since "7 days ago" 2>/dev/null | grep -cE 'Failed password|Invalid user')
    ACEPT=$(journalctl -u ssh -u sshd --since "7 days ago" 2>/dev/null | grep -E 'Accepted' | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -10)
  fi
  info ""
  info "Intentos fallidos de entrar por SSH (log reciente): $FALLOS"
  [ "$FALLOS" -gt 500 ] && aviso "$FALLOS intentos de adivinar contraseña por SSH -> te están atacando (normal en internet, pero hay que cerrar contraseñas + fail2ban)"
  info ""
  info "IPs que SÍ entraron por SSH (cantidad de veces):"
  echo "${ACEPT:-            (ninguna en el log)}" | sed 's/^/            /' >> "$REPORTE"
fi

# =====================================================================
titulo "13. DOCKER"
# =====================================================================
if existe docker && [ -z "$RAIZ" ] && docker info >/dev/null 2>&1; then
  info "Contenedores corriendo:"
  docker ps --format '            {{.Names}}  |  {{.Image}}  |  {{.Ports}}' >> "$REPORTE" 2>/dev/null
  for c in $(docker ps -q 2>/dev/null); do
    nom=$(docker inspect -f '{{.Name}}' "$c" | tr -d /)
    [ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$c")" = "true" ] && aviso "Contenedor '$nom' corre en modo privilegiado (puede tomar control del servidor si lo hackean)"
    docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$c" | grep -q docker.sock && aviso "Contenedor '$nom' tiene acceso a docker.sock (equivale a ser root)"
    docker inspect -f '{{range $p,$b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}' "$c" \
      | tr ' ' '\n' | grep -E '^(0\.0\.0\.0|::|):' | while read -r hp; do
        info "  Contenedor '$nom' publica el puerto ${hp##*:} a TODO internet (Docker se salta el firewall)"
      done
  done
  bien "Docker revisado"
else
  info "Docker no está instalado o no corre aquí"
fi

# =====================================================================
titulo "14. OTROS ACCESOS REMOTOS INSTALADOS"
# =====================================================================
for s in cloudflared tailscaled zerotier-one wg-quick@wg0 headscale anydesk teamviewerd rustdesk; do
  if existe systemctl && [ -z "$RAIZ" ] && systemctl is-active --quiet "$s" 2>/dev/null; then
    info "Activo: $s  (asegúrate de que fuiste tú quien lo instaló)"
  fi
done
for b in anydesk teamviewer rustdesk ngrok frpc chisel; do
  if existe "$b" || [ -x "$RAIZ/usr/local/bin/$b" ]; then
    aviso "Programa de acceso remoto encontrado: $b  (si no lo instalaste tú, es una puerta trasera)"
  fi
done
bien "Revisión de accesos remotos terminada"

# =====================================================================
#  RESUMEN
# =====================================================================
{
  echo ""
  echo "=================================================="
  echo "  RESUMEN - $HOST"
  echo "=================================================="
  echo "  CRITICOS: $CRIT     AVISOS: $AVISO     OK: $OK"
  if [ "$CRIT" -gt 0 ]; then echo ""; echo "  CRITICOS (atender ya):"; printf "$RESUMEN_CRIT\n"; fi
  if [ "$AVISO" -gt 0 ]; then echo ""; echo "  AVISOS (mejorar):"; printf "$RESUMEN_AVISO\n"; fi
} > "$REPORTE.resumen"
cat "$REPORTE.resumen" >> "$REPORTE"

echo ""
cat "$REPORTE.resumen" | cut -c1-200
rm -f "$REPORTE.resumen"
chmod 600 "$REPORTE" 2>/dev/null
echo ""
echo "Reporte completo guardado en: $REPORTE"
echo "Para verlo:   sudo less $REPORTE      (salir con la tecla q)"
exit 0
