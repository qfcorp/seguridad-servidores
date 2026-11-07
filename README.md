# Auditoría de seguridad de servidores

Script que revisa un servidor Ubuntu buscando puertas traseras y configuraciones peligrosas.
**Solo lee — no cambia, no borra, no instala nada.**

## Cómo usarlo (copiar y pegar en el servidor)

```bash
curl -fsSL https://raw.githubusercontent.com/qfcorp/seguridad-servidores/main/auditoria_seguridad.sh -o /tmp/auditoria.sh && sudo bash /tmp/auditoria.sh
```

- Tarda de 1 a 5 minutos.
- Al final muestra un **RESUMEN** con CRÍTICOS (atender ya) y AVISOS (mejorar).
- El reporte completo queda en `/root/auditoria_<servidor>_<fecha>.txt` (solo root lo puede leer).

Para ver el reporte completo:
```bash
sudo ls /root/auditoria_*
sudo less /root/auditoria_NOMBRE_FECHA.txt
```
(salir con la tecla `q`)

## Qué revisa
1. Sistema y actualizaciones
2. Usuarios root ocultos, contraseñas vacías, sudo sin clave
3. SSH y llaves autorizadas
4. Puertos abiertos a internet (bases de datos expuestas)
5. Firewall y fail2ban
6. Tareas programadas (cron) con patrones de backdoor
7. Servicios instalados a mano
8. Procesos sospechosos (mineros, programas en /tmp)
9. Rootkits y programas del sistema alterados, archivos SUID
10. Webshells PHP, PHP en carpetas de subida, archivos expuestos (.git, .env, .sql)
11. Contraseñas y secretos mal protegidos
12. Inicios de sesión e intentos de ataque
13. Docker (contenedores privilegiados, puertos expuestos)
14. Programas de acceso remoto (AnyDesk, ngrok, etc.)

El plan y lo que falta está en [PLAN.md](PLAN.md).
