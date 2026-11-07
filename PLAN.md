# Bloc de notas — Seguridad de servidores QF

Última actualización: 2026-11-07

## Objetivo
Revisar los 4 equipos (VPS ERP, VPS Tukán, VPS Correos, laptop qfcorp), encontrar puertas traseras o configuraciones peligrosas y cerrarlas.

## Fase 1 — Herramienta de auditoría ✅ HECHO (7 nov 2026)
- [x] `auditoria_seguridad.sh`: solo lee, no cambia nada. Revisa 14 áreas:
  usuarios root ocultos, contraseñas vacías, sudo sin clave, SSH, llaves autorizadas,
  puertos abiertos, firewall, fail2ban, cron/timers, servicios, procesos raros,
  rootkits, SUID, webshells PHP, archivos expuestos en la web, secretos, logins, Docker,
  programas de acceso remoto.
- [x] Probado en entorno simulado:
  - Sistema limpio → 0 críticos (se corrigieron 2 falsos positivos: `/bin` vs `/usr/bin` y programas en memoria de Docker).
  - Se plantaron 11 puertas traseras falsas → detectó las 11.
  - Sin sudo → avisa y sale sin romper nada.
  - Si falta el comando `ss` → usa plan B (lee /proc/net/tcp).

## Fase 2 — Correr la auditoría en cada servidor ⏳ PENDIENTE
| Servidor | Corrida | Críticos | Avisos |
|---|---|---|---|
| VPS ERP | ☐ | | |
| VPS Tukán | ☐ | | |
| VPS Correos | ☐ | | |
| Laptop qfcorp | ☐ | | |

## Fase 3 — Arreglos (según resultados) ⏳ PENDIENTE
Pendientes conocidos de antes (el detalle está en las notas del chat, no aquí, porque el repo es público):
- [ ] Rotar el token del bot de alertas y guardarlo en un archivo con permiso 600.
- [ ] Revisar y quitar llaves SSH antiguas que ya no se usan.
- [ ] Completar las actualizaciones del sistema pendientes.
- [ ] Mover credenciales del código a variables de entorno.

Arreglos típicos que probablemente salgan:
- [ ] SSH solo con llaves (sin contraseñas) y sin entrar directo como root.
- [ ] fail2ban en los 4 equipos.
- [ ] Firewall (UFW) + cerrar puertos de Docker publicados a todo internet.
- [ ] Bases de datos (PostgreSQL/MySQL) escuchando solo en 127.0.0.1.
- [ ] Actualizaciones automáticas de seguridad.
- [ ] Bloquear en nginx archivos `.git`, `.env`, `.sql`, `.bak`.

## Fase 4 — Vigilancia automática ⏳ PENDIENTE
- [ ] Correr la auditoría cada semana y mandar el resumen al bot de Telegram (qfserver).
- [ ] Avisar por Telegram si aparece un usuario nuevo, una llave SSH nueva o un PHP nuevo.

## Registro de cambios
- 2026-11-07: v1.0 del script creada y probada.
