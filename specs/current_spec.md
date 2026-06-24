# 📋 Especificación de Desarrollo (SDD) — Sésamo Auditor

> **Estado**: ✅ COMPLETADA
> **Autor**: Antigravity
> **Fecha**: 2026-06-23
> **Subagente Implementador**: Antigravity
> **Aprobado por**: joao_moreira



---

## Instrucciones de Uso

Este archivo es la **única fuente de verdad** para la tarea en curso. Antes de implementar cualquier cambio:

1. **Llenar** las secciones de esta plantilla con los detalles de la tarea.
2. **Solicitar aprobación** del usuario antes de tocar código.
3. **Implementar** estrictamente lo que dice esta spec — nada más, nada menos.
4. **Archivar** al completar: mover a `specs/archive/{fecha}_{nombre_corto}.md`.

---

## 1. Resumen de la Tarea

<!-- ¿Qué se va a hacer? En 2-3 oraciones. -->

**Descripción**: —

**Motivación**: —

**Componentes afectados**: —

---

## 2. Contexto Técnico

<!-- ¿Qué necesita saber el implementador sobre el estado actual del código? -->

### Estado Actual
<!-- Descripción del comportamiento actual relevante -->

### Archivos Involucrados
<!-- Lista de archivos que se van a crear/modificar/eliminar -->

| Acción | Archivo | Descripción del Cambio |
|--------|---------|----------------------|
| MODIFICAR | `ruta/archivo.py` | — |
| CREAR | `ruta/nuevo.py` | — |
| ELIMINAR | `ruta/obsoleto.py` | — |

### Dependencias
<!-- ¿Se necesitan nuevas dependencias en requirements.txt? -->

---

## 3. Diseño Técnico

<!-- Detalles de implementación: clases, métodos, tipos, flujo de datos -->

### Cambios en Modelos (`core/modelos.py`)
<!-- Si aplica: nuevos campos, enums, dataclasses -->

### Cambios en Interfaces (`core/interfaces.py`)
<!-- Si aplica: nuevos métodos en BasePlugin -->

### Cambios en Engine (`core/engine.py`)
<!-- Si aplica: nuevas fases, hooks, lógica -->

### Nuevos Plugins
<!-- Si aplica: nombre, categoría OWASP, severidad, lógica de detección -->

### Cambios en Reportes
<!-- Si aplica: nuevos formatos, campos en el output -->

---

## 4. Criterios de Aceptación

<!-- ¿Cómo sabemos que la tarea está completa y correcta? -->

- [ ] Criterio 1: —
- [ ] Criterio 2: —
- [ ] Criterio 3: —

---

## 5. Plan de Testing

<!-- ¿Qué tests se van a crear/modificar? -->

| Test | Archivo | Qué Verifica |
|------|---------|-------------|
| — | `tests/test_*.py` | — |

```bash
# Comando para verificar
pytest tests/ -v -k "{filtro}"
```

---

## 6. Análisis de Impacto

<!-- ¿Qué podría romperse? ¿Qué otros componentes dependen de los archivos modificados? -->

### Riesgo Alto
<!-- Cambios que podrían romper el pipeline completo -->

### Riesgo Medio
<!-- Cambios que podrían afectar reportes o dashboard -->

### Riesgo Bajo
<!-- Cambios aislados sin dependencias downstream -->

---

## 7. Checklist Pre-Implementación

- [ ] Leí `.engram/ARCH_DECISIONS.md` para verificar decisiones previas relevantes.
- [ ] Leí `.engram/LESSONS_LEARNED.md` para evitar errores conocidos.
- [ ] Verifiqué que no hay otra spec activa en conflicto.
- [ ] El usuario aprobó esta spec.
- [ ] Identifiqué todos los archivos que necesitan cambios.

---

## 8. Notas del Implementador

<!-- Espacio para que el subagente documente decisiones de implementación -->

---

## 9. Post-Mortem (llenar al completar)

<!-- ¿Se cumplió la spec? ¿Hubo desvíos? ¿Qué se aprendió? -->

**Completado**: —
**Desvíos**: —
**Lecciones**: → Mover a `.engram/LESSONS_LEARNED.md`
