# System Analyzer for Processes and Open resources (SAPO)

`sapo` es una herramienta de línea de comandos diseñada para sistemas Linux que permite inspeccionar el estado del sistema, listar conexiones de red activas, auditar procesos y enviar señales, interactuando directamente con el sistema de archivos virtual `/proc`.

## Requisitos Previos

Este programa está diseñado exclusivamente para sistemas operativos **Linux**, ya que depende del directorio `/proc`.

Para la compilación se requiere:
* Un compilador de C (como `gcc`).
* Un Makefile (`make`).

---

## Compilación y Gestión

El proyecto incluye un `Makefile` para automatizar y simplificar el proceso de compilación de todos los módulos. Abre una terminal en la raíz del proyecto y utiliza cualquiera de los siguientes comandos:

* **Compilar el proyecto:** Genera el ejecutable final `sapo` de forma automática detectando todos los archivos fuente `.c`.
    ```bash
    make
    ```
* **Limpiar el repositorio:** Borra los archivos objeto `.o` intermedios y el ejecutable para dejar la carpeta limpia.
    ```bash
    make clean
    ```

---

## Modos de Ejecución

Para obtener información de cómo usar `sapo`, puede ayudarse de las flags -h o --help:
   ```bash
   ./sapo -h
   ./sapo --help
   ```

Comando que mostrará una descripción básica de qué subcomandos posee `sapo`