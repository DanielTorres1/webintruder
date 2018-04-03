
# Web Intruder

Web Intruder tiene funcionalidad similar del módulo **Intruder** de BurpSuite.  Automatiza ataques personalizados contra aplicaciones web.  Por el momento tiene 3 funcionalidades agregadas:

- Busca generar algun tipo de error en la aplicación usando cada uno de los parametros GET/POST
- Realiza pruebas SQLi en cada uno de los parametros GET/POST
- Realiza pruebas de sesiones (cookies)


## ¿COMO INSTALAR?

Testeado en Kali 2:

    git clone https://github.com/DanielTorres1/webintruder
    cd webintruder
    bash instalar.sh


## ¿COMO USAR?

### **webintruder.pl**

Para usar cualquiera de las funcionalidades de este script primero necesitamos guardar las peticiones POST/GET interceptadas por BurpSuite en un archivo xml (Guardar al menos 2 peticiones):
![enter image description here](https://i.imgur.com/4o0TkIf.png)

Opciones: 

    -f: Archivo XML exportado de BurpSuite
    -t: tipo. Puede ser:
        session: Prueba las cookies
        sqli: Prueba injecciones SQL
        error: Busca generar un error

Ejemplo 1 Probar la aplicacion enviando peticiones sin cookies:

    webintruder.pl -f file.xml -t session  -c nocookie


Ejemplo 2 Probar la aplicacion enviando peticiones con la cookie valor de 0:

    webintruder.pl -f file.xml -t session  -c "PHPSESSION=0"


Ejemplo 3 Probar la aplicacion probando inyecciones SQL:

    webintruder.pl -f file.xml -t sqli

 

Ejemplo 4 Probar la aplicacion buscando generar errores:

    webintruder.pl -f file.xml -t sqli 

