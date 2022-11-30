# X-Road federación Colombia

El siguiente procedimiento le permitirá configurar el código fuente X-Road versión Colombia para que sea posible realizar anclajes exitosos con otros ecosistemas X-Road, en el momento de realizar esta configuración se realizó para la version X-Road 6.25

A partir del manual de compilación para generar los binarios de instalación de X-Road.

```
05 Manual_Compilación X-Road_V1.0_05042022.docx
```

seguimos los pasos que se especifican en la guía hasta llegar al punto 3 "Obtener repositorio con código fuente de X-Road a compilar" página 12
en este punto y conforme al manual verificamos que la siguiente variable de entorno este activa  
```
XROAD_FOLDER=x-road-colombia-6.25
```

para confirmar se escribe en la terminal y debe retornar "x-road-colombia-6.25"
```
echo $XROAD_FOLDER
```

ejecutar el siguiente comando este realiza las modificaciones correspondientes en el código para posteriormente compilar conforme según el paso a paso de la guia
```
./insert.sh
```
