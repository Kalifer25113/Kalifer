# 			THE VISIONER	
# NOMBRE: *Fernando Salas Carrion*
# GITHUB: *https://github.com/Kalifer25113
# EMAIL:  *kalifer25113@protonmail.com*
# Descripcion: Tool escrita en Powershell scripting para analisis forense y
# informacion varia de sistemas Windows haciendo uso de
# comandos útiles de cmd y powershell para threat hunting
# y detección de software no deseado.
# Version: 1.0 (castellano)
Function Get-Menu
{
	write-host " ///////////// /        /  //////////    \                /    //////////   //////////   ///////////   |---------|   |\        |   //////////   |----------"
	write-Host "       /       /        /  /              \              /          |       /                 |        |         |   | \       |   /            |         |"
	write-Host "      /        /        /  /               \            /           |       /                 |        |         |   |  \      |   /            |         |"
	write-Host "     /         /        /  /                \          /            |       /                 |        |         |   |   \     |   /            |         |"
	write-Host "    /          //////////  //////////        \        /             |       //////////        |        |         |   |    \    |   //////////   |---------|"
	write-Host "   /           /        /  /                  \      /              |                /        |        |         |   |     \   |   /            |  \       "
	write-Host "  /            /        /  /                   \    /               |                /        |        |         |   |      \  |   /            |   \      "
	write-Host " /             /        /  /                    \  /                |                /        |        |         |   |       \ |   /            |    \     "
	write-host "/              /        /  //////////            \/             //////////  //////////   ///////////   |---------|   |        \|   //////////   |     \    "
	
	
    write-host "1. Verificar la firma de los archivos"
    write-host "2. Escanear la veracidad de los archivos del sistema"
    write-host "3. Sysinternal suite"
    write-host "4. Detectar Man in the middle ARP Spoofing"
	write-host "5. Ver conexiones  del PC y el proceso o archivo asociado."
	write-host "6. Ver la politica de seguridad establecida."
	write-host "7. Ver sesiones abiertas actualmente."
	write-host "8. Ver Usuarios activos en el sistema."
	write-host "9. Ver Informacion de puertos."
	write-host "10.Ver recursos compartidos."
	write-host "11.Ver actividad de red del equipo."
	write-host "12.Encontrar archivos ocultos en la carpeta actual."
	write-host "13.Encontrar todos los archivos y procesos ocultos del sistema."
	write-host "14.Asignar ip estatica al equipo actual."
	write-host "15.Ver procesos en ejecucion."
	
    write-host "16.Salir"
	write-host "													Autor:Kalifer25113"
	write-host "													Version: 1.0	  "
}
Function VerificarFirma
{
	write-host "Esta opcion verificara la firma de los principales archivos del sistema Microsoft."
	write-host "En caso de encontrar un archivo inusual descargara y reemplazara con el correcto."
	cmd /c sigverif
}
Function EscanearVeracidad
{
	write-host "Opcion similar a la primera, que verifica la integridad de los archivos del sistema."
	cmd /c sfc /scannow
}
Function SysInternals
{
	 write-host "SysInternalSuite es una suite de herramientas muy utiles para analisis forense y busqueda de"
	 write-host "software no deseado en Sistemas Microsoft. El enlace de descarga es el siguiente: https://download.sysinternals.com/files/SysinternalsSuite.zip"
}
Function ArpSpoofDetect
{
	write-host "Observar la siguiente salida, y si dos equipos con distintas IP privadas tienen asociada una misma dirección MAC,"
    write-host "es un indicio mas que claro de que un equipo esta suplantando a otro con su dirección MAC."
	cmd /c arp -a	
}
Function Connections
{
	write-host "Con esta opcion que usa un comando avanzado de Powershell se podra ver las conexiones entrantes y salientes del equipo, "
    write-host "asi como el servicio o el ejecutable asociado"
	netstat -a -b -f -q
}
Function SecurityPolicy
{
	write-host "Con esta opcion se podra ver la politica de seguridad establecida en el sistema."
	Get-ExecutionPolicy
}
Function SessionsOpened
{
	write-host "Opcion oara ver las sesiones actuales en el equipo."
	net sessions /LIST
}
Function ActiveUsers
{
	write-host "Ver usuarios activos en el sistema."
	net user
}
Function PortInfo
{
	write-host "Ver informacion de los puertos."
	Get-NetTCPConnection
}
Function NetShareInfo
{
	write-host "Ver recursos compartidos por el dispositivo."
	net share
}
Function NetViewInfo
{
	write-host "opcion para ver actividad de red del sistema."
	net view \\127.0.0.1
}
Function HiddenFiles 
{
	write-host "Opcion para encontrar archivos y carpetas ocultos en el directorio en el cual se este ejecutando este programa."
	dir /S /A:H
}
Function HiddenFilesAll
{
	write-host "Esta opcion mas avanzada mostrara todos los archivos y carpetas ocultos de todo el sistema."
	Get-ChildItem -force
}
Function StaticIP 
{
    Get-Adaptador
    Remove-Adaptador
    #Creamos la nueva IP
    $ip = Read-Host "Introduzca IP"
    $mascara =  Read-Host "Introduzca mascara de subred"
    $gateway = Read-Host "Introduzca la puerta de enlace"
    $dns1 = Read-Host "Introduzca el servidor DNS primario"
    $dns2 = Read-Host "Introduzca el servidor DNS secundario"
    New-NetIPAddress -InterfaceIndex $interfaz $ip -PrefixLength $mascara
    -DefaultGateway $gateway Set-DnsClientServerAddress -InterfaceIndex
    #$interfaz -ResetServerAddresses 
    #Restablecer la interfaz
    Restart-NetAdapter -Name $nombre
}
Function  GetProcess
{
	write-host "Muestra informacion de procesos en ejecucion en el sistema."
	get-process
}
#Inicio
# get-process 
do 
{
    Get-Menu
    $opcion = Read-Host "Seleccione una opcion"
    switch ($opcion)
    {
        '1'{VerificarFirma}
        '2'{EscanearVeracidad}
        '3'{SysInternals}
		'4'{ArpSpoofDetect}
		'5'{Connections}
		'6'{SecurityPolicy}
		'7'{SessionsOpened}
		'8'{ActiveUsers}
		'9'{PortInfo}
		'10'{NetShareInfo}
		'11'{NetViewInfo}
		'12'{HiddenFiles}
		'13'{HiddenFilesAll}
		'14'{StaticIP}
		'15'{GetProcess}
        '16'{exit}
        Default {Write-Host "Opcion incorrecta"}
    }
    $intro = Read-Host "Pulse intro para continuar"
}while ($true)