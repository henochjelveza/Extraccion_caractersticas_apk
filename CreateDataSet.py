#https://docs.python.org/es/3/tutorial/venv.html
##primero que todo crea el entorno virtual (ver comando abajo)
#python -m venv entorno
##luego se activa (ver comando abajo)
#entorno\Scripts\activate.bat


#https://intellipaat.com/community/31672/how-to-use-requirements-txt-to-install-all-dependencies-in-a-python-project
## después de activar el entorno se instalar solo una vez los paquetes
#pip install requirements.txt 

#IMPORTANTE debes instalar el AxmlParserPY manualmente
#trata con el comando sudo python -m pip install AxmlParserPY-master.zip
#si no te funciona revisa con el link a continuación
#http://skptr.me/reading_manifest.html

#para ejecutarlos
#python CreateDataSet.py

import axmlparserpy.apk as apk
import pandas as pd
import os

def createCSV(data, col):
    df = pd.DataFrame(data, columns = col)
    df.to_csv('dataSet_APKManifest.csv')

def readAPK(apk_name):
    return apk.APK(apk_name)

def managerManifest(apkname):
    #creo un diccionaro para almacenar los datos de cada apk
    dataApk={}
    ap=readAPK(apkname)
    #se extrae cada una de las propiedades que se necesitan
    sdk_m_version=ap.get_min_sdk_version()
    #aquí te pongo unos ejemplos, 
    # se me ocurre poner en el nombre "Malware" a los apk infectados. Ejemplo Malware_apk1.apk
    #con esto podemos clasificarlas rapidamente
    file_name=ap.get_filename()
    if file_name.find("VirusShare")>=0:
        dataApk["MALWARE"]=1
    else:
         dataApk["MALWARE"]=0

#--------------------------------------------------------------------------------------------

    #valida si la versión es mayor de la 18
    #creé otra variable que termina en _F (de Feature) que va a tener el valor 0 o 1 si es mayor de 18 
    #así puedes hacer con los otros
    #int convierte los caracteres a enteros para que puedas compararlo, solo funciona con numeros
    #1
    if int(sdk_m_version)>18:
        sdk_m_version_F=0
    else:
        sdk_m_version_F=1
    #se añade la caracteristica al diccionario creado de nombre dataApk
    dataApk["SDK_M_VERSION"]=sdk_m_version_F    
    #2
    sdk_t_version=ap.get_target_sdk_version()
    if int(sdk_t_version)>18:
        sdk_t_version_F=0
    else:
        sdk_t_version_F=1
    dataApk["SDK_T_VERSION"]=sdk_t_version_F
    

#---------------------------------------------------------------------------------------------------------
    #3
    # para los que retornan listas puedes hacer esto
    #se me ocurre buscar el main activity 
    activities=ap.get_activities()
    for a in activities:
       if a.find("MainActivity")>=0: 
           dataApk["MAIN_ACTIVITY"]=1

#----------------------------------------------------------------------------------------------------
    #4
    # para los que retornan listas puedes hacer esto
    #añadir los permisos 
    permissions=ap.get_permissions()
    for p in permissions:
        sp=p.split(".")
        sp_length=len(sp)
        permission=sp[sp_length-1]
        #añado cada permiso a las columnas
        dataApk[permission]=1 

#---------------------------------------------------------------------------------------------------
  #5
    # para los que retornan listas puedes hacer esto
    #se me ocurre buscar el receivers
    receivers=ap.get_receivers()
    for a in receivers:
       if a.find("MyBroadCastReceiver")>=0: 
           dataApk["MyBroadCastReceiver"]=1

#----------------------------------------------------------------------------------------------------
    #6
    # para los que retornan listas puedes hacer esto
    #añadir las librerías, esto nos podría dar indicio si usan apks basadas en Http son muy inseguras 
    libraries=ap.get_libraries()
    for l in libraries:
        dataApk[l.upper()]=1
    
    #retorna el diccionario con todos los datos del apk
    return dataApk  
def ceros(index):
    arr=[]
    for i in range(index):
        arr.append(0)
    return arr
#inicio del código
if __name__ == "__main__":
    #directorio que contiene todas la apk
    dir='APK'
    #declaración de lista que contendrá las columnas del csv
    columns=[]
    #declaración de dicconario que contendrá los valores del csv
    data={}
    #obtenemos la lista de archivos
    content=os.listdir(dir)
    index=0
    for apkFile in content:
        # se envía cada apk a procesarse y retorna el diccionario con lo datos procesados
        raw_data_apk=managerManifest(dir+"/"+apkFile)
        for i in raw_data_apk.items():
            column=i[0]
            value=i[1]
            #verifica si esta columna ya existe
            if not column in columns:
                columns.append(column)
                #completa con ceros
                data[column]=ceros(index)
            data[column].append(value)
            #finalmente despues de reconstruir los datos se crea el csv
        #incrementa el indice
        index=index+1    
    #completa con ceros las columnas incompletas
    for d in data.values():
        if len(d)<index:
            d.extend(ceros(index-len(d)))
    createCSV(data,columns)

