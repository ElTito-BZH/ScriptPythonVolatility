#!/usr/bin/python3
# -*- coding: utf-8 -*-

##AJOUTER SA CLE API VIRUSTOTAL DANS LA VARIABLE PARAMETRE_VIRUSTOTAL AVANT EXECUTION DU SCRIPT
import os
import subprocess
import sys
import re
import operator
import requests
import ntpath

chemin_volatility = "/usr/bin/volatility"
liste_ports_standards= [135,137,138,139,445,1900,5355]

#Seulement 4 requêtes par minute
url_virustotal_scan_fichier='https://www.virustotal.com/vtapi/v2/file/scan'
url_virustotal_adresse_ip = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
parametre_virustotal={'apikey':'INSERERCLEAPIICI'}

#Points à améliorer :
    # Amélioration de la regex r"\S+ \s+ \S+ \s  (?:0\.0\.0\.0|::):(\d{1,5})" pour prendre en compte les adresses IPv4 standards
    # Dumper les programmes détectés comme étant suspects par l'analyse réseau
    # Afficher des informations sur les adresses IP auxquels se connectent les programmes suspects

#Améliorer affichage du script (mettre des couleurs ?)

#Fonctions à ajouter :
    # Vérification de la possibilité de lancer un scan Virustotal (seulement 4 par minute)
	
def comparer_heure_demarrage_processus (heure_demarrage_fils,heure_demarrage_parent) :

    heure_fils = heure_demarrage_fils[:2]
    heure_pere = heure_demarrage_parent[:2]
    if heure_fils > heure_pere :
      return False
    elif heure_pere > heure_fils :
      return True
    else :
      minute_fils = heure_demarrage_fils[3:5]
      minute_pere = heure_demarrage_parent[3:5]
      if minute_fils > minute_pere :
        return False
      elif minute_pere > minute_fils :
        return True
      else : 
        seconde_fils = heure_demarrage_fils[6:8]
        seconde_pere = heure_demarrage_parent[6:8]
        if seconde_fils > seconde_pere :
          return False
        else :
          return True
	
def formatage_resultat_regex (chaine_a_formater):
    chaine_a_formater = str(chaine_a_formater)
    chaine_a_formater = chaine_a_formater.replace("[", "")
    chaine_a_formater = chaine_a_formater.replace("'", "")
    chaine_a_formater = chaine_a_formater.replace("]", "")
    chaine_a_formater = chaine_a_formater.replace('"', '')

    return chaine_a_formater


def determination_profil (resultat_image_info) :
    liste_profils = re.findall(r'Profile suggestion \(KDBGHeader\): (.+)', resultat_image_info)
    occurrence_profils = {}

    for profil in liste_profils:
        profil_raccourci = re.sub(r'_.+', '', profil)

        if occurrence_profils.get(profil_raccourci, "None") == "None":
            occurrence_profils[profil_raccourci] = 1
        else:
            occurrence_profils[profil_raccourci] = occurrence_profils[profil_raccourci] + 1

    profil_utilise = max(occurrence_profils.items(), key=operator.itemgetter(1))[0]
    print ("Le profil %s sera utilisé pour l'analyse" %profil_utilise)
    return profil_utilise

def analyse_programme_psxview (liste_programme_suspects_psxview) :
    dictionnaire_programme_suspect = {}
    for ligne in liste_programme_suspects_psxview:
        nom_programme_suspect = re.findall(r'(.+.exe|bin)', ligne)
        nom_programme_suspect = formatage_resultat_regex(nom_programme_suspect)

        pid_programme_suspect = re.findall(r'\s(\d{1,4})', ligne)
        pid_programme_suspect = formatage_resultat_regex(pid_programme_suspect)
        dictionnaire_programme_suspect[nom_programme_suspect] = pid_programme_suspect
    return dictionnaire_programme_suspect

def analyse_reseau_linux (dump_memoire,profil_utilise) :

  resultat_recherche_promiscous_mode = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_ifconfig")
  recherche_mode_prosmicous = re.findall(r'(\S+)\s+\S+\s+(?:[0-9a-f]{2}[:-]){5}(?:[0-9a-f]{2})  True',resultat_recherche_promiscous_mode)
  if (len(recherche_mode_prosmicous) == 0) :
    print("Le mode promiscous n'est activé sur aucune interface")
  else :
    print ("Le mode promiscous est activés sur les %d interfaces suivantes : " % (len(recherche_mode_prosmicous)))
    for interface in recherche_mode_prosmicous :
      print (interface)
  
  resultat_netstat = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_netstat")
  recherche_ecoute = re.findall(r'(TCP|UDP)\s+\S+\s+:\s+(\d{1,5})\s+\S+\s+:\s+\S+\s+LISTEN\s+(\S+)',resultat_netstat)
  if (len(recherche_ecoute) == 0) :
    print("Cette machine n'écoutait sur aucun port")
  else :
    print ("Cette machine écoutait sur les %d ports suivants : " % (len(recherche_ecoute)))
    for protocole,port,processus in recherche_ecoute :
      print ("Le processus %s écoutait sur le port %s %s" % (processus,port,protocole))


def analyse_rootkit_linux (dump_memoire,profil_utilise) :

  resultat_recherche_rootkit = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_check_afinfo")
  if (len(resultat_recherche_rootkit.split('\n'))) <= 3 :
    print("Aucune rootkit n'a été détecté")
  else: 
    print ("Voici la liste des rootkit détectés : \n")
    print (resultat_recherche_rootkit)
	
  recherche_rootkit_root = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_check_creds")	
  if (len(recherche_rootkit_root.split('\n'))) <= 3 :
    print("Aucune rootkit ayant les privilèges root n'a été détecté")
  else: 
    print ("Voici la liste des rootkit ayant les privilèges root détectés : \n")
    print (recherche_rootkit_root)  

  resultat_recherche_rootkit_idt = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_check_idt")
  recherche_rootkit_idt = re.findall(r'0x[a-f0-9]+ (0x[a-f0-9]+) HOOKED',resultat_recherche_rootkit_idt)	
  if (len(recherche_rootkit_idt) == 0) :
    print("Aucune entrée IDT correspond à un rootkit")
  else :
    print ("%d entrées IDT correspodnants à des rootkits ont été détectées, et ont les adresses suivantes : " % (len(recherche_rootkit_idt)))
    for adresse in recherche_rootkit_idt :
      print (adresse)


  resultat_recherche_verification_appel_systeme = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_check_syscall")
  recherche_appel_systeme_hooked = re.findall(r'(?:32|64)bit\s+\d+\s+(0x[0-9a-f]+) HOOKED',resultat_recherche_verification_appel_systeme)
  if (len(recherche_appel_systeme_hooked) == 0) :
    print("Aucun appel système n'a été hooked ")
  else :
    print ("%d appel systèmes hooked ont été détectés aux adresses suivantes : " % (len(recherche_appel_systeme_hooked)))
    for adresse in recherche_appel_systeme_hooked :
      print (adresse)
	  
  resultat_recherche_rootkit_check_creds = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_check_creds")
  if (len(resultat_recherche_rootkit_check_creds.split('\n'))) <= 3 :
    print("Aucune rootkit n'a été détecté avec la méthode check_creds")
  else: 
    print ("Voici la liste des rootkit détectés avec la méthode check_creds : \n")
    print (resultat_recherche_rootkit_check_creds)  

def dump_processus_suspect_et_scan_virustotal (dump_memoire,profil_utilise,pid) :

    dump_exe_programme_suspect     = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " procdump " + " -p " + pid + " --dump-dir=.")
    dump_memoire_programme_suspect = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " memdump " + " -p " + pid + " --dump-dir=.")
    
    resultat_dump = str(re.findall(r"\S+ \S+ \s+(OK|Error): .+", dump_exe_programme_suspect))
    resultat_dump = formatage_resultat_regex(resultat_dump)
    if resultat_dump == "OK" :

      executable_a_scanner_virustotal= {'file': (('executable.%d.exe'%int(pid)), open(('executable.%d.exe' %int(pid)), 'rb'))}
      scan_virustotal= requests.post(url_virustotal_scan_fichier, files=executable_a_scanner_virustotal, params=parametre_virustotal)
      lien_virustotal=str(re.findall(r"'permalink': '(https://.+/)",str(scan_virustotal.json())))
      lien_virustotal=formatage_resultat_regex(lien_virustotal)
      print ("Le résultat du scan VirusTotal pour le programme ayant le pid %d est disponible sur le lien suivant : %s" % (int(pid),lien_virustotal))
    else:
      print ("Le dump du programme suspect a échoué :(")

def analyse_dump_linux (dump_memoire,profil_utilise) :

  
  resultat_recherche_module_suspect = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_hidden_modules")
  if (len(resultat_recherche_module_suspect.split('\n'))) <= 3 :
    print("Aucune module kernel suspect n'a été détecté")
  else: 
    print ("Voici la liste des modules kernels cachés, qui seront dumpés dans le dossier courant : \n")
    print (resultat_recherche_module_suspect)
    liste_adresse_module_suspect = re.findall(r'(0x[0-9a-f]+)\s+(\S+)',resultat_recherche_module_suspect)
    for adresse_module_suspect,nom_module_suspect in liste_adresse_module_suspect :
      resultat_dump_module_suspect = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_moddump -D . -b " + adresse_module_suspect)
      if ("ERROR   : volatility.debug    :" in resultat_dump_module_suspect) :
        print ("Erreur lors de la génération du dump du module %s" % nom_module_suspect)

  resultat_pstree = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_pstree")
  recherche_execution_bash = re.findall(r'\.*bash(?:]|\s)\s+\d{1,7}',resultat_pstree)
  
  if (len(recherche_execution_bash)) == 0 :
    print ("Aucun shell n'a été exécuté lors de la création de ce dump mémoire")
  else: 
    print ("%d processus correspondant à un shell étaient en cours d'exécution lors de la création de ce dump mémoire. Ils vont maintenant être analysées" % (len(recherche_execution_bash)))
	
    lignes_resultat_pstree = resultat_pstree.split("\n")
    lignes_resultat_pstree = lignes_resultat_pstree[2:]

	#Cette boucle permet de trouver le numéro de la ligne actuelle
    for ligne in recherche_execution_bash :	   
      ligne_comparaison = ligne.replace(" ","")	  
      i = 0
	  
      for ligne_pstree in lignes_resultat_pstree :
        ligne_pstree = ligne_pstree.replace(" ","")
        if ligne_pstree == ligne_comparaison :
          numero_ligne_actuelle = i
          break
        i = i + 1
		
      niveau_parente = ligne.count(".")	  
      lignes_rechercher_processus_parent = lignes_resultat_pstree[:numero_ligne_actuelle]
      lignes_rechercher_processus_parent.reverse()
	  
      for ligne_processus in lignes_rechercher_processus_parent :
        niveau_parente_processus = ligne_processus.count(".")
        if (niveau_parente_processus == (niveau_parente -1)) :
          print("Le processus ayant lancé ce shell est :") 
          print (ligne_processus)	
          break

      print("Voici la liste des commandes bash exécutéees lors de la création de ce dump mémoire :\n") 
      resultat_recherche_memoire_bash = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_bash")
      print (resultat_recherche_memoire_bash)		  
		  
  
  print("Voici la liste des filesystem tmpfs. Si vous souhaitez en extraire un, vous pouvez le faire via la commande suivante")
  print(chemin_volatility + dump_memoire + profil_utilise + " linux_tmpfs -S numero_filesystem -D DossierExtraction")
  resultat_recherche_filesystem_tmpfs = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_tmpfs -L \n") 
  print (resultat_recherche_filesystem_tmpfs)
  
  analyse_rootkit_linux (dump_memoire,profil_utilise)


  resultat_recherche_keylogger = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_check_tty")
  recherche_keylogger = re.findall(r'(tty\S+)\s+0x\S+ .*HOOKED.*',resultat_recherche_keylogger)
#  recherche_keylogger = re.findall(r'(tty\S+)\s+0x\S+ .*n_tty_receive_buf.*',resultat_recherche_keylogger)
  if (len(recherche_keylogger) == 0) :
    print("Aucun keylogger n'a été détecté")
  else :
    print ("%d keyloggers ont été détectées aux TTY suivants : " % (len(recherche_keylogger)))
    for tty in recherche_keylogger :
      print (tty)
	  
  analyse_reseau_linux (dump_memoire,profil_utilise)
  
  affichage_kernel_debug = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_dmesg")
  print ("Le contenu des infos debug du noyau va être écrit dans le nouveau fichier kernel_info_dump_memoire.txt du dossier courant")
  try :
    fichier_kernel_debug = open("kernel_info_dump_memoire.txt","w")
    fichier_kernel_debug.write(affichage_kernel_debug)
    fichier_kernel_debug.close()
  except :
    print("Erreur d'écriture dans le fichier kernel_info_dump_memoire.txt. Le contenu des infos debug va donc être affiché à l'écran :")
    print (affichage_kernel_debug)
  
  
  resultat_enumerate_files = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_enumerate_files ")
  recherche_fichier_flag = re.findall(r'(0x[a-f0-9]+)\s+\d+\s+(?!/sys)(\S+flag\S+)',resultat_enumerate_files)  
  if (len(recherche_fichier_flag)) == 0 :
    print ("Aucun des fichiers de la machine distante ne semble ressembler à un fichier flag de CTF")
  else :
    print ("%d des fichiers de la machine semble correspondre à un fichier flag de CTF. Ils vont maintenant être dumpés dans le dossier courant" % len(recherche_fichier_flag))
    i = 1
    for adresse_flag,nom_fichier_flag in recherche_fichier_flag :
      resultat_dump_flag = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_find_file -i " + adresse_flag + " -O fichier" + str(i))
      if ("ERROR   : volatility.debug    :" in resultat_dump_flag) :
        print ("Le dump du fichier %s a échoué" % nom_fichier_flag)
      else:
        print ("Le fichier %s a été correctement dumpé, et peut être récupéré via le nom fichier%d" % (nom_fichier_flag, i))
      i = i + 1

def check_system_root_process (dump_memoire,profil_utilise,pid,nom_processus) :

    resultat_cmdline = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " cmdline --pid=" + pid)
			
    recherche_dossier_lancement = re.findall(r'Command line : C:\\WINDOWS\\system32\\' + nom_processus,resultat_cmdline)
    if len(recherche_dossier_lancement) == 1 :
      print ("%s est bien lancé depuis le dossier C:\WINDOWS\system32, ce qui correspond à un fonctionnement normal de Windows" % nom_processus)
    elif len(recherche_dossier_lancement) ==  0 :
      print ("Erreur lors de la vérification du dossier depuis lequel %s a été lancé" % nom_processus)
    else:
      recherche_mauvais_dossier_lancement = re.findall(r'Command line :\s+(\S+)',resultat_cmdline)	  
      print ("%s a été lancé depuis %s, au lieu de C:\WINDOWS\system32. Ce processus va donc être dumpé et analysé par Virustotal" % (nom_processus, recherche_mauvais_dossier_lancement[0]))
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid)


def check_if_parent_process_is_winlogon (dump_memoire,profil_utilise,pid,ppid,resultat_pstree,nom_processus) :


    recherche_nom_processus_parent = re.findall(r'0x[a-f0-9]+\s+(\S+)\s+' + ppid,resultat_pstree)
    nom_processus_parent = recherche_nom_processus_parent[0]
		
    if ( nom_processus_parent != "winlogon.exe" and "XP" in profil_utilise) and (nom_processus_parent == "wininit.exe" and "XP" not in profil_utilise) :
      print ("%s a un processus parent différent de winlogon.exe (et de wininit.exe). Ces 2 processus ainsi que le contenu de leur mémoire vont donc être dumpés et envoyés à VirusTotal" % nom_processus)
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid)
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,ppid)
    else:
      print ("Le processus parent de %s est le processus winlogon.exe (ou wininit.exe), ce qui correspond au fonctionnement normal de Windows" % nom_processus)

def analyse_processus_lsass_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pstree) :

    recherche_nombre_occurences_processus_lsass = re.findall(r'0x[0-9a-f]+\s+(lsass.exe)',resultat_psxview)
	
    if len(recherche_nombre_occurences_processus_lsass) == 1 :
      print("Il y a qu'un seul processus lsass.exe détecté dans ce dump, ce qui correspond à un fonctionnement normal de Windows")
	  
	  #Vérifie que le processus parent est bien winlogon.exe
      recherche_pid_ppid_lsass = re.findall(r'0x[a-f0-9]+\s+lsass\.exe\s+(\d+)\s+(\d+)',resultat_pstree)
      pid_lsass = recherche_pid_ppid_lsass[0][0]
      ppid_lsass = recherche_pid_ppid_lsass[0][1]
      check_if_parent_process_is_winlogon (dump_memoire,profil_utilise,pid_lsass,ppid_lsass,resultat_pstree,"lsass.exe")
      
      #Vérifie que le processus lsass.exe a bien été lancé depuis C:\WINDOWS\system32\lsass.exe
      check_system_root_process (dump_memoire,profil_utilise,pid_lsass,"lsass.exe")

	  #Vérifie que lsass.exe n'a pas de processus fils
      recherche_processus_fils_de_lsass = re.findall(r'0x[a-f0-9]+\s(\S+)\s+(\S+)\s+' + pid_lsass,resultat_pstree)
	  
      if len(recherche_processus_fils_de_lsass) == 0 :
        print ("Lsass.exe n'a aucun processus fils, ce qui correspond à un fonctionnement normal de Windows")
      else:
        print ("lsass.exe a %d processus fils, au lieu de 0 normalement. Voici la liste de ces processus, qui seront dumpés et analysés par Virustotal" % len(recherche_processus_fils_de_lsass))
        for nom_fils_lsass,pid_fils_lsass in recherche_processus_fils_de_lsass :
          print (nom_fils_lsass)
          dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_fils_lsass)
	    
    else :
      print(" %d processus lsass.exe différents ont été découverts, alors que seul 1 processus lsass.exe devrait être ouvert. Voici la liste des PID correspondants (les processus en questions seront dumpés et envoyés à Virustotal) :" % len(recherche_nombre_occurences_processus_lsass) )
      for pid in recherche_nombre_occurences_processus_lsass :
        dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid)
        print (pid)


def analyse_processus_services_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pstree) :

    recherche_nombre_occurences_processus_services = re.findall(r'0x[0-9a-f]+\s+(services.exe)',resultat_psxview)
		
    if len(recherche_nombre_occurences_processus_services) == 1 :
      print("Il y a qu'un seul processus services.exe détecté dans ce dump, ce qui correspond à un fonctionnement normal de Windows")
	  
	  #Vérifie que le processus parent est bien winlogon.exe
      recherche_pid_ppid_services = re.findall(r'0x[a-f0-9]+\s+services\.exe\s+(\d+)\s+(\d+)',resultat_pstree)
      pid_services = recherche_pid_ppid_services[0][0]
      ppid_services = recherche_pid_ppid_services[0][1]
      check_if_parent_process_is_winlogon (dump_memoire,profil_utilise,pid_services,ppid_services,resultat_pstree,"services.exe")
	  	  
	  #Vérifie que le processus services.exe est lancé depuis C:\WINDOWS\\system32\\
      check_system_root_process (dump_memoire,profil_utilise,pid_services,"services.exe")
	  
	  #Vérifie que services.exe est bien le parent d'au moins 1 processus + affiche la liste d'entre eux
      recherche_processus_fils_services = re.findall(r'0x[a-f0-9]+\s+(\S+)\s+(\d+)\s+'+pid_services,resultat_pstree)
      if len (recherche_processus_fils_services) == 0 :
        print ("Le processus services.exe n'a aucun processus fils, ce qui est fortement suspect. Ce programme ainsi que sa mémoire seront dumpés afin d'être analysé par Virustotal")
        dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_services)
      else :
        print ("Le processus services.exe a les %d processus fils suivants :" %  len (recherche_processus_fils_services))
        for nom_fils_services,pid_fils_services in recherche_processus_fils_services :
          print ("%s : %s" % (nom_fils_services,pid_fils_services))
		
    else :
      print(" %d processus services.exe différents ont été découverts, alors que seul 1 processus services.exe devrait être ouvert. Voici la liste des PID correspondants (les processus en questions seront dumpés et envoyés à Virustotal) :" % len(recherche_nombre_occurences_processus_services) )
      for pid in recherche_nombre_occurences_processus_services :
        dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid)
        print (pid)

def analyse_processus_svchost_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pstree) :
	
    recherche_nombre_occurences_processus_svchost = re.findall(r'0x[0-9a-f]+\s+svchost\.exe\s+(\d+)',resultat_pstree)	
    recherche_pid_services = re.findall(r'0x[a-f0-9]+\s+services\.exe\s+(\d+)',resultat_pstree)
    pid_services = recherche_pid_services[0]

    for pid_svchost in recherche_nombre_occurences_processus_svchost :
	  
	  #Vérifie que le processus services.exe est lancé depuis C:\WINDOWS\\system32\\ , et que l'option -k est présente et qu'elle corresponde bien à une entrée du registre Windows
      resultat_cmdline = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " cmdline --pid=" + pid_svchost)	  
      recherche_dossier_lancement = re.findall(r'Command line : C:\\(?:WINDOWS|Windows)\\[sS]ystem32\\(?:svchost|svchost\.exe)' ,resultat_cmdline)
	 
      if len(recherche_dossier_lancement) == 1 :
        print ("Le processus Svchost ayant le PID %s est bien lancé depuis le dossier C:\WINDOWS\system32, ce qui correspond à un fonctionnement normal de Windows" % pid_svchost)
	    
        recherche_parametre_svchost = re.findall(r'Command\s+line\s+:\s+C:\\(?:WINDOWS|Windows)\\[sS]ystem32\\(?:svchost|svchost\.exe) -k\s+(\S+)',resultat_cmdline)
		
        if len(recherche_parametre_svchost) != 1 :
          print ("Le processus svchost ayant le PID %s n'est pas lancé avec l'option -k. Ce processus va donc être dumpé et analysé par Virustotal" % pid_svchost)
          dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_svchost)		  
		
      else:
        recherche_mauvais_dossier_lancement = re.findall(r'Command line :\s+(\S+)',resultat_cmdline)		
        if len(recherche_mauvais_dossier_lancement) == 0 :
          print ("La recherche du dossier de lancement du procesus svchost ayant le PID %s a échoué" % pid_svchost)
        else:
          print ("Le processus svchost ayant le PID %s a été lancé depuis %s, au lieu de C:\WINDOWS\system32. Ce processus va donc être dumpé et analysé par Virustotal" % (pid_svchost, recherche_mauvais_dossier_lancement[0]))
          dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_svchost)

	  #Vérifie que le nom du processus parent est bien services.exe
      recherche_pid_processus_parent_svchost = re.findall(r'0x[0-9a-f]+\s+\S+\s+'+ pid_svchost + "\s+(\d{1,5})",resultat_pstree)
      recherche_nom_processus_parent_svchost = re.findall(r'0x[0-9a-f]+\s+(\S+)\s+' + recherche_pid_processus_parent_svchost[0],resultat_pstree)
      if recherche_nom_processus_parent_svchost[0] != "services.exe" :
        print ("Le processus svchost ayant le PID %s n'a pas pour parent services.exe. Ce processus va donc être dumpé et analysé par Virustotal" % pid_svchost)
        dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_svchost)
	    
	  
def analyse_processus_explorer_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pslist,analyse_reseau) :

  
  #Vérifie que le explorer.exe n'écoute pas sur le réseau
  recherche_pid_explorer_reseau = re.findall(r'(\d{4,5})\s+explorer\.exe\s+',analyse_reseau)
  if len(recherche_pid_explorer_reseau) != 0 :
    print ("%d processus explorer.exe écoutent sur le réseau. Chacun d'entre eux vont être dumpés puis analysés par Virustotal." % len(recherche_pid_explorer_reseau))
    for pid_explorer_reseau in recherche_pid_explorer_reseau :
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_explorer_reseau)
    
	
  recherche_pid_explorer = re.findall(r'0x[0-9a-f]+\s+explorer\.exe\s+(\d{1,5})',resultat_pslist)
  
  for pid_explorer in recherche_pid_explorer :
  
	#Vérifie que le processus explorer.exe est lancé depuis C:\WINDOWS\\
    resultat_cmdline = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " cmdline --pid=" + pid_explorer)	 
    recherche_dossier_lancement = re.findall(r'Command line : C:\\(?:WINDOWS|Windows)\\(?:Explorer\.exe|Explorer\.EXE)',resultat_cmdline)	
    if len(recherche_dossier_lancement) == 0 :
      print ("Le processus explorer.exe ayant le PID numéro %s n'a pas été lancé depuis le chemin habituel. Il va donc être dumpé avant d'être scanné par Virustotal." % pid_explorer)
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_explorer)
	  
	#Vérifie que le processus parent d'explorer.exe est déjà éteint
    recherche_pid_processus_parent_explorer = re.findall(r'0x[0-9a-f]+\s+explorer\.exe\s+'+pid_explorer+'\s+(\d{1,5})',resultat_pslist)
    pid_parent_explorer = recherche_pid_processus_parent_explorer[0]
    verification_parent_explorer = re.findall(r'0x[0-9a-f]+\s+(\S+)\s+'+pid_parent_explorer,resultat_pslist)
    if len(verification_parent_explorer) != 0 :
      print ("Le processus parent du processus explorer.exe ayant pour PID %s est toujours en vie (il s'agit du processus %s). Ce procesus explorer va donc être dumpé avant d'être scanné par Virustotal." % (pid_explorer,verification_parent_explorer[0]))
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_explorer)
	  

def analyse_processus_smss_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pslist) :
  
  recherche_pid_smss = re.findall(r'0x[0-9a-f]+\s+smss\.exe\s+(\d{1,5})',resultat_pslist)
  
  #Vérifie qu'il n'y a qu'un seul processus smss.exe en cours d'exécution
  if len(recherche_pid_smss) > 1 :
  
    print ("%d processus smss ont été découverts, alors que seul un est censé être exécuté. Chacun d'entre eux va donc être dumpé puis analysés par Virustotal" % len(recherche_pid_smss))
    for pid_smss in recherche_pid_smss :
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_smss)
	  
  elif len(recherche_pid_smss) == 1 :
  
    pid_smss = recherche_pid_smss[0]
	
	#Vérifie que le processus parent est bien le processus System (dont le PID est 4)
    recherche_parent_smss = re.findall(r'0x[0-9a-f]+\s+\S+\s+'+ pid_smss +'\s+(\d{1,5})',resultat_pslist)
    pid_parent_smss = recherche_parent_smss[0]
    if pid_parent_smss != "4" :
      print ("Le processus smss.exe, qui a pour PID %s, a été exécuté par un processus différent de System. Ces 2 processus seront donc dumpés puis analysés par Virustotal" % pid_smss)
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_smss)
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_parent_smss)
	  
	#Vérifie que le processus smss.exe est bien exécuté depuis \SystemRoot\System32\
    resultat_cmdline = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " cmdline --pid=" + pid_smss)
    recherche_dossier_lancement = re.findall(r'Command line : \\SystemRoot\\System32\\smss\.exe',resultat_cmdline)		
    if len(recherche_dossier_lancement) == 0 :
        recherche_mauvais_dossier_lancement = re.findall(r'Command line :\s+(\S+)',resultat_cmdline)		
        if len(recherche_mauvais_dossier_lancement) == 0 :
          print ("La recherche du dossier de lancement du procesus smss ayant le PID %s a échoué" % pid_smss)
        else:
          print ("Le processus smss.exe, qui a pour PID %s, n'a pas été exécuté depuis le chemin standard. Il va donc être dumpé puis analysé par Virustotal " % pid_smss)
          dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_smss)
	
	
def analyse_processus_system (dump_memoire,profil_utilise,resultat_psxview,resultat_pslist) : 

  #Vérifie que le processus parent de System n'est pas affiché par Volatility (PPID égal à 0)
  recherche_processus_parent_system = re.findall(r'0x[0-9a-f]+\s\S+\s+4\s+(\d{1,5})',resultat_pslist)
  pid_parent_system = recherche_processus_parent_system[0]
  if pid_parent_system != "0" :
    print ("Le Pid du processus parent de System n'est pas 0, mais %s. Ces 2 processus seront donc dumpés puis scannés par Virustotal." % pid_parent_system)
    dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,"4")
    dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_parent_system)

  #Vérifie qu'il n'existe qu'un seul processus System en cours d'exécution
  recherche_nombre_processus_system = re.findall(r'0x[0-9a-f]+\sSystem\s+\d{1,5}',resultat_pslist)
  if len(recherche_nombre_processus_system) > 1 :
    print ("%d processus system étaient en cours d'exécution lors de la création de ce dump mémoire, au lieu de seulement 1. Chacun d'entre eux va être dumpé puis analysés par Virustotal" % len(recherche_nombre_processus_system))
    for pid_processus_system in recherche_nombre_processus_system :
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_processus_system)
	

def analyse_processus_csrss_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pslist) : 
  
  #Vérifie que le nombre de processus crsss correspond bien au nombre de sessions utilisateurs
  resultat_nombre_sessions_utilisateur = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " sessions")
  recherche_nombre_sessions_utilisateur = re.findall(r'Session\(V\): [0-9a-f]+ ID: \d+ Processes: \d+',resultat_nombre_sessions_utilisateur)
  nombre_sessions_utilisateur =  len(recherche_nombre_sessions_utilisateur)
  recherche_processus_csrss = re.findall(r'[0-9a-f]+\s+csrss\.exe\s+(\d{1,5})',resultat_pslist)
  nombre_processus_crsss = len(recherche_processus_csrss)
  if nombre_processus_crsss != nombre_sessions_utilisateur :
    print ("Le nombre de processus crsss.exe ne correspond pas au nombre de sessions utilisateurs (Il y a %d sessions utilisateurs, mais %d processus csrss.exe). Chacun d'entre va donc être dumpé puis scanné par Virustotal" % (nombre_sessions_utilisateur,nombre_processus_crsss))
    for pid_csrss in recherche_processus_csrss :
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_csrss)
	  
  #Vérifie que le processus crsss.exe a bien été lancé depuis le dossier C:\Windows\system32
  else :
    for pid_csrss in recherche_processus_csrss :
      resultat_cmdline = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " cmdline --pid=" + pid_csrss)
      recherche_dossier_lancement = re.findall(r'Command line : (?:%SystemRoot%|C:\\Windows|C:\\WINDOWS)\\system32\\csrss\.exe',resultat_cmdline)
      if len(recherche_dossier_lancement) == 0 :
        print ("Le processus csrss.exe ayant pour PID %s n'a pas été exécuté depuis le chemin standard. Il va donc être dumpé puis analysé par Virustotal " % pid_csrss)
        dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_csrss)     	  

def analyse_processus_winlogon_exe (dump_memoire,profil_utilise,resultat_psxview,resultat_pslist) :
    
  recherche_liste_processus_winlogon = re.findall(r'0x[0-9a-f]+\s+winlogon\.exe\s+(\d{1,5})',resultat_pslist)
  for pid_winlogon in recherche_liste_processus_winlogon :
    #Vérifie que le processus parent de Winlogon est déjà mort, sauf pour les machines Windows XP où il est censé correspondre à smss.exe
    recherche_parent_winlogon = re.findall(r'0x[0-9a-f]+\s+winlogon\.exe\s+'+pid_winlogon+'\s+(\d{1,5})',resultat_pslist)
    pid_parent_winlogon = recherche_parent_winlogon[0]
    recherche_heure_demarrage_winlogon = re.findall(r'0x[0-9a-f]+\s+winlogon\.exe\s+'+pid_winlogon+'.+(\d{2}:\d{2}:\d{2})',resultat_pslist)
    heure_demarrage_winlogon = recherche_heure_demarrage_winlogon[0]
    recherche_heure_demarrage_parent_winlogon = re.findall(r'0x[0-9a-f]+\s+\S+\s+'+pid_parent_winlogon+'.+(\d{2}:\d{2}:\d{2})',resultat_pslist)
    heure_demarrage_parent_winlogon = recherche_heure_demarrage_parent_winlogon[0]	
    is_son_older_than_supposed_dad = comparer_heure_demarrage_processus(heure_demarrage_winlogon,heure_demarrage_parent_winlogon)	
    is_winlogon_dad_alive = re.findall(r'0x[0-9a-f]+\s(\S+)\s+'+pid_parent_winlogon,resultat_pslist)
	
    if ((len(is_winlogon_dad_alive) != 0 and "XP" not in profil_utilise) or ( "smss.exe" in is_winlogon_dad_alive[0] and "XP" not in profil_utilise ))  and is_son_older_than_supposed_dad == False  :
      print ("Le père du processus winlogon ayant pour PID %s est toujours en vie (il a pour PID %s). Ces 2 processus seront donc dumpés  puis analysés par Virustotal" % (pid_winlogon,pid_parent_winlogon))
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_winlogon)
      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_parent_winlogon)
  
  
def analyse_dump_windows (dump_memoire,profil_utilise) :

    liste_pid_programme_suspect_analyse_reseau = []
	
    if ("XP" in profil_utilise) == True or ("2003" in profil_utilise) :
        analyse_reseau = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " connscan")
        liste_port_source=re.findall(r"(?!:127\.0\.0\.1):(\d{1,5}) \s+ \S+ \s+\d{1,5}",analyse_reseau)
        for port in liste_port_source:
            if int(port) <  49152 and int(port) > 0 :
                is_port_suspect = 1
                for port_standard in liste_ports_standards :
                    if int(port) == int(port_standard):
                        is_port_suspect = 0
                        break
                if is_port_suspect == 1 :
                    pid_programme_suspect = re.findall(r"(?!:127\.0\.0\.1):" + str(port) +"\s+\S+\s+(\d{1,5})",analyse_reseau)
                    ip_distante_programme_suspect = re.findall(r"(?!:127\.0\.0\.1):" + str(port) + "\s+(\S+):",analyse_reseau)
                    numero_port_programme_suspect = re.findall(r"(?!:127\.0\.0\.1):" + str(port) + "\s+\S+:(\d{1,5})",analyse_reseau)

                    pid_programme_suspect = formatage_resultat_regex(pid_programme_suspect)
                    ip_distante_programme_suspect = formatage_resultat_regex(ip_distante_programme_suspect)
                    numero_port_programme_suspect = formatage_resultat_regex(numero_port_programme_suspect)
                    if pid_programme_suspect not in liste_pid_programme_suspect_analyse_reseau:
                      print ("Le programme ayant le PID %s a ouvert le port %s sur la machine locale pour se connecter à l'adresse IP %s" % (pid_programme_suspect,numero_port_programme_suspect,ip_distante_programme_suspect))
                      print("Ce programme et le contenu de sa mémoire vont maintenant être dumpés, et le programme sera envoyé à Virustotal")					
                      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_programme_suspect)
                      liste_pid_programme_suspect_analyse_reseau.append(pid_programme_suspect)
                    else:
                      print ("Le programme ayant le PID %s a également écouté sur le port %s pour se connecter à l'adresse IP %s " % (pid_programme_suspect,numero_port_programme_suspect,ip_distante_programme_suspect))
    else:
        analyse_reseau=subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " netscan")
        liste_port_source= re.findall(r"\S+ \s+ \S+ \s  (?:0\.0\.0\.0|::):(\d{1,5})",analyse_reseau)
        #print (liste_ports_standards)
        for port in liste_port_source:
            if int(port) <  49152 and int(port) > 0 :
                is_port_suspect = 1
                for port_standard in liste_ports_standards :
                    if int(port) == int(port_standard):
                        is_port_suspect = 0
                        break
                if is_port_suspect == 1 :
                    pid_programme_port_suspect = re.findall(r"\S+ \s+ \S+ \s  (?:0\.0\.0\.0|::):" + str(port) + "\s+ \S+ \s+ \S+ \s+(\d{1,5})",analyse_reseau)
                    nom_programme_port_suspect = re.findall(r"\S+ \s+ \S+ \s  (?:0\.0\.0\.0|::):" + str(port) + "\s+ \S+ \s+ \S+ \s+(?:\d{1,5}) \s+ \S+",analyse_reseau)
                    if pid_programme_suspect not in liste_pid_programme_suspect_analyse_reseau:
                      print ("Le port %s a été ouvert par le programme  %s, qui est identifié par le PID %s" % (port,nom_programme_port_suspect,pid_programme_port_suspect))
                      print ("Le programme ayant pour PID %s va maintenant être dumpé" % pid_programme_port_suspect)
                      dump_processus_suspect_et_scan_virustotal(dump_memoire,profil_utilise,pid_programme_port_suspect)
                      liste_pid_programme_suspect_analyse_reseau.append(pid_programme_suspect)


    print ("L'exécution de la commande psxview est en cours...")

    resultat_psxview=subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " psxview")	
    liste_programme_suspects_psxview=re.findall(r'.+\s(\D+exe\s+\d{1,4})\s+False\s+True',resultat_psxview)
	
    
    if len(liste_programme_suspects_psxview) == 0 :
        print("La commande psxview n'a pas permis de détecter des programmes suspects")
    else :
        dictionnaire_programme_suspect= {}
        dictionnaire_programme_suspect = analyse_programme_psxview(liste_programme_suspects_psxview)
        print ("Voici la liste des programmes suspects détectés grâce à la commande psxview : %s" % dictionnaire_programme_suspect)
        for pid in dictionnaire_programme_suspect.values():
		
            dump_processus_suspect_et_scan_virustotal (dump_memoire,profil_utilise,pid)
            connexions_programmes_suspects=re.findall(r'\S+ \s+ \S+ \s+ (\S+ \s+ \S+ \s+ \S+ \s+'+str(pid)+'\s.+)'  ,analyse_reseau)
            connexions_programmes_suspects=re.sub("[ ]{2,}", " ", str(connexions_programmes_suspects))

            if len(connexions_programmes_suspects) == 2:
                print ("Le programme ayant le PID %d n'a pas lancé de connexions" %int(pid))
            else:
                print(connexions_programmes_suspects)

            liste_dll_programme_suspect= subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " dlllist " + " -p " + pid)
            liste_dll_suspects=re.findall(r"\S+ \s+ \S+ \s+ \S+ \S+ \S+ \S+ \s+ (C:\\Users.+)",liste_dll_programme_suspect)
            if len(liste_dll_suspects) == 0:
                print("Le programme ayant le PID %d ne lance pas de DLL suspectes" % int(pid))
            else:
                print ("Dump des DLL suspects en cours ...")
                for dll in liste_dll_suspects :
                    nom_dll= ntpath.basename(dll)
                    print (dll)

                    print (nom_dll)

                    dump_dll= subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " dlldump --ignore-case" + " -p " + pid + " --dump-dir=. " + " --regex=" + nom_dll)
                    print(dump_dll)
                    resultat_dump= str(re.findall(r"\S+ \S+ \s+ \S+ \S+ \s+(OK|Error)",dump_dll))
                    resultat_dump = formatage_resultat_regex(resultat_dump)
                    print (resultat_dump)
                    if resultat_dump == "OK" :
                        print ("Le dump de la DLL suspecte s'est bien effectuée. Elle va être dumpée et être envoyée à virustotal pour analyse")
                        nom_dll_dumpe=str(re.findall(r"\S+ \S+ \s+ \S+ \S+ \s+(?:OK|Error):\s+(.+)",dump_dll))
                        nom_dll_dumpe = formatage_resultat_regex(nom_dll_dumpe)



                        dll_a_scanner_virustotal = {'file': (('%s' % nom_dll_dumpe), open(('%s' % nom_dll_dumpe), 'rb'))}
                        scan_virustotal = requests.post(url_virustotal_scan_fichier, files=dll_a_scanner_virustotal,params=parametre_virustotal)
                        lien_virustotal = str(re.findall(r"'permalink': '(https://.+/)", str(scan_virustotal.json())))
                        lien_virustotal = formatage_resultat_regex(lien_virustotal)
                        print ("Le résultat du scan VirusTotal pour la DLL suspecte est disponible sur le lien suivant : %s" %lien_virustotal)


                    else:
                        print ("Le dump de la DLL suspecte a échoué :(")


    analyse_registre_Current_Version_Run=subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + ' printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"' )
    is_analyse_successful=re.findall(r"(The requested key could not be found in the hive\(s\) searched)",analyse_registre_Current_Version_Run)

    if len(is_analyse_successful) == 0 :
        print ("Analyse du contenu de la clé de registre 'Software\Microsoft\Windows\CurrentVersion\Run' en cours ")
        cle_de_registres_suspectes=re.findall(r'\S+ \s+ \S+ \s*: \(S\)\s*(?:\"|\s)(C:\\Users.+)',analyse_registre_Current_Version_Run)

        if len(cle_de_registres_suspectes) == 0 :
            print("Aucune valeur suspecte n'a été détectée dans la clé de registre 'Software\Microsoft\Windows\CurrentVersion\Run'")
        else:
            cle_de_registres_suspectes = formatage_resultat_regex(cle_de_registres_suspectes)
            print ("Les valeurs suspects détectées dans la clé de registre 'Software\Microsoft\Windows\CurrentVersion\Run' sont : %s" % cle_de_registres_suspectes)

    else:
        print ("La clé de registre 'Software\Microsoft\Windows\CurrentVersion\Run' ne contient pas de valeurs")


    analyse_modules=subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " modules")
    modules_suspects=re.findall(r'\S+ \s+ \S+ \s+ \S+ \\[^\\]+\\([A-Z]:\\Users.+)',analyse_modules)

    if len(modules_suspects) == 0:
        print("Aucun module suspect n'a été détecté")
    else:
        i = 0
        for module in modules_suspects :
            print("Le module %s va dorénavant être dumpé puis analysé par Virustotal" %str(module))
            adresse_memoire_module_suspect= re.findall(r'\S+ \s+ (\S+) \s+ \S+ \\[^\\]+\\[A-Z]:\\Users.+',analyse_modules)
            adresse_memoire_module_suspect = adresse_memoire_module_suspect[i]

            dump_module_suspect = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " moddump -b " + adresse_memoire_module_suspect + " --dump-dir=.")
            resultat_dump = str(re.findall(r"\S+ \S+ \s+(OK|Error): .+", dump_module_suspect))
            resultat_dump = formatage_resultat_regex(resultat_dump)

            if resultat_dump == "OK":
                print ("Le dump du module ayant pour adresse %s est réussi. IL va dorénavant être scanné par Virustotal" % adresse_memoire_module_suspect)
                emplacement_dump_module_suspect = re.findall(r"\S+ \S+ \s+OK: \s*(.+)",dump_module_suspect)
                emplacement_dump_module_suspect = formatage_resultat_regex(emplacement_dump_module_suspect)


                with open(r'%s' % emplacement_dump_module_suspect, 'rb') as module_suspect:
                    scan_virustotal = requests.post(url_virustotal_scan_fichier,files={'file': module_suspect},params=parametre_virustotal)
                lien_virustotal=str(re.findall(r"'permalink': '(https://.+/)",str(scan_virustotal.json())))
                lien_virustotal = formatage_resultat_regex(lien_virustotal)
                print("Le résultat du scan VirusTotal pour le module suspect est disponible sur le lien suivant : %s" % lien_virustotal)

            else:
                print("Le dump du module ayant pour adresse %s a échoué :(" % adresse_memoire_module_suspect)

            i = i + 1

    resultat_pslist = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " pslist")
	
	#Les fonctions suivantes permettent d'analyser spécifiquement des programmes systèmes
    analyse_processus_lsass_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)
    analyse_processus_services_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)
    analyse_processus_svchost_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)
    analyse_processus_explorer_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist,analyse_reseau)
    analyse_processus_smss_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)
    analyse_processus_system(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)
    analyse_processus_csrss_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)
    analyse_processus_winlogon_exe(dump_memoire,profil_utilise,resultat_psxview,resultat_pslist)


def main() :
     
	#Vérifie que l'utilisateur courant ait la possibilité d'écrire dans le dossier courant (nécessaire pour les dump de processus malveillant notamment)
    dossier_courant = os.getcwd()
    if os.access(dossier_courant, os.X_OK | os.W_OK) is not True:
      print ("Le compte courant n'est pas en mesure d'écrire dans le dossier courant. Veuillez changer de dossier courant avant de rééxécuter ce script")
      exit(1)

    #Permet de vérifier l'état de la connexion réseau et de la clé API Virustotal
    try: 
      parametre_test_api_virustotal = parametre_virustotal 
      parametre_test_api_virustotal["ip"] = "8.8.8.8"
      verification_cle_api_virustotal = requests.get(url_virustotal_adresse_ip,params=parametre_test_api_virustotal)
      if verification_cle_api_virustotal.status_code == 403 :
        print ("Votre clé d'API est invalide, ou associé à un compte non validé. Veuillez vérifier votre compte et la clé API saisie avant de rééxécuter ce script")
        exit(1)
      elif verification_cle_api_virustotal.status_code == 204 :
        print ("Vous avez dépassé votre quota de requêtes API Virustotal pour cette minute (ou pour la journée entière). Veuillez rééxécuter ce script dans 1 minute, et si ce message réapparait, veuillez attendre demain pour que votre quota de requêtes journalier se rénitialise")
        exit(1)
    except requests.exceptions.ConnectionError :
      print("Echec du test de communication avec VirusTotal. Veuillez vérifier vos paramètres réseaux avant de réexécuter ce script")
      exit(1)

    #Vérifie que le chemin correspondant à Volatility est correct.
    if os.path.isfile(chemin_volatility):
        print ("Volatility est bien présent sur cette machine")
    else:
        print ("Volatility n'est pas installé sur cette machine")
        exit(0)

    #Initialise la variable dump_memoire à partir du 1er argument de ce script, après avoir vérifié que l'utilisateur actuel ait la permission de lire celui-ci
    if len(sys.argv) == 1 :
        print ("Vous devez donner en argument le chemin vers un dump mémoire")
        exit(0)
    elif os.access(str(sys.argv[1]), os.R_OK) is not True :
        print ("L'utilisateur actuel n'a pas les droits pour lire le dump mémoire %s. Veuillez changer de compte utilisateur ou modifier les droits sur ce fichier avant de rééexécuter ce script." % str(sys.argv[1]) )
        exit(1)
    else:
        dump_memoire = " -f " +str(sys.argv[1])
        print("Le fichier %s sera traité par ce script" % str(sys.argv[1]))


    if len(sys.argv) == 3 :
        profil_utilise = " --profile=" + str(sys.argv[2])
    else:
      resultat_image_info=subprocess.getoutput([chemin_volatility + dump_memoire+ " kdbgscan"])
      if resultat_image_info.count('\n') == 0 :
        resultat_image_info = subprocess.getoutput([chemin_volatility + dump_memoire + " imageinfo"])

      is_profile_founded = re.search(r'Profile suggestion \(KDBGHeader\): (.+)', resultat_image_info)
	  #Dans le cas où aucun profil mémoire installé ne permet d'analyser le dump mémoire, cette partie du script va chercher la distribution Linux et la version du noyau à installer pour créer ce profil
      if is_profile_founded == None :

        contenuDumpMemoire = open(str(sys.argv[1]), "rb").read()
        contenuDumpMemoire = str(contenuDumpMemoire)

        versionNoyauDump = re.findall(r'BOOT_IMAGE=[^-]+-([^ ]+)',contenuDumpMemoire)[0]

		#NE MARCHE PAS AVEC OPENSUSE
        distributionDump = re.search(r'Linux version .+\(([a-zA-Z ]+[0-9]+\.[0-9]+\.[0-9]+-[0-9]+)',contenuDumpMemoire)

        #Cette vérification permet d'assurer la compatibilité avec OpenSuse
        if distributionDump == None :
             distributionDump = re.findall(r'PRETTY_NAME=\"(.+)\"',contenuDumpMemoire)[0]
        else:
             distributionDump = re.findall(r'Linux version .+\(([a-zA-Z ]+[0-9]+\.[0-9]+\.[0-9]+-[0-9]+)',contenuDumpMemoire)[0]

        print ("Le profil mémoire Volatility correspondant à ce dump mémoire n'est pas installé sur votre machine")
        print("Vous pouvez le créer depuis une machine virtuelle correspondant aux caractérisques suivantes:")
        print ("Version du noyau et architecture : %s" % versionNoyauDump)
        print ("Distribution Linux : %s" % distributionDump)
        exit(0)

      else :
        liste_profils= re.findall(r'Profile suggestion \(KDBGHeader\): (.+)', resultat_image_info)
        profil_utilise = " --profile=" +  determination_profil(resultat_image_info)


    if "Linux" in profil_utilise :
	
       verification_profil_volatility = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " linux_cpuinfo")
       if "ERROR   : volatility.debug    : Invalid profile" in verification_profil_volatility :
         print("Le profil %s n'existe pas sur cette machine " % profil_utilise )
         exit(1)
       elif "No suitable address space mapping found" in verification_profil_volatility:
         print("Le profil %s ne correspond pas au dump mémoire %s" % (profil_utilise,str(sys.argv[1])))
         exit(1)
       else :
         analyse_dump_linux(dump_memoire,profil_utilise)
    elif "Win" in profil_utilise:
	
       verification_profil_volatility = subprocess.getoutput(chemin_volatility + dump_memoire + profil_utilise + " envars")
       if "ERROR   : volatility.debug    : Invalid profile" in verification_profil_volatility :
         print("Le profil %s n'existe pas sur cette machine " % profil_utilise )
         exit(1)
       elif "No suitable address space mapping found" in verification_profil_volatility:
         print("Le profil %s ne correspond pas au dump mémoire %s" % (profil_utilise,str(sys.argv[1])))
         exit(1)
       else :
         analyse_dump_windows(dump_memoire,profil_utilise)
       
    else :
      print ("Le nom du profil %s est incorrect. S'il s'agit d'un profil Volatility custom, veuillez le renommer pour qu'il commence par Linux pour un profil Linux ou Win pour un profil Windows")
      exit(1)


if __name__ == '__main__':
    main()
