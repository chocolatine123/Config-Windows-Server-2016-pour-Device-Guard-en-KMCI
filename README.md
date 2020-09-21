# White List Device Guard pour un Windows Server 2016 sous Hyper-V en mode KMCI

Device Guard en mode KMCI va scanner la machine ciblée. Cela génère un fichier XML avec des ACL. On convertit ensuite ledit XML en un .bin qu’on mettra en paramètre de la GPO. Toutes les autres applications ne seront pas autorisées.

Nous allons donc recenser les drivers utilisés pour le démarrage d'un Windows Server 2016 tournant sous Hyper-V afin de sécuriser au maximum son démarrage.

Lancer le script sur le DC puis créer ensuite la GPO avec le chemin suivant :
GPO : Computer Configuration\ Policies\ Administrative Template\ System\ Device Guard\Deploy CCI
Valeur : C:\Windows\System32\CodeIntegrity\test.bin

NOTE IMPORTANTE : je recommande vivement de tester la GPO en mode audit d'abord (par défaut dans le script, enlever le "-Delete" en fin de script) afin d'éviter les blue screens au second redémarrage du poste ! De plus, les snapshots sont vivement recommandés !
Je décline toute responsabilité en cas de problèmes !
