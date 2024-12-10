# MaykiCrypto
MaykiCrypto- Documentation

Bienvenue sur MaykiCrypto:
MaykiCrypto une application de cryptographie graphique à l'aide de la bibliothèque Tkinter pour l'interface utilisateur et des bibliothèques Crypto et cryptography pour les opérations de chiffrement et de déchiffrement. L'application prend en charge trois algorithmes de chiffrement principaux : AES, DES et RSA.

structure de MaykiCrypto:
1)Interface Utilisateur (tkinter)
*Le code utilise Tkinter pour créer une interface utilisateur graphique (GUI).
*Il permet à l'utilisateur de sélectionner l'algorithme de chiffrement (AES, DES, RSA) à utiliser.
2)AES - Advanced Encryption Standard
*Lorsque l'utilisateur sélectionne l'algorithme AES, une nouvelle fenêtre s'ouvre.
*L'utilisateur peut entrer une clé AES, choisir un fichier à chiffrer/déchiffrer, et effectuer les opérations correspondantes.
*La clé et le fichier sont utilisés avec AES pour chiffrer ou déchiffrer le fichier
3)DES - Data Encryption Standard
*La fonction "open_des_window"est similaire à celle d'AES, mais prend également en charge la saisie d'un texte à chiffrer/déchiffrer.
*La fonction "perform_des_operation" utilise la clé et le texte pour chiffrer ou déchiffrer.
4)RSA - Rivest-Shamir-Adleman
*La fonction "open_rsa_window"permet à l'utilisateur de saisir une clé publique, une clé privée et un texte à chiffrer/déchiffrer.
*La fonction "perform_rsa_operation" utilise ces valeurs pour chiffrer ou déchiffrer le texte.
5)Brute Force AES et DES
*Des fonctions de force brute sont fournies pour AES et DES.
*"brute_force_aes_attack"et "brute_force_des_attack "testent toutes les combinaisons possibles de clés pour chiffrer les données(texte ou fichier).
6)Génération des clés: 
Trois programmes distincts ont été développés pour la génération des clés, chacun dédié à un algorithme spécifique. Chaque programme est conçu pour générer les clés correspondantes de manière appropriée et les stocker dans un fichier texte dédié. Ces fichiers de clés peuvent ensuite être utilisés par les algorithmes respectifs lors du processus de chiffrement et de déchiffrement. Cette approche permet de garantir que chaque algorithme dispose de clés générées de manière adéquate pour garantir la sécurité et l'efficacité des opérations cryptographiques.
Utilisation de MaykiCrypto:
1)Lancez l'application en exécutant le script principal.
2)Sélectionnez l'algorithme de chiffrement souhaité.
3)Générer une clé pour l'algorithme choisi ou utiliser une clé préexistante à partir du fichier dédié, puis la copier dans l'espace texte correspondant.
4)Effectuez les opérations de chiffrement/déchiffrement ou utilisez la force brute pour les algorithmes appropriés(AES ou DES).

Remarque:
*Assurez-vous que les bibliothèques nécessaires (tkinter, Crypto, cryptography) sont installées avant d'exécuter l'application.
*Les clés générées pour DES, AES et RSA doivent être stockées de manière sécurisée.
Merci pour votre attention
Projet Cryptographie "MaykiCrypto" 
proposé par
Mohamed Achraf Sabbagh 


