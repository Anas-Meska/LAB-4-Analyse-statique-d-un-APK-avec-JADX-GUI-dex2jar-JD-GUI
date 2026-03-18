Cette analyse statique a révélé 4 constats de sécurité dans l'application UnCrackable Level 1. Les principales préoccupations concernent l'utilisation d'un algorithme de chiffrement faible (AES-ECB), la présence de mécanismes anti-tampering bypassables, et une configuration de sauvegarde non sécurisée.

Niveau de risque global : MOYEN

Actions prioritaires recommandées :

Remplacer AES-ECB par AES-GCM pour le chiffrement des secrets.
Désactiver android:allowBackup ou chiffrer les données sensibles.
Ne pas stocker la logique de vérification de secret uniquement côté client.   B. Task 3 — Analyse du manifeste avec JADX GUI Structure de l'APK
image
AndroidManifest.xml image Champ Valeur Package principal owasp.mstg.uncrackable1 versionName 1.0 versionCode 1 minSdkVersion 19 (Android 4.4 KitKat) targetSdkVersion 28 (Android 9 Pie) Permissions Aucune uses-permission déclarée android:allowBackup true — RISQUE (fuite via adb backup) android:debuggable Non présent android:usesCleartextTraffic Non présent network_security_config.xml Absent image Le fichier strings.xml ne contient aucune donnée sensible hardcodée. On y trouve uniquement des chaînes d'interface utilisateur : nom de l'app (Uncrackable1), label du bouton (Verify), et placeholder (Enter the Secret String). Le secret ne se trouve pas dans les ressources statiques. image Le code décompilé révèle plusieurs mécanismes de protection dans onCreate() : • Détection de root : c.a(), c.b() et c.c() — si l'une est vraie, dialogue bloquant + System.exit(0). • Détection du mode debug : b.a(getApplicationContext()) vérifie si l'app tourne en mode débogage.

image
La saisie utilisateur est passée à a.a(string). Si true → "Success!", sinon "Nope...". La logique réelle est dans la classe a.

image
Cette classe implémente un déchiffrement AES-ECB avec padding PKCS7. La méthode statique a(byte[] clé, byte[] données) retourne les données déchiffrées.

C. Task 4 — Recherche de chaînes sensibles Recherche textuelle globale effectuée dans JADX GUI (Navigation > Text Search).

image image image
Pattern Résultat Fichier Risque http:// Aucun résultat — — https:// Aucun résultat — — secret secretKeySpec — clé AES sg.vantagepoint.a.a Moyen key SecretKeySpec, AES/ECB, "test-keys" sg.vantagepoint.a.a Moyen debug "App is debuggable!" — détection active MainActivity Faible password Aucun résultat — — token Aucun résultat — — firebase Aucun résultat — —

Aucune URL, token ou credential n'a été trouvé en clair. La recherche sur "key" révèle l'utilisation de SecretKeySpec pour AES-ECB et la chaîne "test-keys" (détection root). Aucune information critique de production n'est hardcodée. D. Task 5 — Conversion DEX vers JAR avec dex2jar

image Étape Résultat Fichier DEX extrait classes.dex — 5,528 bytes dans C:\APK-Analysis\dex_out\ Commande utilisée d2j-dex2jar.bat classes.dex -o app.jar Version dex2jar v2.4 Erreurs Aucune Fichier JAR généré C:\APK-Analysis\app.jar Multi-dex Non — un seul classes.dex présent
E. Task 6 — Comparaison JADX GUI vs JD-GUI

image image image
Aspect JADX GUI JD-GUI Navigation Structure Android complète (Manifest, ressources, code) Structure Java uniquement (packages, classes) Ressources Accès direct aux XML, strings.xml, assets Aucun accès aux ressources Android Lisibilité Meilleure reconstruction des noms de variables Noms obfusqués parfois conservés (a, b, c) Recherche Recherche textuelle globale (Ctrl+Shift+F) Recherche limitée au fichier ouvert Workflow Tout-en-un, pas besoin de dex2jar Nécessite conversion DEX->JAR au préalable Conclusion Recommandé pour analyse complète d'APK Utile en outil complémentaire secondaire Conclusion : JADX GUI est l'outil le plus adapté pour une analyse complète d'APK Android. JD-GUI reste utile comme outil complémentaire pour une deuxième lecture du bytecode Java.   Informations générales

Date d'analyse : 03 mars 2026 Analyste : Nisrine APK analysé : UnCrackable-Level1.apk Version : 1.0 (versionCode 1) Provenance : OWASP MAS Crackmes (github.com/OWASP/owasp-mastg) Outils utilisés : JADX GUI v1.5, dex2jar v2.4, JD-GUI v1.6

Résumé exécutif Cette analyse statique a révélé 4 vulnérabilités potentielles dans l'application UnCrackable Level 1. Les principales préoccupations concernent l'utilisation d'un algorithme de chiffrement faible (AES-ECB), une configuration de sauvegarde non sécurisée (android:allowBackup="true"), et une logique de vérification du secret entièrement exposée côté client. Le niveau de risque global est évalué comme moyen. Actions prioritaires recommandées :

Remplacer AES-ECB par AES-GCM pour le chiffrement des secrets. Désactiver android:allowBackup ou chiffrer toutes les données sensibles stockées localement. Déplacer la logique de vérification du secret côté serveur.

Constats détaillés Constat #1 : Utilisation d'AES en mode ECB Sévérité : Élevée Description : La classe sg.vantagepoint.a.a utilise AES-ECB avec padding PKCS7 pour chiffrer/déchiffrer le secret. Le mode ECB est cryptographiquement faible : des blocs de plaintext identiques produisent des blocs chiffrés identiques, exposant des patterns du texte clair. Localisation : sg.vantagepoint.a.a — méthode a(byte[], byte[]) Impact potentiel : Un attaquant peut analyser les patterns du texte chiffré pour déduire partiellement le plaintext, ou monter une attaque par rejeu sur les blocs. Remédiation recommandée : Remplacer AES-ECB par AES-GCM (mode authentifié) qui garantit à la fois la confidentialité et l'intégrité des données.

Constat #2 : android:allowBackup non désactivé Sévérité : Moyenne Description : Le manifeste déclare android:allowBackup="true", ce qui permet à n'importe quel utilisateur ayant accès physique au terminal d'extraire les données de l'application via adb backup sans avoir besoin de root. Localisation : AndroidManifest.xml — attribut android:allowBackup Impact potentiel : Extraction des préférences, bases de données SQLite et fichiers internes de l'application sans privilèges root. Remédiation recommandée : Définir android:allowBackup="false" dans le manifeste, ou chiffrer toutes les données sensibles stockées localement.

Constat #3 : Logique de vérification entièrement côté client Sévérité : Moyenne Description : La vérification du secret se fait entièrement en local via verify() → a.a(string). Aucune validation serveur n'est effectuée. La logique de vérification est entièrement exposée dans le bytecode de l'APK, accessible par décompilation. Localisation : MainActivity — méthode verify() ; sg.vantagepoint.uncrackable1.a Impact potentiel : Un attaquant peut décompiler l'APK, analyser la logique de vérification et retrouver le secret sans exécuter l'application. Remédiation recommandée : Déplacer la vérification du secret côté serveur. Le client ne doit jamais posséder la logique complète de validation d'un secret.

Constat #4 : Mécanismes anti-tampering bypassables statiquement Sévérité : Faible Description : L'application implémente trois vérifications de root (c.a(), c.b(), c.c()) et une détection du mode debug (b.a()). Ces protections sont toutes implémentées en Java, visibles et contournables par décompilation ou hooking Frida/Xposed. Localisation : MainActivity — onCreate() ; sg.vantagepoint.a.b et sg.vantagepoint.a.c Impact potentiel : Les protections peuvent être désactivées par patching du bytecode ou hooking dynamique, rendant l'application vulnérable sur un appareil rooté ou en mode debug. Remédiation recommandée : Implémenter les vérifications dans du code natif (NDK/JNI) et utiliser la Play Integrity API pour une attestation côté serveur.

Annexes Permissions demandées

Aucune uses-permission déclarée — l'application ne requiert aucun accès système (réseau, stockage, caméra, etc.)

Composants exportés

sg.vantagepoint.uncrackable1.MainActivity — exportée implicitement via intent-filter LAUNCHER/MAIN Aucun Service, BroadcastReceiver ou ContentProvider déclaré.

Résultats de la recherche de chaînes sensibles (Task 4) PatternRésultatFichierRisquehttp:// / https://Aucun résultat——secretsecretKeySpec — clé AES en mémoiresg.vantagepoint.a.aMoyenkeySecretKeySpec, "AES/ECB", "test-keys"sg.vantagepoint.a.aMoyendebug"App is debuggable!"MainActivityFaiblepassword / token / firebaseAucun résultat—— Comparaison JADX GUI vs JD-GUI (Task 6) AspectJADX GUIJD-GUINavigationStructure Android complète (Manifest, ressources, code)Structure Java uniquementRessourcesAccès direct aux XML, strings.xmlAucun accès aux ressourcesRechercheRecherche textuelle globaleLimitée au fichier ouvertWorkflowTout-en-un, pas besoin de conversionNécessite dex2jar au préalableConclusionRecommandé pour analyse complèteUtile en outil secondaire
